/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mjpeg_decoder.h"
#include <cstring>
#include <dlfcn.h>

#ifdef CAMERA_BUILT_ON_USB
#include "camera.h"
#else
// 直接使用 hilog，避免 camera.h 依赖链
#include "hilog/log.h"
#define CAMERA_LOGE(fmt, ...) HILOG_ERROR(LOG_CORE, fmt, ##__VA_ARGS__)
#define CAMERA_LOGI(fmt, ...) HILOG_INFO(LOG_CORE, fmt, ##__VA_ARGS__)
#define CAMERA_LOGD(fmt, ...) HILOG_DEBUG(LOG_CORE, fmt, ##__VA_ARGS__)
#endif

extern "C" {
#ifdef DEVICE_USAGE_FFMPEG_ENABLE
#include "libavcodec/avcodec.h"
#include "libavutil/frame.h"
#include "libavutil/imgutils.h"
#include "libavutil/pixdesc.h"
#include "libswscale/swscale.h"
#endif
}

namespace OHOS::Camera {

// ==================== FfmpegMjpegDecoder ====================

static void ProcessColorRange(AVFrame *srcFrame)
{
    int newPixFmt = srcFrame->format;
    switch (srcFrame->format) {
        case AV_PIX_FMT_YUVJ422P:
            newPixFmt = AV_PIX_FMT_YUV422P;
            break;
        case AV_PIX_FMT_YUVJ420P:
            newPixFmt = AV_PIX_FMT_YUV420P;
            break;
        case AV_PIX_FMT_YUVJ444P:
            newPixFmt = AV_PIX_FMT_YUV444P;
            break;
        default:
            break;
    }
    if (newPixFmt != srcFrame->format) {
        srcFrame->format = newPixFmt;
        srcFrame->color_range = AVCOL_RANGE_JPEG;
    }
}

static SwsContext *SetupSwsContext(SwsContext *swsCtx, AVFrame *srcFrame, int width, int height)
{
    return sws_getCachedContext(swsCtx, srcFrame->width, srcFrame->height, (AVPixelFormat)srcFrame->format, width,
        height, AV_PIX_FMT_NV21, SWS_BILINEAR, nullptr, nullptr, nullptr);
}

static bool FillAndScale(SwsContext *swsCtx, AVFrame *srcFrame, uint8_t *outputBuffer, int width, int height)
{
    uint8_t *dstData[4] = {nullptr};
    int dstLinesize[4] = {0};
    int ret = av_image_fill_arrays(dstData, dstLinesize, outputBuffer, AV_PIX_FMT_NV21, width, height, 1);
    if (ret < 0) {
        CAMERA_LOGE("FfmpegMjpegDecoder: Could not fill image arrays, ret=%{public}d", ret);
        return false;
    }
    sws_scale(swsCtx, reinterpret_cast<const uint8_t * const *>(srcFrame->data), srcFrame->linesize, 0, height, dstData,
        dstLinesize);
    return true;
}

struct FfmpegMjpegDecoder::Impl {
    AVCodecContext *codecCtx = nullptr;
    AVPacket *packet = nullptr;
    AVFrame *srcFrame = nullptr;
    AVFrame *dstFrame = nullptr;
    SwsContext *swsCtx = nullptr;

    bool Init()
    {
#ifdef DEVICE_USAGE_FFMPEG_ENABLE
        av_log_set_level(AV_LOG_ERROR);

        const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_MJPEG);
        if (!codec) {
            CAMERA_LOGE("FfmpegMjpegDecoder: MJPEG codec not found");
            return false;
        }

        codecCtx = avcodec_alloc_context3(codec);
        if (!codecCtx) {
            CAMERA_LOGE("FfmpegMjpegDecoder: Could not allocate codec context");
            return false;
        }

        if (avcodec_open2(codecCtx, codec, nullptr) < 0) {
            CAMERA_LOGE("FfmpegMjpegDecoder: Could not open codec");
            avcodec_free_context(&codecCtx);
            codecCtx = nullptr;
            return false;
        }

        packet = av_packet_alloc();
        if (!packet) {
            CAMERA_LOGE("FfmpegMjpegDecoder: Could not allocate packet");
            avcodec_free_context(&codecCtx);
            codecCtx = nullptr;
            return false;
        }

        srcFrame = av_frame_alloc();
        if (!srcFrame) {
            CAMERA_LOGE("FfmpegMjpegDecoder: Could not allocate src frame");
            av_packet_free(&packet);
            avcodec_free_context(&codecCtx);
            codecCtx = nullptr;
            return false;
        }

        dstFrame = av_frame_alloc();
        if (!dstFrame) {
            CAMERA_LOGE("FfmpegMjpegDecoder: Could not allocate dst frame");
            av_frame_free(&srcFrame);
            av_packet_free(&packet);
            avcodec_free_context(&codecCtx);
            codecCtx = nullptr;
            return false;
        }

        CAMERA_LOGI("FfmpegMjpegDecoder: FFmpeg initialized successfully");
        return true;
#else
        CAMERA_LOGI("FfmpegMjpegDecoder: FFmpeg not enabled in build");
        return false;
#endif
    }

    ~Impl()
    {
#ifdef DEVICE_USAGE_FFMPEG_ENABLE
        if (swsCtx) {
            sws_freeContext(swsCtx);
            swsCtx = nullptr;
        }
        if (dstFrame) {
            av_frame_free(&dstFrame);
            dstFrame = nullptr;
        }
        if (srcFrame) {
            av_frame_free(&srcFrame);
            srcFrame = nullptr;
        }
        if (packet) {
            av_packet_free(&packet);
            packet = nullptr;
        }
        if (codecCtx) {
            avcodec_close(codecCtx);
            avcodec_free_context(&codecCtx);
            codecCtx = nullptr;
        }
#endif
    }
};

FfmpegMjpegDecoder::FfmpegMjpegDecoder() : pimpl_(new Impl)
{
    isInitialized_ = pimpl_->Init();
}

FfmpegMjpegDecoder::~FfmpegMjpegDecoder()
{
    delete pimpl_;
    pimpl_ = nullptr;
}

bool FfmpegMjpegDecoder::Decode(const DecodeParams& params)
{
    if (!isInitialized_) {
        CAMERA_LOGE("FfmpegMjpegDecoder not initialized");
        return false;
    }
    if (params.width <= 0 || params.height <= 0) {
        CAMERA_LOGE("FfmpegMjpegDecoder: Invalid resolution %dx%d", params.width, params.height);
        return false;
    }
    if (!params.mjpegData || params.size == 0 || !params.outputBuffer || params.outputSize == 0) {
        CAMERA_LOGE("FfmpegMjpegDecoder invalid parameters");
        return false;
    }
    size_t requiredSize = static_cast<size_t>(params.width) * static_cast<size_t>(params.height) * 3 / 2;
    if (params.outputSize < requiredSize) {
        CAMERA_LOGE("FfmpegMjpegDecoder: Output buffer too small, need %{public}zu, got %{public}zu",
            requiredSize, params.outputSize);
        return false;
    }
#ifdef DEVICE_USAGE_FFMPEG_ENABLE
    pimpl_->packet->data = const_cast<uint8_t*>(params.mjpegData);
    pimpl_->packet->size = static_cast<int>(params.size);
    int ret = avcodec_send_packet(pimpl_->codecCtx, pimpl_->packet);
    if (ret < 0) {
        CAMERA_LOGE("FfmpegMjpegDecoder: Error sending packet for decoding, ret=%{public}d", ret);
        return false;
    }
    ret = avcodec_receive_frame(pimpl_->codecCtx, pimpl_->srcFrame);
    if (ret < 0) {
        CAMERA_LOGE("FfmpegMjpegDecoder: Error during decoding, ret=%{public}d", ret);
        return false;
    }
    ProcessColorRange(pimpl_->srcFrame);
    pimpl_->swsCtx = SetupSwsContext(pimpl_->swsCtx, pimpl_->srcFrame, params.width, params.height);
    if (!pimpl_->swsCtx) {
        CAMERA_LOGE("FfmpegMjpegDecoder: Could not initialize sws context");
        return false;
    }
    if (!FillAndScale(pimpl_->swsCtx, pimpl_->srcFrame, params.outputBuffer, params.width, params.height)) {
        return false;
    }
    CAMERA_LOGD("FfmpegMjpegDecoder: Decode success, %{public}dx%{public}d", params.width, params.height);
    return true;
#else
    (void)params;
    return false;
#endif
}

// ==================== LibyuvMjpegDecoder ====================

// 全局 once_flag 用于保护 dlopen 的线程安全
static std::once_flag g_libyuvInitOnce;
static bool g_libyuvAvailable = false;
static void *g_libyuvHandle = nullptr;

using LibyuvMJPGSizeFunc = int(const uint8_t *, size_t, int *, int *);
using LibyuvMJPGToNV21Func = int(const uint8_t *, size_t, uint8_t *, int, uint8_t *, int, int, int, int, int);

static LibyuvMJPGSizeFunc *g_mjpgSize = nullptr;
static LibyuvMJPGToNV21Func *g_mjpgToNv21 = nullptr;

struct LibyuvMjpegDecoder::Impl {
    void *libyuvHandle = nullptr;

    using MJPGSizeFunc = LibyuvMJPGSizeFunc;
    using MJPGToNV21Func = LibyuvMJPGToNV21Func;

    MJPGSizeFunc *mjpgSize = nullptr;
    MJPGToNV21Func *mjpgToNv21 = nullptr;
    bool isAvailable = false;

    static void InitLibyuvOnce()
    {
        void *handle = dlopen("libyuv.z.so", RTLD_LAZY);
        if (!handle) {
            handle = dlopen("libyuv.so.0", RTLD_LAZY);
        }

        if (!handle) {
            CAMERA_LOGI("LibyuvMjpegDecoder: libyuv library not found");
            g_libyuvAvailable = false;
            return;
        }

        auto *sizeFunc = (MJPGSizeFunc *)dlsym(handle, "MJPGSize");
        auto *convertFunc = (MJPGToNV21Func *)dlsym(handle, "MJPGToNV21");
        if (!sizeFunc || !convertFunc) {
            CAMERA_LOGI("LibyuvMjpegDecoder: MJPG functions not found in libyuv");
            dlclose(handle);
            g_libyuvAvailable = false;
            return;
        }

        g_libyuvHandle = handle;
        g_mjpgSize = sizeFunc;
        g_mjpgToNv21 = convertFunc;
        g_libyuvAvailable = true;
        CAMERA_LOGI("LibyuvMjpegDecoder: libyuv loaded successfully");
    }

    bool Init()
    {
        std::call_once(g_libyuvInitOnce, InitLibyuvOnce);

        mjpgSize = g_mjpgSize;
        mjpgToNv21 = g_mjpgToNv21;
        isAvailable = g_libyuvAvailable;
        return isAvailable;
    }

    ~Impl()
    {
        // 不关闭动态库，可能被其他实例使用
    }
};

LibyuvMjpegDecoder::LibyuvMjpegDecoder() : pimpl_(new Impl)
{
    pimpl_->Init();
}

LibyuvMjpegDecoder::~LibyuvMjpegDecoder()
{
    delete pimpl_;
    pimpl_ = nullptr;
}

bool LibyuvMjpegDecoder::IsAvailable() const
{
    return pimpl_->isAvailable;
}

bool LibyuvMjpegDecoder::Decode(const DecodeParams& params)
{
    if (!pimpl_->isAvailable) {
        CAMERA_LOGE("LibyuvMjpegDecoder not available");
        return false;
    }
    if (params.width <= 0 || params.height <= 0) {
        CAMERA_LOGE("LibyuvMjpegDecoder: Invalid resolution %dx%d", params.width, params.height);
        return false;
    }
    if (!params.mjpegData || params.size == 0 || !params.outputBuffer || params.outputSize == 0) {
        CAMERA_LOGE("LibyuvMjpegDecoder invalid parameters");
        return false;
    }
    size_t requiredSize = static_cast<size_t>(params.width) * static_cast<size_t>(params.height) * 3 / 2;
    if (params.outputSize < requiredSize) {
        CAMERA_LOGE("LibyuvMjpegDecoder: Output buffer too small, need %{public}zu, got %{public}zu",
            requiredSize, params.outputSize);
        return false;
    }

    int srcWidth = 0;
    int srcHeight = 0;
    int ret = pimpl_->mjpgSize(params.mjpegData, params.size, &srcWidth, &srcHeight);
    if (ret != 0) {
        CAMERA_LOGE("LibyuvMjpegDecoder: MJPGSize failed, ret=%{public}d", ret);
        return false;
    }

    ret = pimpl_->mjpgToNv21(params.mjpegData, params.size,
        params.outputBuffer, params.width,
        params.outputBuffer + params.width * params.height, params.width,
        srcWidth, srcHeight, params.width, params.height);
    if (ret != 0) {
        CAMERA_LOGE("LibyuvMjpegDecoder: MJPGToNV21 failed, ret=%{public}d", ret);
        return false;
    }

    CAMERA_LOGD("LibyuvMjpegDecoder: Decode success, %{public}dx%{public}d", params.width, params.height);
    return true;
}

// ==================== MjpegDecoderFactory ====================

std::shared_ptr<IMjpegDecoder> MjpegDecoderFactory::Create()
{
    auto libyuvDecoder = std::make_shared<LibyuvMjpegDecoder>();
    if (libyuvDecoder->IsAvailable()) {
        CAMERA_LOGI("MjpegDecoderFactory: Using Libyuv decoder");
        return libyuvDecoder;
    }

    CAMERA_LOGI("MjpegDecoderFactory: Fallback to FFmpeg decoder");
    return std::make_shared<FfmpegMjpegDecoder>();
}

const char *MjpegDecoderFactory::GetAvailableDecoderName()
{
    LibyuvMjpegDecoder testLibyuv;
    if (testLibyuv.IsAvailable()) {
        return "Libyuv";
    }

    FfmpegMjpegDecoder testFfmpeg;
    if (testFfmpeg.IsAvailable()) {
        return "FFmpeg";
    }

    return "None";
}

} // namespace OHOS::Camera
