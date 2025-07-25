/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "node_utils.h"
#include "map"
#include "camera.h"
extern "C" {
#ifdef DEVICE_USAGE_FFMPEG_ENABLE
#include "libavutil/frame.h"
#include "libavcodec/avcodec.h"
#include "libswscale/swscale.h"
#include "libavutil/imgutils.h"
#endif // DEVICE_USAGE_FFMPEG_ENABLE
}

namespace OHOS::Camera {
using namespace std;

const int32_t INVALID_ARGUMENT = -1;

static enum AVPixelFormat ConvertOhosFormat2AVPixelFormat(uint32_t format)
{
    static map<uint32_t, enum AVPixelFormat> ohosFormat2AVPixelFormatMap = {
        {CAMERA_FORMAT_RGBA_8888,    AV_PIX_FMT_RGBA},
        {CAMERA_FORMAT_RGB_888,      AV_PIX_FMT_RGB24},
        {CAMERA_FORMAT_YCRCB_420_SP, AV_PIX_FMT_NV21},
        {CAMERA_FORMAT_YCBCR_420_SP, AV_PIX_FMT_NV12},
        {CAMERA_FORMAT_YUYV_422_PKG, AV_PIX_FMT_YUYV422},
    };
    auto it = ohosFormat2AVPixelFormatMap.find(format);
    if (it != ohosFormat2AVPixelFormatMap.end()) {
        return it->second;
    }
    return AV_PIX_FMT_NONE;
}

int32_t NodeUtils::ImageFormatConvert(ImageBufferInfo &srcBufferInfo, ImageBufferInfo &dstBufferInfo)
{
    static uint32_t convertCount = 0;
    uint32_t id = convertCount++;
    auto srcAVFmt = ConvertOhosFormat2AVPixelFormat(srcBufferInfo.format);
    auto dstAVFmt = ConvertOhosFormat2AVPixelFormat(dstBufferInfo.format);
    if (srcAVFmt == AV_PIX_FMT_NONE || dstAVFmt == AV_PIX_FMT_NONE) {
        CAMERA_LOGE("NodeUtils::ImageFormatConvert err, id = %{public}d, unsupport format: %{public}d -> %{public}d",
            id, srcBufferInfo.format, dstBufferInfo.format);
        return INVALID_ARGUMENT;
    }
    CAMERA_LOGI("NodeUtils::ImageFormatConvert Start ====== id = %{public}d", id);
    CAMERA_LOGI("====imageSize: %{public}d * %{public}d -> %{public}d * %{public}d, format: %{public}d -> %{public}d",
        srcBufferInfo.width, srcBufferInfo.height, dstBufferInfo.width, dstBufferInfo.height,
        srcBufferInfo.format, dstBufferInfo.format);
    CAMERA_LOGI("====buffer: [%{public}d] -> [%{public}d]", srcBufferInfo.bufferSize, dstBufferInfo.bufferSize);

    AVFrame *pFrameSrc = av_frame_alloc();
    if (pFrameSrc == nullptr) {
        CAMERA_LOGE("ImageFormatConvert Error pFrameSrc == nullptr");
        return INVALID_ARGUMENT;
    }
    AVFrame *pFrameDst = av_frame_alloc();
    if (pFrameDst == nullptr) {
        CAMERA_LOGE("ImageFormatConvert Error pFrameDst == nullptr");
        av_frame_free(&pFrameSrc);
        return INVALID_ARGUMENT;
    }

    av_image_fill_arrays(pFrameSrc->data, pFrameSrc->linesize, static_cast<uint8_t *>(srcBufferInfo.bufferAddr),
        srcAVFmt, srcBufferInfo.width, srcBufferInfo.height, 1);
    av_image_fill_arrays(pFrameDst->data, pFrameDst->linesize, static_cast<uint8_t *>(dstBufferInfo.bufferAddr),
        dstAVFmt, dstBufferInfo.width, dstBufferInfo.height, 1);

    struct SwsContext* imgCtx = sws_getContext(
        srcBufferInfo.width, srcBufferInfo.height, srcAVFmt,
        dstBufferInfo.width, dstBufferInfo.height, dstAVFmt,
        SWS_BILINEAR, 0, 0, 0);

    auto ret = sws_scale(imgCtx, pFrameSrc->data, pFrameSrc->linesize, 0, srcBufferInfo.height,
        pFrameDst->data, pFrameDst->linesize);

    sws_freeContext(imgCtx);
    av_frame_free(&pFrameSrc);
    av_frame_free(&pFrameDst);
    CAMERA_LOGD("NodeUtils::ImageFormatConvert End [%{public}d] ====== %{public}d", ret, id);

    return 0;
}

void NodeUtils::BufferScaleFormatTransform(std::shared_ptr<IBuffer>& buffer, void *dstBuffer, uint32_t dstBufferSize)
{
    if (buffer == nullptr) {
        CAMERA_LOGI("BufferScaleFormatTransform Error buffer == nullptr");
        return;
    }

    if (buffer->GetCurWidth() == buffer->GetWidth()
        && buffer->GetCurHeight() == buffer->GetHeight()
        && buffer->GetCurFormat() == buffer->GetFormat()) {
            CAMERA_LOGI("no need ImageFormatConvert, nothing to do");
            return;
    }
    if (buffer->GetIsValidDataInSurfaceBuffer()) {
        CAMERA_LOGD("IsValidDataInSurfaceBuffer ture");
        if (memcpy_s(buffer->GetVirAddress(), buffer->GetSize(),
            buffer->GetSuffaceBufferAddr(), buffer->GetSuffaceBufferSize()) != 0) {
            CAMERA_LOGE("BufferScaleFormatTransform Fail,  memcpy_s error");
            return;
        }
    }

    NodeUtils::ImageBufferInfo srcInfo = {
        .width = buffer->GetCurWidth(),
        .height = buffer->GetCurHeight(),
        .format = buffer->GetCurFormat(),
        .bufferAddr = buffer->GetVirAddress(),
        .bufferSize = buffer->GetSize(),
    };

    NodeUtils::ImageBufferInfo dstInfo = {
        .width = buffer->GetWidth(),
        .height = buffer->GetHeight(),
        .format = buffer->GetFormat(),
        .bufferAddr = buffer->GetSuffaceBufferAddr(),
        .bufferSize = buffer->GetSuffaceBufferSize()
    };

    if (dstBuffer != nullptr && dstBufferSize != 0) {
        dstInfo.bufferAddr = dstBuffer;
        dstInfo.bufferSize = dstBufferSize;
    }

    if (NodeUtils::ImageFormatConvert(srcInfo, dstInfo) == 0) {
        buffer->SetCurFormat(buffer->GetFormat());
        buffer->SetCurWidth(buffer->GetWidth());
        buffer->SetCurHeight(buffer->GetHeight());
        buffer->SetIsValidDataInSurfaceBuffer(true);
    }
}

static void AddStrideToNV21(uint8_t* buffer, uint8_t* bufferMAX, int width, int height, int newStride)
{
    const int yPlaneSize = width * height;
    const int uvPlaneSize = yPlaneSize / 2;
    const int totalSize = yPlaneSize + uvPlaneSize;

    // 1. 计算需要扩展的总空间
    int newYPlaneSize = height * newStride;
    int newUvPlaneSize = (height / 2) * newStride;

    // 2. 从后向前处理UV平面
    uint8_t* uvEnd = buffer + totalSize;
    for (int y = (height / 2) - 1; y >= 0; --y) {
        uint8_t* src = buffer + yPlaneSize + y * width;
        uint8_t* dst = buffer + newYPlaneSize + y * newStride;
        if (memmove_s(dst, bufferMAX - dst, src, width) != 0) {
            CAMERA_LOGE("AddStrideToNV21 memmove_s Fail 1");
            return;
        }
        if (newStride > width) {
            if (memset_s(dst + width, bufferMAX - (dst + width), 0, newStride - width)) {
                CAMERA_LOGE("AddStrideToNV21 memset_s Fail 1");
                return;
            }
        }
    }

    // 3. 从后向前处理Y平面
    for (int y = height - 1; y >= 0; --y) {
        uint8_t* src = buffer + y * width;
        uint8_t* dst = buffer + y * newStride;
        if (memmove_s(dst, bufferMAX - dst, src, width) != 0) {
            CAMERA_LOGE("AddStrideToNV21 memmove_s Fail 2");
            return;
        }
        if (newStride > width) {
            if (memset_s(dst + width, bufferMAX - (dst + width), 0, newStride - width)) {
                CAMERA_LOGE("AddStrideToNV21 memset_s Fail 2");
                return;
            }
        }
    }
}

void NodeUtils::BufferTransformForStride(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGI("BufferScaleFormatTransform Error buffer == nullptr");
        return;
    }

    if (buffer->GetCurWidth() != buffer->GetWidth()
        || buffer->GetCurHeight() != buffer->GetHeight()
        || buffer->GetCurFormat() != buffer->GetFormat()) {
            CAMERA_LOGI("width, width or format is not all the same");
            return;
    }

    if (buffer->GetWidth() == buffer->GetStride()) {
        CAMERA_LOGI("buffer->GetWidth() == buffer->GetStride(), no need stride");
        return;
    }

    if (buffer->GetIsValidDataInSurfaceBuffer()) {
        CAMERA_LOGE("IsValidDataInSurfaceBuffer true");
        if (memcpy_s(buffer->GetVirAddress(), buffer->GetSize(),
            buffer->GetSuffaceBufferAddr(), buffer->GetSuffaceBufferSize()) != 0) {
            CAMERA_LOGE("BufferScaleFormatTransform Fail, memcpy_s error");
            return;
        }
    }

    uint8_t* bufferForStride = (uint8_t*)buffer->GetSuffaceBufferAddr();
    uint8_t* bufferForStrideMax = bufferForStride + buffer->GetSuffaceBufferSize();
    auto dstAVFmt = ConvertOhosFormat2AVPixelFormat(buffer->GetFormat());
    if (dstAVFmt == AV_PIX_FMT_NV21 || dstAVFmt == AV_PIX_FMT_NV12) {
        AddStrideToNV21(bufferForStride, bufferForStrideMax,
            buffer->GetWidth(), buffer->GetHeight(), buffer->GetStride());
    } else {
        CAMERA_LOGE("format not supported for stride, format = %{public}d", buffer->GetFormat());
    }
}
};