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

#include <list>
#include <chrono>
#include <thread>
#include <map>
#include <cinttypes>
#include <fstream>
#include <sstream>
#include "surface_type.h"
#include "surface_buffer.h"
#include "v1_0/hdi_z_factory.h"
#include "key_value.h"
#include "error_type.h"
#include "codec_log_wrapper.h"
#include "command_parse.h"
#include "zencoder_tester.h"

using namespace std;
using namespace std::chrono_literals;
using namespace OHOS::HDI::Codec::Zcodec::V1_0;

namespace OHOS::HDI::Codec::Zcodec {

static inline bool IsEos(const std::ifstream& src, std::streamsize expectedSize)
{
    return src.gcount() != expectedSize;
}

int64_t GetNowUs()
{
    auto now = chrono::steady_clock::now();
    return chrono::duration_cast<chrono::microseconds>(now.time_since_epoch()).count();
}

TestZEncoder::TestZEncoder(CommandOpt opt, uint32_t instanceId)
    : mOpt(opt), mInstanceId(instanceId)
{
}

TestZEncoder::~TestZEncoder()
{
    CODEC_LOGI(">>");
    WaitDone();
    mZCodec = nullptr;
}

void TestZEncoder::RunOnThread()
{
    if (mRunning) {
        CODEC_LOGW("already running");
        return;
    }
    mRunning = true;
    mThreadDone = false;
    mThread = std::thread(&TestZEncoder::ThreadFun, this);
}

void TestZEncoder::WaitDone()
{
    if (mThread.joinable()) {
        mThread.join();
    }
    mRunning = false;
    mThreadDone = true;
}

bool TestZEncoder::IsRunning() const
{
    return mRunning && !mThreadDone;
}

void TestZEncoder::ThreadFun()
{
    int32_t ret = ThreadFunInner();
    mLastErr = ret;
    mRunning = false;
    mThreadDone = true;
    CODEC_LOGI("ThreadFun exit, ret=%{public}d", ret);
}

int32_t TestZEncoder::ConfigureEncoder()
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {mOpt.w, mOpt.h};
    param->Set(KEY_RESOLUTION, reso);
    if (mOpt.targetBitrate.has_value()) {
        param->Set(KEY_TARGET_BITRATE, mOpt.targetBitrate.value());
    }
    if (mOpt.profile.has_value()) {
        param->Set(KEY_PROFILE, static_cast<uint32_t>(mOpt.profile.value()));
    }
    if (mOpt.iFrameInterval.has_value()) {
        param->Set(KEY_I_FRAME_INTERVAL, mOpt.iFrameInterval.value());
    }
    if (mOpt.bitrateControlMode.has_value()) {
        param->Set(KEY_BITRATE_CONTROL_MODE, static_cast<uint32_t>(mOpt.bitrateControlMode.value()));
    }
    if (mOpt.targetQuality.has_value()) {
        param->Set(KEY_TARGET_QUALITY, mOpt.targetQuality.value());
    }
    if (mOpt.targetQp.has_value()) {
        param->Set(KEY_TARGET_QP, mOpt.targetQp.value());
    }
    if (mOpt.colorAspects.has_value()) {
        param->Set(KEY_COLOR_ASPECTS, mOpt.colorAspects.value());
    }
    int32_t ret = mZCodec->SetParam(param);
    if (ret == ALL_FAIL) {
        CODEC_LOGI("setparam failed");
        return -1;
    }
    return OK;
}

int32_t TestZEncoder::ThreadFunInner()
{
    for (uint32_t runIdx = 1; runIdx <= mOpt.runTimes; runIdx++) {
        CODEC_LOGI("========== runTimes: %{public}u/%{public}u ==========", runIdx, mOpt.runTimes);

        // 设置当前循环索引
        mCurrentRunIdx = runIdx;

        // 关闭旧的文件句柄（如果有）
        if (mOfstream.is_open()) {
            mOfstream.close();
        }
        mSampleCount = 0;

        // 清理缓冲区池
        {
            lock_guard<mutex> lk(mInMtx);
            mInputBufferPool.clear();
            mInAvaliableBuffers.clear();
        }
        {
            lock_guard<mutex> lk(mOutMtx);
            mOutputBufferPool.clear();
            mOutAvaliableBuffers.clear();
        }

        // 重新打开输入文件（每次循环都需要重新读取）
        mIfstream = ifstream(mOpt.inputFile, ios::binary);
        if (!mIfstream) {
            CODEC_LOGE("open input file failed %{public}s", mOpt.inputFile.c_str());
            return -1;
        }

        sptr<HdiZFactory> fac = HdiZFactory::Get(mOpt.isPassthrough);
        if (fac == nullptr) {
            CODEC_LOGE("HdiZFactory::Get failed");
            return -1;
        }
        sptr<HdiZComponent> instance;
        sptr<HdiZCallback> zcb = sptr<MyCallback>::MakeSptr(this);
        Standard protocol = (mOpt.protocol == CodeType::H264) ? AVC : HEVC;
        int32_t ret = fac->CreateByStandard(protocol, true, zcb, nullptr, instance);
        if (ret != 0 || instance == nullptr) {
            return -1;
        }
        mFac = fac;
        mZCodec = instance;
        CODEC_LOGI("CreateByName succ");

        ret = ConfigureEncoder();
        if (ret == ALL_FAIL) {
            return ret;
        }

        for (int32_t index = 0; index < 2; ++index) {
            std::pair<ZBufferId, sptr<SurfaceBuffer>> buf = CreateOneBuffer();
            if (buf.second == nullptr) {
                return -1;
            }
            mInputBufferPool[buf.first] = buf.second;
            mInAvaliableBuffers.push_back(buf.first);
            CODEC_LOGI("alloc succ, id=%{public}lu, fd=%{public}d, now pool size=%{public}zu",
                buf.first, buf.second->GetFileDescriptor(), mInputBufferPool.size());
        }

        ret = mZCodec->Start();
        if (ret != 0) {
            CODEC_LOGE("Start failed, ret=%{public}d", ret);
            return ret;
        }
        CODEC_LOGI("Start succ");

        // 重置状态
        mCurrInputSampleCnt = 0;

        std::thread inLoop = std::thread(&TestZEncoder::InputLoop, this);
        std::thread outLoop = std::thread(&TestZEncoder::OutputLoop, this);
        if (inLoop.joinable()) {
            inLoop.join();
        }
        if (outLoop.joinable()) {
            outLoop.join();
        }

        // 停止编码器并清理
        mZCodec->Stop();
        mZCodec = nullptr;
        mOfstream.close();
        CODEC_LOGI("========== run %{public}u finished ==========", runIdx);
    }
    return 0;
}

void TestZEncoder::SaveOneSample(uint8_t* va, uint32_t filledLen)
{
    if (!mOpt.enableDump) {
        return;
    }
    if (!mOfstream.is_open()) {
        string protocol = (mOpt.protocol == CodeType::H264) ? "h264" : "h265";
        // 输出文件名格式: input.instanceN.runM.h264/h265
        // 其中 N 是实例ID，M 是当前循环次数
        string outputFile = mOpt.inputFile + ".instance" + to_string(mInstanceId) + ".run" + to_string(mCurrentRunIdx) + "." + protocol;
        mOfstream.open(outputFile, std::ios::binary | std::ios::trunc);
        CODEC_LOGI("open output file: %{public}s", outputFile.c_str());
    }

    if (mOfstream.is_open() && va != nullptr && filledLen > 0) {
        mOfstream.write(reinterpret_cast<char*>(va), filledLen);
        mSampleCount++;
        if (mSampleCount % 100 == 0) {
            CODEC_LOGI("saved %{public}d samples", mSampleCount);
        }
    }
}

uint32_t TestZEncoder::ReadOneFrameYUV420P(std::ifstream& src, sptr<SurfaceBuffer>& buffer)
{
    char* dst = static_cast<char*>(buffer->GetVirAddr());
    int32_t w = buffer->GetWidth();
    int32_t h = buffer->GetHeight();
    int32_t stride = buffer->GetStride();
    constexpr int32_t SAMPLE_RATIO = 2;
    char* start = dst;
    // copy Y
    for (uint32_t i = 0; i < h; i++) {
        src.read(dst, w);
        if (IsEos(src, w)) {
            CODEC_LOGI("no more data");
            return 0;
        }
        dst += stride;
    }
    // copy U
    for (uint32_t i = 0; i < h / SAMPLE_RATIO; i++) {
        src.read(dst, w / SAMPLE_RATIO);
        if (IsEos(src, w / SAMPLE_RATIO)) {
            CODEC_LOGI("no more data");
            return 0;
        }
        dst += stride / SAMPLE_RATIO;
    }
    // copy V
    for (uint32_t i = 0; i < h / SAMPLE_RATIO; i++) {
        src.read(dst, w / SAMPLE_RATIO);
        if (IsEos(src, w / SAMPLE_RATIO)) {
            CODEC_LOGI("no more data");
            return 0;
        }
        dst += stride / SAMPLE_RATIO;
    }
    return dst - start;
}

uint32_t TestZEncoder::ReadOneFrameYUV420SP(std::ifstream& src, sptr<SurfaceBuffer>& buffer, uint8_t bytesPerPixel)
{
    char* dst = static_cast<char*>(buffer->GetVirAddr());
    int32_t w = buffer->GetWidth();
    int32_t h = buffer->GetHeight();
    int32_t stride = buffer->GetStride();
    constexpr int32_t SAMPLE_RATIO = 2;
    char* start = dst;
    // copy Y
    for (uint32_t i = 0; i < h; i++) {
        src.read(dst, w * bytesPerPixel);
        if (IsEos(src, w * bytesPerPixel)) {
            CODEC_LOGI("no more data");
            return 0;
        }
        dst += stride;
    }
    // copy UV
    for (uint32_t i = 0; i < h / SAMPLE_RATIO; i++) {
        src.read(dst, w * bytesPerPixel);
        if (IsEos(src, w * bytesPerPixel)) {
            CODEC_LOGI("no more data");
            return 0;
        }
        dst += stride;
    }
    return dst - start;
}

uint32_t TestZEncoder::ReadOneFrameRGBA(std::ifstream& src, sptr<SurfaceBuffer>& buffer)
{
    char* dst = static_cast<char*>(buffer->GetVirAddr());
    int32_t w = buffer->GetWidth();
    int32_t h = buffer->GetHeight();
    int32_t stride = buffer->GetStride();

    constexpr int32_t BYTES_PER_PIXEL_RBGA = 4;
    char* start = dst;
    for (uint32_t i = 0; i < h; i++) {
        src.read(dst, w * BYTES_PER_PIXEL_RBGA);
        if (IsEos(src, w * BYTES_PER_PIXEL_RBGA)) {
            CODEC_LOGI("no more data");
            return 0;
        }
        dst += stride;
    }
    return dst - start;
}

int32_t TestZEncoder::ReadOneFrame(sptr<SurfaceBuffer>& buffer)
{
    if (!mIfstream) {
        return 0;
    }
    switch (mOpt.pixfmt) {
        case GRAPHIC_PIXEL_FMT_YCBCR_420_P: {
            return ReadOneFrameYUV420P(mIfstream, buffer);
        }
        case GRAPHIC_PIXEL_FMT_YCBCR_420_SP:
        case GRAPHIC_PIXEL_FMT_YCRCB_420_SP: {
            return ReadOneFrameYUV420SP(mIfstream, buffer, 1);
        }
        case GRAPHIC_PIXEL_FMT_YCBCR_P010:
        case GRAPHIC_PIXEL_FMT_YCRCB_P010: {
            return ReadOneFrameYUV420SP(mIfstream, buffer, 2); // bytesPerPixel=2
        }
        case GRAPHIC_PIXEL_FMT_RGBA_1010102:
        case GRAPHIC_PIXEL_FMT_RGBA_8888: {
            return ReadOneFrameRGBA(mIfstream, buffer);
        }
        default:
            return 0;
    }
}

std::pair<ZBufferId, sptr<SurfaceBuffer>> TestZEncoder::CreateOneBuffer()
{
    HdiBufferAllocInfo allocInfo {
        .isImage = true,
        .width = mOpt.w,
        .height = mOpt.h,
        .format = mOpt.pixfmt,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA
    };
    HdiBufferWithId buf;
    int32_t ret = mZCodec->BindBufferByAlloc(allocInfo, nullptr, buf);
    if (ret != 0 || buf.buf == nullptr) {
        CODEC_LOGW("BindImageBuffers failed");
        return {0, nullptr};
    }
    BufferHandle* cloned = buf.buf->Clone();
    if (cloned == nullptr) {
        CODEC_LOGE("CloneNativeBufferHandle failed");
        return {0, nullptr};
    }
    sptr<SurfaceBuffer> surfaceBuf = SurfaceBuffer::Create();
    surfaceBuf->SetBufferHandle(cloned);
    return {buf.id, surfaceBuf};
}

void TestZEncoder::InputLoop()
{
    while (true) {
        HdiZBufferInfo info;
        sptr<SurfaceBuffer> imageBuf;
        {
            unique_lock<mutex> lk(mInMtx);
            bool bret = mInCond.wait_for(lk, 10ms, [this] {
                return !mInAvaliableBuffers.empty() || mInThreadNeedStop;
            });
            if (mInThreadNeedStop) {
                return;
            }
            if (!bret) {
                CODEC_LOGI("wait timeout, try create one");
                if (mInputBufferPool.size() >= 4) {
                    continue;
                }
                lk.unlock();
                std::pair<ZBufferId, sptr<SurfaceBuffer>> buf = CreateOneBuffer();
                lk.lock();
                if (buf.second == nullptr) {
                    continue;
                }
                mInputBufferPool[buf.first] = buf.second;
                mInAvaliableBuffers.push_back(buf.first);
                CODEC_LOGI("alloc succ, id=%{public}lu, fd=%{public}d, now pool size=%{public}lu",
                    buf.first, buf.second->GetFileDescriptor(), mInputBufferPool.size());
                continue;
            }
            info.id = mInAvaliableBuffers.front();
            mInAvaliableBuffers.pop_front();
            auto iter = mInputBufferPool.find(info.id);
            if (iter == mInputBufferPool.end()) {
                continue;
            }
            imageBuf = iter->second;
        }
        if (imageBuf == nullptr) {
            CODEC_LOGE("null imageBuf");
            return;
        }

        int32_t size = ReadOneFrame(imageBuf);

        info.filledLen = size;
        info.pts = GetNowUs();
        mCurrInputSampleCnt++;
        bool isEos = (mOpt.maxReadFrameCnt > 0 && mCurrInputSampleCnt == mOpt.maxReadFrameCnt) || size == 0;
        info.flag = isEos ? static_cast<uint32_t>(SampleFlag::EOS) : 0u;

        info.alongParam = ParcelableParam::Create();
        info.alongParam->Set(KEY_RESOLUTION, mReso);

        CODEC_LOGI("frameNo=%{public}u, %{public}ux%{public}u, pts=%{public}" PRId64 ", id=%{public}lu, fd=%{public}d",
            mCurrInputSampleCnt, imageBuf->GetWidth(), imageBuf->GetHeight(),
            info.pts, info.id, imageBuf->GetFileDescriptor());
        std::vector<int32_t> errCodes {};
        int ret = mZCodec->QueueInputBuffers({info}, errCodes);
        if (ret != 0) {
            CODEC_LOGE("QueueInputBuffers failed");
            return;
        }
        if (isEos) {
            CODEC_LOGI("input eos, quit loop");
            return;
        }
    }
}

void TestZEncoder::OutputLoop()
{
    while (true) {
        HdiZBufferInfo info;
        sptr<ParcelableBuffer> streamBuf;
        {
            unique_lock<mutex> lk(mOutMtx);
            mOutCond.wait(lk, [this] {
                return !mOutAvaliableBuffers.empty();
            });
            info = mOutAvaliableBuffers.front();
            mOutAvaliableBuffers.pop_front();
            auto iter = mOutputBufferPool.find(info.id);
            if (iter == mOutputBufferPool.end()) {
                CODEC_LOGE("can not find id %{public}ld", info.id);
                continue;
            }
            streamBuf = iter->second;
        }
        if (streamBuf == nullptr) {
            CODEC_LOGE("null streamBuf");
            return;
        }
        uint8_t* va = reinterpret_cast<uint8_t*>(streamBuf->GetVirAddr());
        if (va == nullptr) {
            CODEC_LOGE("null va");
            return;
        }
        SaveOneSample(va, info.filledLen);

        if (info.flag & static_cast<uint32_t>(SampleFlag::EOS)) {
            CODEC_LOGI("output eos, quit loop");
            return;
        }
        std::vector<int32_t> errCodes {};
        int ret = mZCodec->QueueOutputBuffers({info}, errCodes);
        if (ret != 0) {
            CODEC_LOGE("QueueOutputBuffers failed");
            return;
        }
    }
}

} // namespace OHOS::HDI::Codec::Zcodec