/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "zcodec_endecode_fuzzer.h"
#include <cstdlib>
#include <list>
#include <map>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <thread>
#include <vector>
#include "v1_0/hdi_z_factory.h"
#include "v1_0/hdi_z_component.h"
#include "key_value.h"
#include "error_type.h"
#include "codec_log_wrapper.h"

using namespace OHOS::HDI::Codec::Zcodec::V1_0;
using namespace OHOS::HDI::Codec;
using namespace OHOS;
using namespace std;

extern "C" __attribute__((visibility("default"))) int dlclose(void* handle)
{
    return 0;
}

namespace Vendor::ZCodec {

// 常见分辨率配置数组
static const struct {
    uint32_t width;
    uint32_t height;
} SUPPORTED_RESOLUTIONS[] = {
    {1920, 1080},  // 1080p
    {1280, 720},   // 720p
    {3840, 2160},  // 4K
    {640, 480},    // VGA
    {2560, 1440},  // 1440p
    {854, 480},    // 480p
    {352, 288},    // CIF
    {176, 144},    // QCIF
};

static const uint32_t SUPPORTED_RESOLUTIONS_COUNT = sizeof(SUPPORTED_RESOLUTIONS) / sizeof(SUPPORTED_RESOLUTIONS[0]);

// 从fuzz数据中安全获取随机数值
static uint32_t GetUint32FromData(const uint8_t *data, size_t size, size_t offset, uint32_t minVal, uint32_t maxVal)
{
    if (size < offset + sizeof(uint32_t)) {
        return minVal;
    }
    uint32_t value = *reinterpret_cast<const uint32_t*>(data + offset);
    return minVal + (value % (maxVal - minVal + 1));
}

// 从fuzz数据中安全获取伪随机bool值
static bool GetBoolFromData(const uint8_t *data, size_t size, size_t offset)
{
    if (size <= offset) {
        return false;
    }
    return (data[offset] % 2) == 1; // 2: 判断奇偶
}

class EnDecodeCodecCallback : public HdiZCallback {
public:
    EnDecodeCodecCallback() : inputDone_(false), outputDone_(false) {}
    virtual ~EnDecodeCodecCallback() = default;

    int32_t OnEvent(int32_t event, const sptr<ParcelableParam>& param) override
    {
        (void)event;
        (void)param;
        return 0;
    }

    int32_t OnBuffersBinded(const std::vector<HdiBufferWithId>& bufs) override
    {
        lock_guard<mutex> lk(mtx_);
        for (const auto& buf : bufs) {
            outputBufferIds_.push_back(buf.id);
            outputBufferPool_[buf.id] = buf.buf;
        }
        cv_.notify_one();
        return 0;
    }

    int32_t OnBuffersUnbinded(const std::vector<uint64_t>& ids) override
    {
        lock_guard<mutex> lk(mtx_);
        for (const auto& id : ids) {
            outputBufferPool_.erase(id);
        }
        return 0;
    }

    int32_t OnOutputBuffersDone(const std::vector<HdiZBufferInfo>& infos) override
    {
        lock_guard<mutex> lk(mtx_);
        for (const auto& info : infos) {
            availableOutputBuffers_.push_back(info.id);
        }
        outputDone_ = true;
        cv_.notify_one();
        return 0;
    }

    int32_t OnInputBuffersDone(const std::vector<HdiZBufferInfo>& infos) override
    {
        lock_guard<mutex> lk(mtx_);
        for (const auto& info : infos) {
            availableInputBuffers_.push_back(info.id);
        }
        inputDone_ = true;
        cv_.notify_one();
        return 0;
    }

    bool WaitForOutputBuffer(uint64_t timeoutMs)
    {
        unique_lock<mutex> lk(mtx_);
        return cv_.wait_for(lk, chrono::milliseconds(timeoutMs),
            [this] { return !availableOutputBuffers_.empty() || outputDone_; });
    }

    bool WaitForInputBuffer(uint64_t timeoutMs)
    {
        unique_lock<mutex> lk(mtx_);
        return cv_.wait_for(lk, chrono::milliseconds(timeoutMs),
            [this] { return !availableInputBuffers_.empty() || inputDone_; });
    }

    mutex mtx_;
    condition_variable cv_;
    bool inputDone_;
    bool outputDone_;
    vector<uint64_t> outputBufferIds_;
    map<uint64_t, sptr<ParcelableBuffer>> outputBufferPool_;
    list<uint64_t> availableOutputBuffers_;
    list<uint64_t> availableInputBuffers_;
};

bool EnDecodeFuzzer(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        CODEC_LOGE("%s: data %p, size %zu\n", __func__, data, size);
        return false;
    }

    // 从fuzz数据中提取测试配置参数
    bool isEncoder = GetBoolFromData(data, size, 0);
    Standard codecStandard = (data[1] % 2 == 1) ? Standard::HEVC : Standard::AVC;

    // 随机选择分辨率配置
    uint32_t resolutionIndex = GetUint32FromData(data, size, 2, 0, SUPPORTED_RESOLUTIONS_COUNT - 1);
    uint32_t width = SUPPORTED_RESOLUTIONS[resolutionIndex].width;
    uint32_t height = SUPPORTED_RESOLUTIONS[resolutionIndex].height;

    // 允许fuzz输入自定义分辨率（50%概率）
    if (GetBoolFromData(data, size, 6) && size >= 12) { // offset 6, 随机数size > 12
        width = GetUint32FromData(data, size, 7, 176, 7680); // offset 7, width range 176-7680
        height = GetUint32FromData(data, size, 11, 144, 4320); // offset 8, height range 144-4320
    }

    // 获取HDI工厂实例
    sptr<HdiZFactory> fac = HdiZFactory::Get(false);
    if (fac == nullptr) {
        CODEC_LOGE("%s: get HdiZFactory failed\n", __func__);
        return false;
    }

    sptr<EnDecodeCodecCallback> cb = sptr<EnDecodeCodecCallback>(new EnDecodeCodecCallback());
    sptr<HdiZComponent> zCodec = nullptr;

    int32_t ret = OK;
    // 使用CreateByStandard接口
    sptr<ParcelableParam> paramForCreate = ParcelableParam::Create();
    ret = fac->CreateByStandard(codecStandard, isEncoder, cb, paramForCreate, zCodec);
    CODEC_LOGI("%s: Using CreateByStandard, standard=%d, isEncoder=%d\n", __func__,
        static_cast<int>(codecStandard), isEncoder);

    if (ret != OK || zCodec == nullptr) {
        CODEC_LOGE("%s: Create failed, ret=%d\n", __func__, ret);
        return false;
    }

    // 设置丰富的随机参数
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {width, height};  // 按顺序初始化w和h字段
    param->Set(KEY_RESOLUTION, reso);

    // 随机帧率：1-120fps
    uint32_t frameRate = GetUint32FromData(data, size, 15, 1, 120);
    param->Set(KEY_FRAME_RATE, frameRate);

    // 编码器专用的随机参数
    uint32_t iFrameInterval = 30;  // 30: 默认I帧间隔
    if (isEncoder && (size >= 32)) { // 32: 随机数size
        // 随机码率：100Kbps - 50Mbps
        uint32_t bitrate = GetUint32FromData(data, size, 20, 100000, 50000000);
        param->Set(KEY_TARGET_BITRATE, bitrate);

        // 随机Profile档次（直接使用uint32_t值，避免枚举运算）
        uint32_t profile = 0;
        if (codecStandard == Standard::HEVC) {
            profile = (data[24] % 2 == 0) ? 3 : 4;  // 24: offset, HEVC_PROFILE_MAIN=3, HEVC_PROFILE_MAIN_10=4
        } else {
            profile = data[24] % 3;  // 24: offset, AVC_PROFILE_BASELINE=0, AVC_PROFILE_MAIN=1, AVC_PROFILE_HIGH=2
        }
        param->Set(KEY_PROFILE, profile);

        iFrameInterval = GetUint32FromData(data, size, 26, 1, 60); // 26: offset, 随机I帧间隔：1-60帧
        param->Set(KEY_I_FRAME_INTERVAL, static_cast<int32_t>(iFrameInterval));

        int32_t targetQp = -30 + static_cast<int32_t>(data[27] % 81); // 27: offset, 随机QP值：-30到50
        param->Set(KEY_TARGET_QP, targetQp);
    }

    ret = zCodec->SetParam(param);
    if (ret == ALL_FAIL) {
        CODEC_LOGE("%s: SetParam failed, ret=%d\n", __func__, ret);
        return false;
    }

    // 动态分配缓冲区
    const uint32_t inputBufferCount = GetUint32FromData(data, size, 28, 2, 5); // 28: offset, 分配2-5个buffer
    map<uint64_t, sptr<ParcelableBuffer>> inputBufferPool;
    list<uint64_t> availableInputBuffers;

    for (uint32_t i = 0; i < inputBufferCount; ++i) {
        HdiBufferAllocInfo info {};
        info.isImage = isEncoder;
        info.capacity = width * height * 3 / 2; // 1.5倍wxh
        info.width = width;
        info.height = height;
        info.format = 0;  // 使用默认格式
        info.usage = 0;
        
        HdiBufferWithId buf {};
        ret = zCodec->BindBufferByAlloc(info, nullptr, buf);
        if (ret == OK) {
            inputBufferPool[buf.id] = buf.buf;
            availableInputBuffers.push_back(buf.id);
        }
    }

    if (inputBufferPool.empty()) {
        CODEC_LOGE("%s: no input buffer allocated\n", __func__);
        return false;
    }

    // 启动编解码器
    ret = zCodec->Start();
    if (ret != OK) {
        CODEC_LOGE("%s: Start failed, ret=%d\n", __func__, ret);
        return false;
    }

    cb->WaitForOutputBuffer(200); // 200: 等待输出缓冲区绑定200ms

    // 随机帧数处理：1-100帧
    uint32_t frameCount = GetUint32FromData(data, size, 29, 1, 5);
    uint32_t processedFrames = 0;
    
    for (uint32_t frame = 0; frame < frameCount; frame++) {
        // 获取可用的输入缓冲区
        if (availableInputBuffers.empty()) {
            cb->WaitForInputBuffer(100); // 100: 等待100ms
            if (availableInputBuffers.empty()) {
                break;
            }
        }

        uint64_t inputId = availableInputBuffers.front();
        availableInputBuffers.pop_front();

        // 构造动态变化的buffer信息
        HdiZBufferInfo inputInfo {};
        inputInfo.id = inputId;
        inputInfo.offset = 0;
        // offset: 33 + frame % 20, min: 128, max: width * height * 2
        inputInfo.filledLen = GetUint32FromData(data, size, 33 + frame % 20, 128, width * height * 2);
        inputInfo.pts = frame * (1000000 / (frameRate > 0 ? frameRate : 30));  // 1000000: 根据帧率计算准确时间戳, 30: 默认
        if (iFrameInterval != 0) {
            inputInfo.flag = (frame == 0 || (frame % iFrameInterval == 0 && isEncoder)) ? 1 : 0;
        }
        inputInfo.alongParam = nullptr;
        inputInfo.fence = nullptr;

        vector<HdiZBufferInfo> inputInfos = {inputInfo};
        vector<int32_t> errCodes;
        ret = zCodec->QueueInputBuffers(inputInfos, errCodes);
        if (ret != OK) {
            availableInputBuffers.push_back(inputId);
        } else {
            processedFrames++;
        }

        // 获取可用的输出缓冲区
        if (!cb->availableOutputBuffers_.empty()) {
            uint64_t outputId = cb->availableOutputBuffers_.front();
            cb->availableOutputBuffers_.pop_front();

            HdiZBufferInfo outputInfo {};
            outputInfo.id = outputId;
            outputInfo.offset = 0;
            outputInfo.filledLen = 0;
            outputInfo.pts = frame * (1000000 / (frameRate > 0 ? frameRate : 30));
            outputInfo.flag = 0;
            outputInfo.alongParam = nullptr;
            outputInfo.fence = nullptr;

            vector<HdiZBufferInfo> outputInfos = {outputInfo};
            vector<int32_t> outErrCodes;
            (void)zCodec->QueueOutputBuffers(outputInfos, outErrCodes);
        }

        // 根据情况添加暂停/恢复测试
        if (GetBoolFromData(data, size, 53)) { // 53: 偏移53随机获取bool，以进行FLush+Start
            zCodec->Flush();
            zCodec->Start();
        }
    }

    // 刷新编解码器
    (void)zCodec->Flush();

    // 停止编解码器
    ret = zCodec->Stop();
    if (ret != OK) {
        CODEC_LOGE("%s: Stop return %d", __func__, ret);
    } else {
        CODEC_LOGI("%s: EnDecode succeed, codec_std=%d, res=%ux%u, frameRate=%u, frames=%u",
            __func__, static_cast<int>(codecStandard), width, height, frameRate, processedFrames);
    }

    return true;
}
} // namespace Vendor::ZCodec

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Vendor::ZCodec::EnDecodeFuzzer(data, size);
    return 0;
}