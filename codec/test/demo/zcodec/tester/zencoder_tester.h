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

#ifndef ZENCODER_TESTER_H
#define ZENCODER_TESTER_H

#include <fstream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include "key_value.h"
#include "codec_log_wrapper.h"
#include "command_parse.h"
#include "surface_type.h"
#include "surface_buffer.h"
#include "v1_0/hdi_z_factory.h"

namespace OHOS::HDI::Codec::Zcodec {

using ZBufferId = uint64_t;
using namespace std;
using namespace OHOS;
using namespace OHOS::HDI::Codec;
using namespace OHOS::HDI::Codec::Zcodec::V1_0;

/**
 * @brief TestZEncoder - 视频编码测试类
 *
 * 支持通过 CommandOpt 配置参数，可独立使用或集成到其他模块
 *
 * 使用示例:
 * @code
 * CommandOpt opt;
 * opt.inputFile = "/data/test.yuv";
 * opt.w = 1920;
 * opt.h = 1080;
 * opt.protocol = CodeType::H265;
 * opt.pixfmt = OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
 * opt.enableDump = true;
 * opt.runTimes = 1;
 *
 * auto encoder = std::make_shared<TestZEncoder>(opt);
 * encoder->RunOnThread();
 * encoder->WaitDone();
 * @endcode
 */
class TestZEncoder {
public:
    explicit TestZEncoder(CommandOpt opt, uint32_t instanceId = 1);
    ~TestZEncoder();

    void RunOnThread();
    void WaitDone();
    uint32_t GetInstanceId() const { return mInstanceId; }
    bool IsRunning() const;
    bool IsSuccess() const { return mLastErr == 0; }
    int32_t GetLastErr() const { return mLastErr; }
    int32_t GetSampleDone() const { return mSampleCount; }

private:
    void ThreadFun();
    int32_t ThreadFunInner();

    int32_t ConfigureEncoder();
    void SaveOneSample(uint8_t* va, uint32_t filledLen);
    uint32_t ReadOneFrameYUV420P(std::ifstream& src, sptr<SurfaceBuffer>& buffer);
    uint32_t ReadOneFrameYUV420SP(std::ifstream& src, sptr<SurfaceBuffer>& buffer, uint8_t bytesPerPixel);
    uint32_t ReadOneFrameRGBA(std::ifstream& src, sptr<SurfaceBuffer>& buffer);
    int32_t ReadOneFrame(sptr<SurfaceBuffer>& buffer);
    std::pair<ZBufferId, sptr<SurfaceBuffer>> CreateOneBuffer();
    void InputLoop();
    void OutputLoop();

    class MyCallback : public HdiZCallback {
    public:
        explicit MyCallback(TestZEncoder* tester) : mTester(tester) {}
        virtual ~MyCallback() = default;
        int32_t OnEvent(int32_t event, const sptr<ParcelableParam>& param) override { return 0; }

        int32_t OnBuffersBinded(const std::vector<HdiBufferWithId>& bufs) override
        {
            lock_guard<mutex> lk(mTester->mOutMtx);
            for (const HdiBufferWithId& buf : bufs) {
                CODEC_LOGI("id = %{public}lu", buf.id);
                mTester->mOutputBufferPool[buf.id] = buf.buf;
            }
            return 0;
        }

        int32_t OnBuffersUnbinded(const std::vector<ZBufferId>& ids) override
        {
            lock_guard<mutex> lk(mTester->mOutMtx);
            for (ZBufferId id : ids) {
                CODEC_LOGI("id = %{public}lu", id);
                mTester->mOutputBufferPool.erase(id);
            }
            return 0;
        }

        int32_t OnInputBuffersDone(const std::vector<HdiZBufferInfo>& infos) override
        {
            {
                lock_guard<mutex> lk(mTester->mInMtx);
                for (const HdiZBufferInfo& info : infos) {
                    CODEC_LOGI("id = %{public}lu", info.id);
                    mTester->mInAvaliableBuffers.push_back(info.id);
                }
            }
            mTester->mInCond.notify_one();
            return 0;
        }

        int32_t OnOutputBuffersDone(const std::vector<HdiZBufferInfo>& infos) override
        {
            {
                lock_guard<mutex> lk(mTester->mOutMtx);
                for (const HdiZBufferInfo& info : infos) {
                    CODEC_LOGI("id = %{public}lu", info.id);
                    mTester->mOutAvaliableBuffers.push_back(info);
                }
            }
            mTester->mOutCond.notify_one();
            return 0;
        }
    private:
        TestZEncoder* mTester;
    };

private:
    CommandOpt mOpt;
    uint32_t mInstanceId = 1;
    uint32_t mCurrentRunIdx = 1;
    std::ifstream mIfstream;
    int32_t mSampleCount = 0;
    std::ofstream mOfstream;
    std::thread mThread;
    sptr<HdiZFactory> mFac;
    sptr<HdiZComponent> mZCodec;

    Resolution mReso {640, 480};
    uint32_t mCurrInputSampleCnt = 0;

    std::mutex mInMtx;
    std::condition_variable mInCond;
    std::map<ZBufferId, sptr<SurfaceBuffer>> mInputBufferPool;
    std::list<ZBufferId> mInAvaliableBuffers;
    bool mInThreadNeedStop = false;

    std::mutex mOutMtx;
    std::condition_variable mOutCond;
    std::map<ZBufferId, sptr<ParcelableBuffer>> mOutputBufferPool;
    std::list<HdiZBufferInfo> mOutAvaliableBuffers;

    bool mRunning = false;
    bool mThreadDone = false;
    int32_t mLastErr = 0;  // 最后一次执行的错误码，0表示成功
};

} // namespace OHOS::HDI::Codec::Zcodec

#endif // ZENCODER_TESTER_H