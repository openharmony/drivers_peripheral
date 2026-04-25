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

#ifndef ZDECODER_TESTER_H
#define ZDECODER_TESTER_H

#include <atomic>
#include <fstream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include "error_type.h"
#include "key_value.h"
#include "codec_log_wrapper.h"
#include "command_parse.h"
#include "start_code_detector.h"
#include "v1_0/hdi_z_factory.h"

namespace OHOS::HDI::Codec::Zcodec {

using ZBufferId = uint64_t;
using namespace std;
using namespace OHOS;
using namespace OHOS::HDI::Codec;
using namespace OHOS::HDI::Codec::Zcodec::V1_0;
/**
 * @brief TestZDecoder - 视频解码测试类
 *
 * 支持通过 CommandOpt 配置参数，可独立使用或集成到其他模块
 *
 * 使用示例:
 * @code
 * CommandOpt opt;
 * opt.inputFile = "/data/test.h264";
 * opt.w = 1920;
 * opt.h = 1080;
 * opt.protocol = CodeType::H264;
 *
 * auto decoder = std::make_shared<TestZDecoder>(opt);
 * decoder->RunOnThread();
 * decoder->WaitDone();
 * @endcode
 */
class TestZDecoder {
public:
    explicit TestZDecoder(CommandOpt opt, uint32_t instanceId = 1);
    ~TestZDecoder();

    void RunOnThread();
    void WaitDone();
    uint32_t GetInstanceId() const { return instanceId_; }
    bool IsRunning() const;
    bool IsSuccess() const { return !hasErr_.load(); }
    int32_t GetLastErr() const { return (hasErr_.load() ? -1 : 0); }

private:
    void ThreadFun();
    void ThreadFunInner();

    bool CreateDecoder();
    bool ConfigureDecoder();
    bool AllocateInputBuffer();
    bool StartDecoder();
    bool FlushDecoder();
    bool StopDecoder();
    bool RestartDecoder();
    void ClearUp();
    CodeProtocol CodeType2CodeProtocol(CodeType type);
    bool PrepareInputStream();
    void ResetInputStream();
    uint32_t GetNextSample(void* bufVa, uint32_t bufLen, size_t& sampleIdx, bool& isCsd);
    static int64_t GenarateTimestamp();
    void LogQueueBuffersError(bool isInput, uint64_t id, const std::vector<int32_t>& errCodes);
    static size_t GenerateRandomNumInRange(size_t rangeStart, size_t rangeEnd);
    void PrepareSeek();
    bool WaitForInput(ZBufferId& id, sptr<ParcelableBuffer>& buffer);
    bool SeekIfNecessary();
    void InputLoop();
    bool WaitForOutput(HdiZBufferInfo& info);
    void OutputLoop();

    class ZDecoderCallback : public HdiZCallback {
    public:
        ZDecoderCallback(TestZDecoder* tester) : tester_(tester) {}
        virtual ~ZDecoderCallback() = default;

        int32_t OnEvent(int32_t event, const sptr<ParcelableParam>& param) override {
            (void)param;
            if (event != OK) {
                CODEC_LOGE("[inst_%{public}u] hardware vdec report error(%{public}d), force stop",
                           tester_->instanceId_, event);
                tester_->errFlagForOneRound_.store(true);
            }
            return 0;
        }

        int32_t OnBuffersBinded(const std::vector<HdiBufferWithId>& bufs) override {
            {
                std::lock_guard<std::mutex> lk(tester_->outMtx_);
                for (const HdiBufferWithId& buf : bufs) {
                    CODEC_LOGI("[inst_%{public}u] add buf(id:%{public}lu) to outputBufferPool/outAvaliableBuffers",
                               tester_->instanceId_, buf.id);
                    tester_->outputBufferPool_[buf.id] = buf.buf;
                }
            }
            return 0;
        }

        int32_t OnBuffersUnbinded(const std::vector<ZBufferId>& ids) override {
            {
                std::lock_guard<std::mutex> lk(tester_->outMtx_);
                for (const ZBufferId& id : ids) {
                    auto iter = tester_->outputBufferPool_.find(id);
                    if (iter != tester_->outputBufferPool_.end()) {
                        CODEC_LOGI("[inst_%{public}u] erase buf(id:%{public}lu) from outputBufferPool",
                                   tester_->instanceId_, id);
                        tester_->outputBufferPool_.erase(iter);
                    }
                    auto iter1 = std::find_if(tester_->outAvaliableBuffers_.begin(),
                                              tester_->outAvaliableBuffers_.end(),
                                              [id](const HdiZBufferInfo& info) { return (info.id == id); });
                    if (iter1 != tester_->outAvaliableBuffers_.end()) {
                        CODEC_LOGI("[inst_%{public}u] erase buf(id:%{public}lu) from outAvaliableBuffers",
                                   tester_->instanceId_, id);
                        tester_->outAvaliableBuffers_.erase(iter1);
                    }
                }
            }
            return 0;
        }

        int32_t OnOutputBuffersDone(const std::vector<HdiZBufferInfo>& infos) override {
            {
                std::lock_guard<std::mutex> lk(tester_->outMtx_);
                for (const HdiZBufferInfo& info : infos) {
                    tester_->outAvaliableBuffers_.push_back(info);
                }
            }
            tester_->outCond_.notify_one();
            return 0;
        }

        int32_t OnInputBuffersDone(const std::vector<HdiZBufferInfo>& infos) override {
            {
                std::lock_guard<std::mutex> lk(tester_->inMtx_);
                for (const HdiZBufferInfo& info : infos) {
                    tester_->inAvaliableBuffers_.push_back(info.id);
                }
            }
            tester_->inCond_.notify_one();
            return 0;
        }
    private:
        TestZDecoder* tester_;
    };

private:
    CommandOpt opt_;
    uint32_t instanceId_ = 1;
    std::thread thread_;
    std::atomic_bool hasErr_ {false};
    std::atomic_bool errFlagForOneRound_ {false};
    std::atomic_bool running_ {false};
    std::atomic_bool threadDone_ {false};

    sptr<HdiZFactory> fac_ = nullptr;
    sptr<HdiZComponent> zCodec_ = nullptr;

    std::ifstream ifs_;
    std::shared_ptr<StartCodeDetector> demuxer_;

    std::mutex inMtx_;
    std::condition_variable inCond_;
    std::map<ZBufferId, sptr<ParcelableBuffer>> inputBufferPool_ {};
    std::list<ZBufferId> inAvaliableBuffers_ {};
    size_t totalSampleCnt_ = 0;
    size_t currSampleIdx_ = 0;
    std::list<std::pair<size_t, size_t>> userSeekPos_;

    std::mutex outMtx_;
    std::condition_variable outCond_;
    std::map<ZBufferId, sptr<ParcelableBuffer>> outputBufferPool_ {};
    std::list<HdiZBufferInfo> outAvaliableBuffers_ {};
};

} // namespace OHOS::HDI::Codec::Zcodec

#endif // ZDECODER_TESTER_H