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

#include <atomic>
#include <chrono>
#include <iostream>
#include <list>
#include <map>
#include <thread>
#include <vector>
#include "error_type.h"
#include "key_value.h"
#include "codec_log_wrapper.h"
#include "command_parse.h"
#include "start_code_detector.h"
#include "v1_0/hdi_z_factory.h"
#include "zdecoder_tester.h"

using namespace OHOS::HDI::Codec::Zcodec::V1_0;
using namespace std::chrono_literals;
using ZBufferId = uint64_t;

namespace OHOS::HDI::Codec::Zcodec {

TestZDecoder::TestZDecoder(CommandOpt opt, uint32_t instanceId)
    : opt_(opt), instanceId_(instanceId)
{
    fac_ = HdiZFactory::Get(opt_.isPassthrough);
}

TestZDecoder::~TestZDecoder()
{
    CODEC_LOGI(">>");
    WaitDone();
    zCodec_ = nullptr;
    fac_ = nullptr;
    std::cout << "inst " << instanceId_ << " done" << std::endl;
}

void TestZDecoder::RunOnThread()
{
    if (running_.load()) {
        CODEC_LOGW("already running");
        return;
    }
    running_.store(true);
    threadDone_.store(false);
    thread_ = std::thread(&TestZDecoder::ThreadFun, this);
}

void TestZDecoder::WaitDone()
{
    if (thread_.joinable()) {
        thread_.join();
    }
    running_.store(false);
    threadDone_.store(true);
}

bool TestZDecoder::IsRunning() const
{
    return running_.load() && !threadDone_.load();
}

void TestZDecoder::ThreadFun()
{
    ThreadFunInner();
    running_.store(false);
    threadDone_.store(true);
    CODEC_LOGI("ThreadFun exit, ret=%{public}s", (IsSuccess() ? "OK" : "FAIL"));
}

void TestZDecoder::ThreadFunInner()
{
    for (uint32_t runIdx = 0; runIdx < opt_.runTimes; runIdx++) {
        CODEC_LOGI("[%{public}u][%{public}u/%{public}u] START", instanceId_, runIdx + 1, opt_.runTimes);
        std::cout << "[inst_" << instanceId_ << "] [" << (runIdx + 1) << "] START" << std::endl;

        ClearUp();
        bool ret = CreateDecoder();
        std::cout << "[inst_" << instanceId_ << "] CreateDecoder: " << (ret ? "true" : "false") << std::endl;
        ret = ret ? ConfigureDecoder() : ret;
        std::cout << "[inst_" << instanceId_ << "] ConfigureDecoder: " << (ret ? "true" : "false") << std::endl;
        ret = ret ? AllocateInputBuffer() : ret;
        std::cout << "[inst_" << instanceId_ << "] AllocateInputBuffer: " << (ret ? "true" : "false") << std::endl;
        ret = ret ? StartDecoder() : ret;
        std::cout << "[inst_" << instanceId_ << "] StartDecoder: " << (ret ? "true" : "false") << std::endl;
        ret = ret ? PrepareInputStream() : ret;
        std::cout << "[inst_" << instanceId_ << "] PrepareInputStream: " << (ret ? "true" : "false") << std::endl;
        if (ret) {
            std::thread inLoop = std::thread(&TestZDecoder::InputLoop, this);
            std::thread outLoop = std::thread(&TestZDecoder::OutputLoop, this);
            inCond_.notify_all();
            outCond_.notify_all();
            if (inLoop.joinable()) {
                inLoop.join();
            }
            std::cout << "[inst_" << instanceId_ << "] InputLoop done" << std::endl;
            if (outLoop.joinable()) {
                outLoop.join();
            }
            std::cout << "[inst_" << instanceId_ << "] OutputLoop done" << std::endl;
            (void)StopDecoder();
            std::cout << "[inst_" << instanceId_ << "] StopDecoder done" << std::endl;
        }
        if (!hasErr_.load() && (!ret || errFlagForOneRound_.load())) {
            hasErr_.store(true);
        }
        CODEC_LOGI("[%{public}u][%{public}u/%{public}u] END", instanceId_, runIdx + 1, opt_.runTimes);
        std::cout << "[inst_" << instanceId_ << "] [" << (runIdx + 1) << "] END" << std::endl;
    }
}

bool TestZDecoder::CreateDecoder()
{
    if (fac_ == nullptr) {
        CODEC_LOGE("[inst_%{public}u] HdiZFactory::Get failed", instanceId_);
        return false;
    }
    sptr<HdiZCallback> cb = sptr<ZDecoderCallback>::MakeSptr(this);
    std::string codecName = (opt_.protocol == CodeType::H264) ?
                            "z.hisi.video.decoder.avc" : "z.hisi.video.decoder.hevc";
    int32_t ret = fac_->CreateByName(codecName, cb, nullptr, zCodec_);
    if (ret != OK || zCodec_ == nullptr) {
        CODEC_LOGE("[inst_%{public}u] CreateByName failed", instanceId_);
        return false;
    }
    CODEC_LOGI("[inst_%{public}u] CreateByName succeed", instanceId_);
    return true;
}

bool TestZDecoder::ConfigureDecoder()
{
    sptr<ParcelableParam> param = ParcelableParam::Create();
    Resolution reso {opt_.w, opt_.h};
    param->Set(KEY_RESOLUTION, reso);
    param->Set(KEY_FRAME_RATE, opt_.frameRate);
    if (opt_.pixfmt == OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_SP) {
        param->Set(KEY_UV_ORDER, true);
    } else {
        param->Set(KEY_UV_ORDER, false);
    }
    int32_t ret = zCodec_->SetParam(param);
    if (ret != OK) {
        CODEC_LOGE("[inst_%{public}u] SetParam failed", instanceId_);
        return false;
    }
    CODEC_LOGI("[inst_%{public}u] SetParam succeed", instanceId_);
    return true;
}

bool TestZDecoder::AllocateInputBuffer()
{
    static constexpr uint32_t INPUT_BUFFER_CNT = 4;
    for (uint32_t i = 0; i < INPUT_BUFFER_CNT; ++i) {
        HdiBufferAllocInfo info {
            .isImage = false,
            .capacity = opt_.w * opt_.h * 1.5,
        };
        HdiBufferWithId buf {};
        int32_t ret = zCodec_->BindBufferByAlloc(info, nullptr, buf);
        if (ret != OK) {
            CODEC_LOGE("[inst_%{public}u] AllocateInputBuffer(%{public}u/%{public}u) failed",
                       instanceId_, (i + 1), INPUT_BUFFER_CNT);
            inputBufferPool_.clear();
            return false;
        }
        CODEC_LOGI("[inst_%{public}u] add buf(id:%{public}lu) to inputBufferPool", instanceId_, buf.id);
        inputBufferPool_[buf.id] = buf.buf;
        inAvaliableBuffers_.push_back(buf.id);
    }
    CODEC_LOGI("[inst_%{public}u] AllocateInputBuffer(%{public}u) succeed", instanceId_, INPUT_BUFFER_CNT);
    return true;
}

bool TestZDecoder::StartDecoder()
{
    int32_t ret = zCodec_->Start();
    if (ret != OK) {
        CODEC_LOGE("[inst_%{public}u] StartDecoder failed, ret=%{public}d", instanceId_, ret);
        return false;
    }
    CODEC_LOGI("[inst_%{public}u] StartDecoder succeed", instanceId_);
    return true;
}

bool TestZDecoder::FlushDecoder()
{
    int32_t ret = zCodec_->Flush();
    if (ret != OK) {
        CODEC_LOGE("[inst_%{public}u] FlushDecoder failed, ret=%{public}d", instanceId_, ret);
        return false;
    }
    CODEC_LOGI("[inst_%{public}u] FlushDecoder succeed", instanceId_);
    return true;
}

bool TestZDecoder::StopDecoder()
{
    int32_t ret = zCodec_->Stop();
    if (ret != OK) {
        CODEC_LOGE("[inst_%{public}u] StopDecoder failed, ret=%{public}d", instanceId_, ret);
        return false;
    }
    CODEC_LOGI("[inst_%{public}u] StopDecoder succeed", instanceId_);
    return true;
}

bool TestZDecoder::RestartDecoder()
{
    ResetInputStream();
    if (!PrepareInputStream()) {
        return false;
    }
    PrepareSeek();
    if (!FlushDecoder()) {
        return false;
    }
    if (!StartDecoder()) {
        return false;
    }
    return true;
}

void TestZDecoder::ClearUp()
{
    zCodec_ = nullptr;
    inputBufferPool_.clear();
    inAvaliableBuffers_.clear();
    outputBufferPool_.clear();
    outAvaliableBuffers_.clear();
    errFlagForOneRound_.store(false);
    ResetInputStream();
}

CodeProtocol TestZDecoder::CodeType2CodeProtocol(CodeType type)
{
    if (type == CodeType::H264) {
        return CodeProtocol::H264;
    }
    return CodeProtocol::H265;
}

bool TestZDecoder::PrepareInputStream()
{
    ifs_ = std::ifstream(opt_.inputFile, std::ios::binary);
    if (!ifs_) {
        CODEC_LOGE("[inst_%{public}u] failed to open file %{public}s", instanceId_, opt_.inputFile.c_str());
        return false;
    }
    demuxer_ = StartCodeDetector::Create(CodeType2CodeProtocol(opt_.protocol));
    totalSampleCnt_ = demuxer_->SetSource(opt_.inputFile);
    if (totalSampleCnt_ == 0) {
        CODEC_LOGE("[inst_%{public}u] no nalu found", instanceId_);
        return false;
    }
    return true;
}

void TestZDecoder::ResetInputStream()
{
    if (ifs_.is_open()) {
        ifs_.close();
    }
    demuxer_.reset();
    totalSampleCnt_ = 0;
    currSampleIdx_ = 0;
    userSeekPos_.clear();
}

uint32_t TestZDecoder::GetNextSample(void* bufVa, uint32_t bufLen, size_t& sampleIdx, bool& isCsd)
{
    std::optional<Sample> sample = demuxer_->PeekNextSample();
    if (!sample.has_value()) {
        return 0;
    }
    uint32_t sampleSize = sample->endPos - sample->startPos;
    if (sampleSize > bufLen) {
        CODEC_LOGE("[inst_%{public}u] sampleSize(%{public}u) > dst capacity(%{public}u)",
                   instanceId_, sampleSize, bufLen);
        return 0;
    }
    sampleIdx = sample->idx;
    isCsd = sample->isCsd;
    ifs_.seekg(sample->startPos);
    ifs_.read(reinterpret_cast<char*>(bufVa), sampleSize);
    return sampleSize;
}

int64_t TestZDecoder::GenarateTimestamp()
{
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

void TestZDecoder::LogQueueBuffersError(bool isInput, uint64_t id, const std::vector<int32_t>& errCodes)
{
    if (errCodes.empty()) {
        CODEC_LOGE("[inst_%{public}u] queue %{public}s(%{public}lu) failed, unknown err",
                   instanceId_, (isInput ? "input" : "output"), id);
    } else {
        CODEC_LOGE("[inst_%{public}u] queue %{public}s(%{public}lu) failed, ret=%{public}d",
                   instanceId_, (isInput ? "input" : "output"), id, errCodes[0]);
    }
}

size_t TestZDecoder::GenerateRandomNumInRange(size_t rangeStart, size_t rangeEnd)
{
    return rangeStart + rand() % (rangeEnd - rangeStart);
}

void TestZDecoder::PrepareSeek()
{
    srand(static_cast<uint32_t>(GenarateTimestamp()));
    uint32_t mockCnt = 0;
    size_t lastSeekTo = 0;
    while (mockCnt++ < opt_.flushCnt) {
        size_t seekFrom = GenerateRandomNumInRange(lastSeekTo, totalSampleCnt_);
        size_t seekTo = GenerateRandomNumInRange(0, totalSampleCnt_);
        CODEC_LOGI("mock seek from sample index %{public}zu to %{public}zu", seekFrom, seekTo);
        userSeekPos_.emplace_back(seekFrom, seekTo);
        lastSeekTo = seekTo;
    }
}

bool TestZDecoder::SeekIfNecessary()
{
    if (userSeekPos_.empty()) {
        return true;
    }
    size_t seekFrom;
    size_t seekTo;
    std::tie(seekFrom, seekTo) = userSeekPos_.front();
    if (currSampleIdx_ != seekFrom) {
        return true;
    }
    CODEC_LOGI("begin to seek from sample index %{public}zu to %{public}zu", seekFrom, seekTo);
    std::cout << "[inst_" << instanceId_ << "] seek from " << seekFrom << " to " << seekTo << std::endl;
    if (!demuxer_->SeekTo(seekTo)) {
        return true;
    }
    if (!FlushDecoder()) {
        return false;
    }
    userSeekPos_.pop_front();
    return true;
}

bool TestZDecoder::WaitForInput(ZBufferId& id, sptr<ParcelableBuffer>& buffer)
{
    std::unique_lock<std::mutex> lk(inMtx_);
    bool bret = inCond_.wait_for(lk, 100ms, [this] {
        return (errFlagForOneRound_.load() || !inAvaliableBuffers_.empty());
    });
    if (errFlagForOneRound_.load()) {
        return false;
    }
    if (!bret) {
        CODEC_LOGW("[inst_%{public}u] InputLoop timeout", instanceId_);
        return false;
    }
    id = inAvaliableBuffers_.front();
    inAvaliableBuffers_.pop_front();
    auto iter = inputBufferPool_.find(id);
    if (iter == inputBufferPool_.end()) {
        CODEC_LOGW("[inst_%{public}u] buf(id:%{public}lu) not in inputBufferPool", instanceId_, id);
        return false;
    }
    buffer = iter->second;
    if (buffer == nullptr) {
        CODEC_LOGW("[inst_%{public}u] buf(id:%{public}lu) is null", instanceId_, id);
        return false;
    }
    return true;
}

void TestZDecoder::InputLoop()
{
    CODEC_LOGI("[inst_%{public}u] InputLoop in", instanceId_);
    std::cout << "[inst_" << instanceId_ << "] InputLoop in" << std::endl;
    PrepareSeek();
    bool enableRestart = opt_.enableRestartAfterEos;
    bool isEos = false;
    uint32_t frameCnt = 0;
    while (!isEos && !errFlagForOneRound_.load()) {
        if (!SeekIfNecessary()) {
            errFlagForOneRound_.store(true);
            outCond_.notify_all();
            break;
        }
        ZBufferId id;
        sptr<ParcelableBuffer> buffer;
        if (!WaitForInput(id, buffer)) {
            continue;
        }
        HdiZBufferInfo info {
            .id = id,
            .offset = 0,
            .filledLen = 0,
            .pts = GenarateTimestamp(),
            .flag = 0,
            .alongParam = nullptr
        };
        size_t sampleIdx;
        bool isCsd = false;
        uint32_t sampleSize = GetNextSample(buffer->GetVirAddr(), buffer->GetCapacity(), sampleIdx, isCsd);
        info.filledLen = sampleSize;
        info.flag = isCsd ? static_cast<uint32_t>(SampleFlag::CSD) : info.flag;
        if ((sampleSize == 0) || (opt_.maxReadFrameCnt > 0 && frameCnt > opt_.maxReadFrameCnt)) {
            CODEC_LOGI("[inst_%{public}u] send eos, frameCnt=%{public}u, maxReadFrameCnt=%{public}u",
                       instanceId_, frameCnt, opt_.maxReadFrameCnt);
            isEos = true;
            info.flag = static_cast<uint32_t>(SampleFlag::EOS);
            info.filledLen = 0;
        }
        std::vector<int32_t> errCodes {};
        int32_t ret = zCodec_->QueueInputBuffers({info}, errCodes);
        if (ret != OK) {
            LogQueueBuffersError(true, info.id, errCodes);
            errFlagForOneRound_.store(true);
            outCond_.notify_all();
        }
        currSampleIdx_ = sampleIdx;
        demuxer_->MoveToNext();
        ++frameCnt;
        if (isEos && enableRestart) {
            enableRestart = false;
            isEos = false;
            frameCnt = 0;
            bool restartRet = RestartDecoder();
            if (!restartRet) {
                errFlagForOneRound_.store(true);
                outCond_.notify_all();
            }
            std::cout << "[inst_" << instanceId_ << "] enable restart, run InputLoop again(";
            std::cout << restartRet << ")" << std::endl;
            CODEC_LOGI("[inst_%{public}u] enable restart, run again(%{public}d)", instanceId_, restartRet);
        }
    }
    CODEC_LOGI("[inst_%{public}u] InputLoop out, isEos=%{public}d, hasErr=%{public}d",
               instanceId_, isEos, errFlagForOneRound_.load());
}

bool TestZDecoder::WaitForOutput(HdiZBufferInfo& info)
{
    std::unique_lock<std::mutex> lk(outMtx_);
    bool bret = outCond_.wait_for(lk, 2000ms, [this] {
        return (errFlagForOneRound_.load() || !outAvaliableBuffers_.empty());
    });
    if (errFlagForOneRound_.load()) {
        return false;
    }
    if (!bret) {
        CODEC_LOGW("[inst_%{public}u] OutputLoop timeout", instanceId_);
        return false;
    }
    info = outAvaliableBuffers_.front();
    outAvaliableBuffers_.pop_front();
    auto iter = outputBufferPool_.find(info.id);
    if (iter == outputBufferPool_.end()) {
        CODEC_LOGW("[inst_%{public}u] buf(id:%{public}lu) not in outputBufferPool_", instanceId_, info.id);
        return false;
    }
    return true;
}

void TestZDecoder::OutputLoop()
{
    CODEC_LOGI("[inst_%{public}u] OutputLoop in", instanceId_);
    std::cout << "[inst_" << instanceId_ << "] OutputLoop in" << std::endl;
    bool enableRestart = opt_.enableRestartAfterEos;
    while (!errFlagForOneRound_.load()) {
        HdiZBufferInfo info {};
        if (!WaitForOutput(info)) {
            break;
        }
        if ((info.flag & static_cast<uint32_t>(SampleFlag::EOS)) > 0) {
            CODEC_LOGI("[inst_%{public}u] receive eos", instanceId_);
            if (!enableRestart) {
                break;
            }
            std::cout << "[inst_" << instanceId_ << "] enable restart, run OutputLoop again" << std::endl;
            CODEC_LOGI("[inst_%{public}u] enable restart, run again", instanceId_);
            enableRestart = false;
        }
        info.offset = 0;
        info.filledLen = 0;
        info.pts = 0;
        info.flag = 0;
        info.alongParam = nullptr;
        std::vector<int32_t> errCodes {};
        int32_t ret = zCodec_->QueueOutputBuffers({info}, errCodes);
        if (ret != OK) {
            LogQueueBuffersError(false, info.id, errCodes);
        }
    }
    CODEC_LOGI("[inst_%{public}u] OutputLoop out, hasErr=%{public}d", instanceId_, errFlagForOneRound_.load());
}

} // namespace OHOS::HDI::Codec::Zcodec