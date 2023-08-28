/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "watchdog.h"
#include "stream_operator.h"
#include "buffer_adapter.h"
#include "camera_device_impl.h"
#include "metadata_utils.h"
#include <algorithm>
#include <iterator>

namespace OHOS::Camera {
StreamOperator::StreamOperator(const OHOS::sptr<IStreamOperatorCallback>& callback,
                               const std::weak_ptr<ICameraDevice>& device)
{
    CAMERA_LOGV("enter");
    callback_ = callback;
    device_ = device;
}

StreamOperator::~StreamOperator()
{
    CAMERA_LOGV("enter");
}

RetCode StreamOperator::Init()
{
    auto dev = std::static_pointer_cast<CameraDeviceImpl>(device_.lock());
    CHECK_IF_PTR_NULL_RETURN_VALUE(dev, RC_ERROR);
    pipelineCore_ = dev->GetPipelineCore();
    if (pipelineCore_ == nullptr) {
        CAMERA_LOGE("get pipeline core failed.");
        return RC_ERROR;
    }

    requestTimeoutCB_ = std::bind(&CameraDeviceImpl::OnRequestTimeout, dev);
    streamPipeline_ = pipelineCore_->GetStreamPipelineCore();
    if (streamPipeline_ == nullptr) {
        CAMERA_LOGE("get stream pipeline core failed.");
        return RC_ERROR;
    }

    RetCode rc = streamPipeline_->Init();
    if (rc != RC_OK) {
        CAMERA_LOGE("stream pipeline core init failed.");
        return RC_ERROR;
    }

    auto cb = [this](MessageGroup& m) { HandleCallbackMessage(m); };
    messenger_ = std::make_shared<CaptureMessageOperator>(cb);
    CHECK_IF_PTR_NULL_RETURN_VALUE(messenger_, RC_ERROR);
    messenger_->StartProcess();

    return RC_OK;
}

void StreamOperator::GetStreamSupportType(std::set<int32_t> inputIDSet,
                                          DynamicStreamSwitchMode method,
                                          StreamSupportType& type)
{
    std::set<int32_t> currentIDSet = {};
    {
        std::lock_guard<std::mutex> l(streamLock_);
        for (auto& it : streamMap_) {
            currentIDSet.emplace(it.first);
        }
    }

    // no streams are running
    if (currentIDSet.empty()) {
        if (method == DYNAMIC_STREAM_SWITCH_NEED_INNER_RESTART) {
            type = DYNAMIC_SUPPORTED;
            return;
        }
        type = NOT_SUPPORTED;
        return;
    }

    // the difference of currentSet from inputIDSet
    std::set<int32_t> cfiSet = {};
    std::set_difference(inputIDSet.begin(), inputIDSet.end(), currentIDSet.begin(), currentIDSet.end(),
                        std::inserter(cfiSet, cfiSet.begin()));

    // the difference of cfiSet from inputIDSet
    std::set<int32_t> expectCurrentSet = {};
    std::set_difference(inputIDSet.begin(), inputIDSet.end(), cfiSet.begin(), cfiSet.end(),
                        std::inserter(expectCurrentSet, expectCurrentSet.begin()));

    bool isEqual =
        std::equal(expectCurrentSet.begin(), expectCurrentSet.end(), currentIDSet.begin(), currentIDSet.end());
    if (isEqual) {
        // currentIDSet is subset of inputIDSet
        if (method == DYNAMIC_STREAM_SWITCH_NEED_INNER_RESTART) {
            type = DYNAMIC_SUPPORTED;
            return;
        }
        type = NOT_SUPPORTED;
    } else {
        if (method == DYNAMIC_STREAM_SWITCH_NEED_INNER_RESTART) {
            type = RE_CONFIGURED_REQUIRED;
            return;
        }
        type = NOT_SUPPORTED;
    }

    return;
}

int32_t StreamOperator::IsStreamsSupported(OperationMode mode, const std::vector<uint8_t>& modeSetting,
                                           const std::vector<StreamInfo>& infos, StreamSupportType& type)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamPipeline_, DEVICE_ERROR);
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    if (infos.empty() || modeSetting.empty()) {
        CAMERA_LOGE("input vector is empty");
        return INVALID_ARGUMENT;
    }
    DFX_LOCAL_HITRACE_BEGIN;

    std::set<int32_t> inputIDSet = {};
    std::vector<int32_t> checkStreamIdVec = {};
    for (auto it : infos) {
        CHECK_IF_NOT_EQUAL_RETURN_VALUE(CheckStreamInfo(it), true, INVALID_ARGUMENT);
        inputIDSet.emplace(it.streamId_);
        checkStreamIdVec.push_back(it.streamId_);
    }
    CHECK_IF_EQUAL_RETURN_VALUE(inputIDSet.empty(), true, INVALID_ARGUMENT);

    auto uniqueIt = std::unique(checkStreamIdVec.begin(), checkStreamIdVec.end());
    if (checkStreamIdVec.size() != (uint32_t)(std::distance(checkStreamIdVec.begin(), uniqueIt))) {
        CAMERA_LOGE("stream id must be unique");
        return INVALID_ARGUMENT;
    }

    std::shared_ptr<CameraMetadata> settings;
    MetadataUtils::ConvertVecToMetadata(modeSetting, settings);
    DynamicStreamSwitchMode method = CheckStreamsSupported(mode, settings, infos);
    if (method == DYNAMIC_STREAM_SWITCH_SUPPORT) {
        type = DYNAMIC_SUPPORTED;
        return HDI::Camera::V1_0::HDI::Camera::V1_0::NO_ERROR;
    }

    if (method == DYNAMIC_STREAM_SWITCH_NOT_SUPPORT) {
        type = NOT_SUPPORTED;
        return HDI::Camera::V1_0::NO_ERROR;
    }

    // change mode need to update pipeline, and caller must restart streams
    if (mode != streamPipeline_->GetCurrentMode()) {
        if (method == DYNAMIC_STREAM_SWITCH_NEED_INNER_RESTART) {
            type = RE_CONFIGURED_REQUIRED;
            return HDI::Camera::V1_0::NO_ERROR;
        }
        type = NOT_SUPPORTED;
        return HDI::Camera::V1_0::NO_ERROR;
    }

    if (method == DYNAMIC_STREAM_SWITCH_NEED_INNER_RESTART) {
        GetStreamSupportType(inputIDSet, method, type);
        return HDI::Camera::V1_0::NO_ERROR;
    }

    DFX_LOCAL_HITRACE_END;
    return HDI::Camera::V1_0::NO_ERROR;
}

DynamicStreamSwitchMode StreamOperator::CheckStreamsSupported(
    OperationMode mode,
    const std::shared_ptr<CameraMetadata>& modeSetting,
    const std::vector<StreamInfo>& infos)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamPipeline_, DYNAMIC_STREAM_SWITCH_NOT_SUPPORT);
    std::vector<StreamConfiguration> configs = {};
    for (auto& it : infos) {
        StreamConfiguration config = {};
        config.type = it.intent_;
        config.width = it.width_;
        config.height = it.height_;
        PixelFormat pf = static_cast<PixelFormat>(it.format_);
        config.format = BufferAdapter::PixelFormatToCameraFormat(pf);
        config.dataspace = it.dataspace_; // fix spell error
        config.tunnelMode = it.tunneledMode_;
        config.minFrameDuration = it.minFrameDuration_;
        config.encodeType = it.encodeType_;
        configs.emplace_back(config);
    }
    // search device capability to check if this configuration is supported.
    return streamPipeline_->CheckStreamsSupported(mode, modeSetting, configs);
}

void StreamOperator::StreamInfoToStreamConfiguration(StreamConfiguration &scg, const StreamInfo info)
{
    scg.id = info.streamId_;
    scg.type = info.intent_;
    scg.width = info.width_;
    scg.height = info.height_;
    PixelFormat pf = static_cast<PixelFormat>(info.format_);
    scg.format = BufferAdapter::PixelFormatToCameraFormat(pf);
    scg.dataspace = info.dataspace_; // fix misspell
    scg.tunnelMode = info.tunneledMode_;
    scg.minFrameDuration = info.minFrameDuration_;
    scg.encodeType = info.encodeType_;
}

int32_t StreamOperator::CreateStreams(const std::vector<StreamInfo>& streamInfos)
{
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    DFX_LOCAL_HITRACE_BEGIN;
    for (const auto& it : streamInfos) {
        CHECK_IF_NOT_EQUAL_RETURN_VALUE(CheckStreamInfo(it), true, INVALID_ARGUMENT);
        CAMERA_LOGI("streamId:%{public}d and format:%{public}d and width:%{public}d and height:%{public}d",
            it.streamId_, it.format_, it.width_, it.height_);
        if (streamMap_.count(it.streamId_) > 0) {
            CAMERA_LOGE("stream [id = %{public}d] has already been created.", it.streamId_);
            return INVALID_ARGUMENT;
        }
        std::shared_ptr<IStream> stream = StreamFactory::Instance().CreateShared(
            IStream::g_availableStreamType[it.intent_], it.streamId_, it.intent_, pipelineCore_, messenger_);
        if (stream == nullptr) {
            CAMERA_LOGE("create stream [id = %{public}d] failed.", it.streamId_);
            return INSUFFICIENT_RESOURCES;
        }
        StreamConfiguration scg;
        StreamInfoToStreamConfiguration(scg, it);
        RetCode rc = stream->ConfigStream(scg);
        if (rc != RC_OK) {
            CAMERA_LOGE("configure stream %{public}d failed", it.streamId_);
            return INVALID_ARGUMENT;
        }
        if (!scg.tunnelMode && (it.bufferQueue_)->producer_ != nullptr) {
            CAMERA_LOGE("stream [id:%{public}d] is not tunnel mode, can't bind a buffer producer", it.streamId_);
            return INVALID_ARGUMENT;
        }
        if ((it.bufferQueue_)->producer_ != nullptr) {
            auto tunnel = std::make_shared<StreamTunnel>();
            CHECK_IF_PTR_NULL_RETURN_VALUE(tunnel, INSUFFICIENT_RESOURCES);
            rc = tunnel->AttachBufferQueue((it.bufferQueue_)->producer_);
            CHECK_IF_NOT_EQUAL_RETURN_VALUE(rc, RC_OK, INVALID_ARGUMENT);
            if (stream->AttachStreamTunnel(tunnel) != RC_OK) {
                CAMERA_LOGE("attach buffer queue to stream [id = %{public}d] failed", it.streamId_);
                return INVALID_ARGUMENT;
            }
        }
        {
            std::lock_guard<std::mutex> l(streamLock_);
            streamMap_[stream->GetStreamId()] = stream;
        }
        CAMERA_LOGI("create stream success [id:%{public}d] [type:%{public}s]", stream->GetStreamId(),
                    IStream::g_availableStreamType[it.intent_].c_str());
    }
    DFX_LOCAL_HITRACE_END;
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperator::ReleaseStreams(const std::vector<int32_t>& streamIds)
{
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    DFX_LOCAL_HITRACE_BEGIN;
    for (auto id : streamIds) {
        std::lock_guard<std::mutex> l(streamLock_);
        auto it = streamMap_.find(id);
        if (it == streamMap_.end()) {
            continue;
        }
        if (it->second->IsRunning()) {
            it->second->StopStream();
        }
        it->second->DumpStatsInfo();
        it->second->ReleaseStreamBufferPool();
        streamMap_.erase(it);
    }

    for (auto id : streamIds) {
        CHECK_IF_EQUAL_RETURN_VALUE(id < 0, true, INVALID_ARGUMENT);
    }

    DFX_LOCAL_HITRACE_END;
    return HDI::Camera::V1_0::NO_ERROR;
}


RetCode StreamOperator::ReleaseStreams()
{
    std::vector<int32_t> ids = {};
    for (auto it : streamMap_) {
        ids.push_back(it.first);
    }
    ReleaseStreams(ids);
    return RC_OK;
}

int32_t StreamOperator::CommitStreams(OperationMode mode, const std::vector<uint8_t>& modeSetting)
{
    CAMERA_LOGV("enter");
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamPipeline_, DEVICE_ERROR);
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    if (modeSetting.empty()) {
        CAMERA_LOGE("input vector is empty");
        return INVALID_ARGUMENT;
    }
    DFX_LOCAL_HITRACE_BEGIN;

    std::vector<StreamConfiguration> configs = {};
    {
        std::lock_guard<std::mutex> l(streamLock_);
        std::transform(streamMap_.begin(), streamMap_.end(), std::back_inserter(configs),
            [](auto &iter) { return iter.second->GetStreamAttribute(); });
    }

    std::shared_ptr<CameraMetadata> setting;
    MetadataUtils::ConvertVecToMetadata(modeSetting, setting);
    DynamicStreamSwitchMode method = streamPipeline_->CheckStreamsSupported(mode, setting, configs);
    if (method == DYNAMIC_STREAM_SWITCH_NOT_SUPPORT) {
        return INVALID_ARGUMENT;
    }
    if (method == DYNAMIC_STREAM_SWITCH_NEED_INNER_RESTART) {
        std::lock_guard<std::mutex> l(streamLock_);
        for (auto it : streamMap_) {
            it.second->StopStream();
        }
    }
    {
        std::lock_guard<std::mutex> l(streamLock_);
        for (auto it : streamMap_) {
            if (it.second->CommitStream() != RC_OK) {
                CAMERA_LOGE("commit stream [id = %{public}d] failed.", it.first);
                return DEVICE_ERROR;
            }
        }
    }
    RetCode rc = streamPipeline_->PreConfig(setting);
    if (rc != RC_OK) {
        CAMERA_LOGE("prepare mode settings failed");
        return DEVICE_ERROR;
    }
    rc = streamPipeline_->CreatePipeline(mode);
    if (rc != RC_OK) {
        CAMERA_LOGE("create pipeline failed.");
        return INVALID_ARGUMENT;
    }

    DFX_LOCAL_HITRACE_END;
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperator::GetStreamAttributes(std::vector<StreamAttribute>& attributes)
{
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    DFX_LOCAL_HITRACE_BEGIN;

    attributes.clear();
    for (auto it : streamMap_) {
        auto configuration = it.second->GetStreamAttribute();
        StreamAttribute attribute = {};
        attribute.streamId_ = it.first;
        attribute.width_ = configuration.width;
        attribute.height_ = configuration.height;
        attribute.overrideFormat_ = (int32_t)BufferAdapter::CameraFormatToPixelFormat(configuration.format);
        attribute.overrideDataspace_ = configuration.dataspace;
        attribute.producerUsage_ = BufferAdapter::CameraUsageToGrallocUsage(configuration.usage);
        attribute.producerBufferCount_ = configuration.bufferCount;
        attribute.maxBatchCaptureCount_ = configuration.maxCaptureCount;
        attribute.maxCaptureCount_ = configuration.maxCaptureCount;
        attributes.emplace_back(attribute);
    }
    DFX_LOCAL_HITRACE_END;
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperator::AttachBufferQueue(int32_t streamId, const sptr<BufferProducerSequenceable>& bufferProducer)
{
    CHECK_IF_EQUAL_RETURN_VALUE(streamId < 0, true, INVALID_ARGUMENT);
    CHECK_IF_PTR_NULL_RETURN_VALUE(bufferProducer, INVALID_ARGUMENT);
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    DFX_LOCAL_HITRACE_BEGIN;

    std::shared_ptr<IStream> stream = nullptr;
    {
        std::lock_guard<std::mutex> l(streamLock_);
        auto it = streamMap_.find(streamId);
        if (it == streamMap_.end()) {
            return INVALID_ARGUMENT;
        }
        stream = it->second;
    }

    CHECK_IF_PTR_NULL_RETURN_VALUE(stream, INVALID_ARGUMENT);
    CHECK_IF_EQUAL_RETURN_VALUE(stream->GetTunnelMode(), false, METHOD_NOT_SUPPORTED);

    auto tunnel = std::make_shared<StreamTunnel>();
    CHECK_IF_EQUAL_RETURN_VALUE(tunnel, nullptr, INSUFFICIENT_RESOURCES);
    auto bufferQueue = const_cast<OHOS::sptr<OHOS::IBufferProducer>&>(bufferProducer->producer_);
    RetCode rc = tunnel->AttachBufferQueue(bufferQueue);
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(rc, RC_OK, INVALID_ARGUMENT);

    rc = stream->AttachStreamTunnel(tunnel);
    if (rc != RC_OK) {
        CAMERA_LOGE("attach buffer queue to stream [id = %{public}d] failed", streamId);
        return CAMERA_BUSY;
    }
    DFX_LOCAL_HITRACE_END;
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperator::DetachBufferQueue(int32_t streamId)
{
    CHECK_IF_EQUAL_RETURN_VALUE(streamId < 0, true, INVALID_ARGUMENT);
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    DFX_LOCAL_HITRACE_BEGIN;

    std::shared_ptr<IStream> stream = nullptr;
    {
        std::lock_guard<std::mutex> l(streamLock_);
        auto it = streamMap_.find(streamId);
        if (it == streamMap_.end()) {
            return INVALID_ARGUMENT;
        }
        stream = it->second;
    }

    CHECK_IF_PTR_NULL_RETURN_VALUE(stream, INVALID_ARGUMENT);
    CHECK_IF_EQUAL_RETURN_VALUE(stream->GetTunnelMode(), false, METHOD_NOT_SUPPORTED);
    RetCode rc = RC_ERROR;
    if (stream->IsRunning()) {
        rc = stream->StopStream();
        CHECK_IF_NOT_EQUAL_RETURN_VALUE(rc, RC_OK, DEVICE_ERROR);
    }

    rc = stream->DetachStreamTunnel();
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(rc, RC_OK, DEVICE_ERROR);

    DFX_LOCAL_HITRACE_END;
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperator::Capture(int32_t captureId, const CaptureInfo& info, bool isStreaming)
{
    CHECK_IF_EQUAL_RETURN_VALUE(captureId < 0, true, INVALID_ARGUMENT);
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    DFX_LOCAL_HITRACE_BEGIN;

    for (auto id : info.streamIds_) {
        std::lock_guard<std::mutex> l(streamLock_);
        auto it = streamMap_.find(id);
        if (it == streamMap_.end()) {
            return INVALID_ARGUMENT;
        }
    }

    {
        std::lock_guard<std::mutex> l(requestLock_);
        auto itr = requestMap_.find(captureId);
        if (itr != requestMap_.end()) {
            return INVALID_ARGUMENT;
        }
    }

    std::shared_ptr<CameraMetadata> captureSetting;
    MetadataUtils::ConvertVecToMetadata(info.captureSetting_, captureSetting);
    auto request =
        std::make_shared<CaptureRequest>(captureId, info.streamIds_.size(), captureSetting,
                                         info.enableShutterCallback_, isStreaming);
    for (auto id : info.streamIds_) {
        RetCode rc = streamMap_[id]->AddRequest(request);
        if (rc != RC_OK) {
            return DEVICE_ERROR;
        }
    }

    {
        std::lock_guard<std::mutex> l(requestLock_);
        requestMap_[captureId] = request;
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperator::CancelCapture(int32_t captureId)
{
    CHECK_IF_EQUAL_RETURN_VALUE(captureId < 0, true, INVALID_ARGUMENT);
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    DFX_LOCAL_HITRACE_BEGIN;

    std::lock_guard<std::mutex> l(requestLock_);
    auto itr = requestMap_.find(captureId);
    if (itr == requestMap_.end()) {
        CAMERA_LOGE("can't cancel capture [id = %{public}d], this capture doesn't exist", captureId);
        return INVALID_ARGUMENT;
    }

    RetCode rc = itr->second->Cancel();
    if (rc != RC_OK) {
        return DEVICE_ERROR;
    }
    requestMap_.erase(itr);

    DFX_LOCAL_HITRACE_END;
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperator::ChangeToOfflineStream(const std::vector<int32_t>& streamIds,
    const sptr<IStreamOperatorCallback>& callbackObj, sptr<IOfflineStreamOperator>& offlineOperator)
{
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    DFX_LOCAL_HITRACE_BEGIN;
    CHECK_IF_PTR_NULL_RETURN_VALUE(callbackObj, INVALID_ARGUMENT);
    // offlineOperator should not be null
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(offlineOperator, nullptr, INVALID_ARGUMENT);
    CHECK_IF_EQUAL_RETURN_VALUE(streamIds.empty(), true, INVALID_ARGUMENT);

#ifdef CAMERA_BUILT_ON_OHOS_LITE
    oflstor_ = std::make_shared<OfflineStreamOperator>();
#else
    oflstor_ = new (std::nothrow) OfflineStreamOperator();
#endif
    CHECK_IF_PTR_NULL_RETURN_VALUE(oflstor_, INSUFFICIENT_RESOURCES);

    for (auto it : streamIds) {
        CHECK_IF_EQUAL_RETURN_VALUE(it < 0, true, INVALID_ARGUMENT);
        std::lock_guard<std::mutex> l(streamLock_);
        auto streamIt = streamMap_.find(it);
        if (streamIt == streamMap_.end()) {
            CAMERA_LOGE("stream id %{public}d doesn't exist, change to offline mode failed.", it);
            return INVALID_ARGUMENT;
        }
        // only still-capture stream can be changed to offline mode
        if (streamMap_[it]->GetStreamAttribute().type != STILL_CAPTURE) {
            return METHOD_NOT_SUPPORTED;
        }

        auto offlineStream = std::make_shared<OfflineStream>(it, callbackObj);
        CHECK_IF_PTR_NULL_RETURN_VALUE(offlineStream, INSUFFICIENT_RESOURCES);

        RetCode rc = streamMap_[it]->ChangeToOfflineStream(offlineStream);
        if (rc != RC_OK) {
            CAMERA_LOGE("stream id %{public}d change to offline mode failed.", it);
            return DEVICE_ERROR;
        }
        rc = oflstor_->CommitOfflineStream(offlineStream);
        if (rc != RC_OK) {
            CAMERA_LOGE("stream id %{public}d, commit offline stream failed.", it);
            return DEVICE_ERROR;
        }
        CAMERA_LOGI("stream %{public}d switch to offline success.", it);
    }

    offlineOperator = oflstor_;
    DFX_LOCAL_HITRACE_END;
    return HDI::Camera::V1_0::NO_ERROR;
}

bool StreamOperator::CheckStreamInfo(const StreamInfo streamInfo)
{
    if (streamInfo.streamId_ < 0 || streamInfo.width_ < 0 || streamInfo.height_ < 0 || streamInfo.format_ < 0 ||
        streamInfo.dataspace_ < 0 || streamInfo.intent_ > CUSTOM || streamInfo.intent_ < PREVIEW ||
        streamInfo.minFrameDuration_ < 0) {
        return false;
    }
    return true;
}

void StreamOperator::HandleCallbackMessage(MessageGroup& message)
{
    if (message.empty()) {
        return;
    }
    CHECK_IF_PTR_NULL_RETURN_VOID(message[0]);
    CaptureMessageType type = message[0]->GetMessageType();
    switch (type) {
        case CAPTURE_MESSAGE_TYPE_ON_STARTED: {
            std::vector<int32_t> ids = {};
            for (auto cm : message) {
                auto m = std::static_pointer_cast<CaptureStartedMessage>(cm);
                CHECK_IF_PTR_NULL_RETURN_VOID(m);
                ids.push_back(m->GetStreamId());
            }
            OnCaptureStarted(message[0]->GetCaptureId(), ids);
            break;
        }
        case CAPTURE_MESSAGE_TYPE_ON_ERROR: {
            std::vector<CaptureErrorInfo> info = {};
            for (auto cm : message) {
                auto m = std::static_pointer_cast<CaptureErrorMessage>(cm);
                CHECK_IF_PTR_NULL_RETURN_VOID(m);
                CaptureErrorInfo edi = {};
                edi.streamId_ = m->GetStreamId();
                edi.error_ = m->GetStreamError();
                info.push_back(edi);
            }
            OnCaptureError(message[0]->GetCaptureId(), info);
            break;
        }
        case CAPTURE_MESSAGE_TYPE_ON_ENDED: {
            std::vector<CaptureEndedInfo> info = {};
            for (auto cm : message) {
                auto m = std::static_pointer_cast<CaptureEndedMessage>(cm);
                CHECK_IF_PTR_NULL_RETURN_VOID(m);
                CaptureEndedInfo edi = {};
                edi.streamId_ = m->GetStreamId();
                edi.frameCount_ = m->GetFrameCount();
                info.push_back(edi);
            }
            OnCaptureEnded(message[0]->GetCaptureId(), info);
            break;
        }
        case CAPTURE_MESSAGE_TYPE_ON_SHUTTER: {
            std::vector<int32_t> ids = {};
            for (auto cm : message) {
                auto m = std::static_pointer_cast<FrameShutterMessage>(cm);
                CHECK_IF_PTR_NULL_RETURN_VOID(m);
                ids.push_back(m->GetStreamId());
            }
            OnFrameShutter(message[0]->GetCaptureId(), ids, message[0]->GetTimestamp());
            break;
        }
        default:
            break;
    }
    return;
}

void StreamOperator::OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    CHECK_IF_EQUAL_RETURN_VOID(callback_, nullptr);
    callback_->OnCaptureStarted(captureId, streamIds);
}

void StreamOperator::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
{
    CHECK_IF_EQUAL_RETURN_VOID(callback_, nullptr);
    callback_->OnCaptureEnded(captureId, infos);

    std::lock_guard<std::mutex> l(requestLock_);
    auto itr = requestMap_.find(captureId);
    if (itr == requestMap_.end()) {
        return;
    }
    requestMap_.erase(itr);
}

void StreamOperator::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    CHECK_IF_EQUAL_RETURN_VOID(callback_, nullptr);
    callback_->OnCaptureError(captureId, infos);
}

void StreamOperator::OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    CHECK_IF_EQUAL_RETURN_VOID(callback_, nullptr);
    callback_->OnFrameShutter(captureId, streamIds, timestamp);
}
} // end namespace OHOS::Camera
