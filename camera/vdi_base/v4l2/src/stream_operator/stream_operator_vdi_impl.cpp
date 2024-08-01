/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <iterator>
#include "watchdog.h"
#include "stream_operator_vdi_impl.h"
#include "buffer_adapter.h"
#include "camera_device_vdi_impl.h"
#include "camera_host_config.h"
#include "metadata_utils.h"
#include "camera_dump.h"
#ifdef HITRACE_LOG_ENABLED
#include "hdf_trace.h"
#define HDF_CAMERA_TRACE HdfTrace trace(__func__, "HDI:CAM:")
#else
#define HDF_CAMERA_TRACE
#endif

namespace OHOS::Camera {
StreamOperatorVdiImpl::StreamOperatorVdiImpl(const OHOS::sptr<IStreamOperatorVdiCallback> &callback,
    const std::weak_ptr<ICameraDeviceVdi> &device)
{
    CAMERA_LOGV("enter");
    callback_ = callback;
    device_ = device;
}

StreamOperatorVdiImpl::~StreamOperatorVdiImpl()
{
    CAMERA_LOGV("enter");
}

RetCode StreamOperatorVdiImpl::Init()
{
    auto dev = std::static_pointer_cast<CameraDeviceVdiImpl>(device_.lock());
    CHECK_IF_PTR_NULL_RETURN_VALUE(dev, RC_ERROR);
    pipelineCore_ = dev->GetPipelineCore();
    if (pipelineCore_ == nullptr) {
        CAMERA_LOGE("get pipeline core failed.");
        return RC_ERROR;
    }

    requestTimeoutCB_ = std::bind(&CameraDeviceVdiImpl::OnRequestTimeout, dev);
    streamPipeline_ = pipelineCore_->GetStreamPipelineCore();
    if (streamPipeline_ == nullptr) {
        CAMERA_LOGE("get stream pipeline core failed.");
        return RC_ERROR;
    }

    std::string cameraIds;
    dev->GetCameraId(cameraIds);
    RetCode rc = streamPipeline_->Init(cameraIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("stream pipeline core init failed.");
        return RC_ERROR;
    }

    auto cb = [this](MessageGroup &m) { HandleCallbackMessage(m); };
    messenger_ = std::make_shared<CaptureMessageOperator>(cb);
    CHECK_IF_PTR_NULL_RETURN_VALUE(messenger_, RC_ERROR);
    messenger_->StartProcess();

    return RC_OK;
}

void StreamOperatorVdiImpl::GetStreamSupportType(std::set<int32_t> inputIDSet,
    DynamicStreamSwitchMode method, VdiStreamSupportType &type)
{
    std::set<int32_t> currentIDSet = {};
    {
        std::lock_guard<std::mutex> l(streamLock_);
        for (auto &it : streamMap_) {
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

int32_t StreamOperatorVdiImpl::IsStreamsSupported(VdiOperationMode mode, const std::vector<uint8_t> &modeSetting,
    const std::vector<VdiStreamInfo> &infos, VdiStreamSupportType &type)
{
    HDF_CAMERA_TRACE;
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
        return VDI::Camera::V1_0::NO_ERROR;
    }

    if (method == DYNAMIC_STREAM_SWITCH_NOT_SUPPORT) {
        type = NOT_SUPPORTED;
        return VDI::Camera::V1_0::NO_ERROR;
    }

    // change mode need to update pipeline, and caller must restart streams
    if (mode != streamPipeline_->GetCurrentMode()) {
        if (method == DYNAMIC_STREAM_SWITCH_NEED_INNER_RESTART) {
            type = RE_CONFIGURED_REQUIRED;
            return VDI::Camera::V1_0::NO_ERROR;
        }
        type = NOT_SUPPORTED;
        return VDI::Camera::V1_0::NO_ERROR;
    }

    if (method == DYNAMIC_STREAM_SWITCH_NEED_INNER_RESTART) {
        GetStreamSupportType(inputIDSet, method, type);
        return VDI::Camera::V1_0::NO_ERROR;
    }

    DFX_LOCAL_HITRACE_END;
    return VDI::Camera::V1_0::NO_ERROR;
}

DynamicStreamSwitchMode StreamOperatorVdiImpl::CheckStreamsSupported(
    VdiOperationMode mode,
    const std::shared_ptr<CameraMetadata> &modeSetting,
    const std::vector<VdiStreamInfo> &infos)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamPipeline_, DYNAMIC_STREAM_SWITCH_NOT_SUPPORT);
    std::vector<StreamConfiguration> configs = {};
    for (auto &it : infos) {
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

void StreamOperatorVdiImpl::StreamInfoToStreamConfiguration(StreamConfiguration &scg, const VdiStreamInfo info)
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

int32_t StreamOperatorVdiImpl::CreateStreams(const std::vector<VdiStreamInfo> &streamInfos)
{
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    HDF_CAMERA_TRACE;
    DFX_LOCAL_HITRACE_BEGIN;
    for (const auto &it : streamInfos) {
        CHECK_IF_NOT_EQUAL_RETURN_VALUE(CheckStreamInfo(it), true, INVALID_ARGUMENT);
        CAMERA_LOGI("streamId:%{public}d and format:%{public}d and width:%{public}d and height:%{public}d",
            it.streamId_, it.format_, it.width_, it.height_);
        if (streamMap_.count(it.streamId_) > 0) {
            CAMERA_LOGE("stream [id = %{public}d] has already been created.", it.streamId_);
            return INVALID_ARGUMENT;
        }
        std::shared_ptr<IStream> stream = StreamFactory::Instance().CreateShared(
            IStream::g_availableStreamType[it.intent_], it.streamId_, it.intent_, pipelineCore_, messenger_);

        CHECK_IF_PTR_NULL_RETURN_VALUE(stream, INSUFFICIENT_RESOURCES);

        StreamConfiguration scg;
        StreamInfoToStreamConfiguration(scg, it);
        RetCode rc = stream->ConfigStream(scg);
        CHECK_IF_NOT_EQUAL_RETURN_VALUE(rc, RC_OK, INVALID_ARGUMENT);
        CHECK_IF_PTR_NULL_RETURN_VALUE(it.bufferQueue_, INVALID_ARGUMENT);

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
        std::lock_guard<std::mutex> l(streamLock_);
        streamMap_[stream->GetStreamId()] = stream;
        CAMERA_LOGI("create stream success [id:%{public}d] [type:%{public}s]", stream->GetStreamId(),
                    IStream::g_availableStreamType[it.intent_].c_str());
    }
    DFX_LOCAL_HITRACE_END;
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperatorVdiImpl::ReleaseStreams(const std::vector<int32_t> &streamIds)
{
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    HDF_CAMERA_TRACE;
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
    return VDI::Camera::V1_0::NO_ERROR;
}


RetCode StreamOperatorVdiImpl::ReleaseStreams()
{
    std::vector<int32_t> ids = {};
    for (auto it : streamMap_) {
        ids.push_back(it.first);
    }
    ReleaseStreams(ids);
    return RC_OK;
}

int32_t StreamOperatorVdiImpl::CommitStreams(VdiOperationMode mode, const std::vector<uint8_t> &modeSetting)
{
    HDF_CAMERA_TRACE;
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
    CameraHalTimeSysevent::WriteCameraParameterEvent(CameraHalTimeSysevent::GetEventName(PARAMS_OFCAPTURE_OR_VEDIO),
                                                     setting->get());
    CHECK_IF_EQUAL_RETURN_VALUE(method, DYNAMIC_STREAM_SWITCH_NOT_SUPPORT, INVALID_ARGUMENT);
    {
        std::lock_guard<std::mutex> l(streamLock_);
        if (method == DYNAMIC_STREAM_SWITCH_NEED_INNER_RESTART) {
            for (auto it : streamMap_) {
                it.second->StopStream();
            }
        }

        for (auto it : streamMap_) {
            if (it.second->CommitStream() != RC_OK) {
                CAMERA_LOGE("commit stream [id = %{public}d] failed.", it.first);
                return DEVICE_ERROR;
            }
        }
    }
    RetCode rc = streamPipeline_->PreConfig(setting);
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(rc, RC_OK, DEVICE_ERROR);

    auto dev = std::static_pointer_cast<CameraDeviceVdiImpl>(device_.lock());
    CHECK_IF_PTR_NULL_RETURN_VALUE(dev, RC_ERROR);
    std::string cameraId;
    dev->GetCameraId(cameraId);
    // 2:uvc mode
    int32_t mode1 = CameraHostConfig::GetInstance()->SearchUsbCameraId(cameraId) ? 2 : mode;

    rc = streamPipeline_->CreatePipeline(mode1);
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(rc, RC_OK, INVALID_ARGUMENT);

    DFX_LOCAL_HITRACE_END;
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperatorVdiImpl::GetStreamAttributes(std::vector<VdiStreamAttribute> &attributes)
{
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    HDF_CAMERA_TRACE;
    DFX_LOCAL_HITRACE_BEGIN;

    attributes.clear();
    for (auto it : streamMap_) {
        auto configuration = it.second->GetStreamAttribute();
        VdiStreamAttribute attribute = {};
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
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperatorVdiImpl::AttachBufferQueue(int32_t streamId,
    const sptr<BufferProducerSequenceable> &bufferProducer)
{
    CHECK_IF_EQUAL_RETURN_VALUE(streamId < 0, true, INVALID_ARGUMENT);
    CHECK_IF_PTR_NULL_RETURN_VALUE(bufferProducer, INVALID_ARGUMENT);
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    HDF_CAMERA_TRACE;
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
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperatorVdiImpl::DetachBufferQueue(int32_t streamId)
{
    CHECK_IF_EQUAL_RETURN_VALUE(streamId < 0, true, INVALID_ARGUMENT);
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    HDF_CAMERA_TRACE;
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
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperatorVdiImpl::Capture(int32_t captureId, const VdiCaptureInfo &info, bool isStreaming)
{
    CAMERA_LOGI("--- start Capture captureId = [%{public}d] ---", captureId) ;
    CHECK_IF_EQUAL_RETURN_VALUE(captureId < 0, true, INVALID_ARGUMENT);
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    HDF_CAMERA_TRACE;
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

    CameraDumper &dumper = CameraDumper::GetInstance();
    dumper.DumpMetadata("capturesetting", ENABLE_METADATA, captureSetting);

    auto request =
        std::make_shared<CaptureRequest>(captureId, info.streamIds_.size(), captureSetting,
                                         info.enableShutterCallback_, isStreaming);
    request->SetFirstRequest(!isStreaming);
    for (auto id : info.streamIds_) {
        std::lock_guard<std::mutex> l(streamLock_);
        RetCode rc = streamMap_[id]->AddRequest(request);
        if (rc != RC_OK) {
            return DEVICE_ERROR;
        }
    }

    {
        std::lock_guard<std::mutex> l(requestLock_);
        requestMap_[captureId] = request;
    }
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperatorVdiImpl::CancelCapture(int32_t captureId)
{
    CAMERA_LOGI("--- start CancelCapture captureId = [%{public}d] ---", captureId) ;
    CHECK_IF_EQUAL_RETURN_VALUE(captureId < 0, true, INVALID_ARGUMENT);
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    HDF_CAMERA_TRACE;
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
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t StreamOperatorVdiImpl::ChangeToOfflineStream(const std::vector<int32_t> &streamIds,
    const sptr<IStreamOperatorVdiCallback> &callbackObj, sptr<IOfflineStreamOperatorVdi> &offlineOperator)
{
    PLACE_A_NOKILL_WATCHDOG(requestTimeoutCB_);
    HDF_CAMERA_TRACE;
    DFX_LOCAL_HITRACE_BEGIN;
    CHECK_IF_PTR_NULL_RETURN_VALUE(callbackObj, INVALID_ARGUMENT);
    // offlineOperator should not be null
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(offlineOperator, nullptr, INVALID_ARGUMENT);
    CHECK_IF_EQUAL_RETURN_VALUE(streamIds.empty(), true, INVALID_ARGUMENT);

#ifdef CAMERA_BUILT_ON_OHOS_LITE
    oflstor_ = std::make_shared<OfflineStreamOperatorVdiImpl>();
#else
    oflstor_ = new (std::nothrow) OfflineStreamOperatorVdiImpl();
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
    return VDI::Camera::V1_0::NO_ERROR;
}

bool StreamOperatorVdiImpl::CheckStreamInfo(const VdiStreamInfo streamInfo)
{
    if (streamInfo.streamId_ < 0 || streamInfo.width_ < 0 || streamInfo.height_ < 0 || streamInfo.format_ < 0 ||
        streamInfo.dataspace_ < 0 || streamInfo.intent_ > CUSTOM || streamInfo.intent_ < PREVIEW ||
        streamInfo.minFrameDuration_ < 0) {
        return false;
    }
    return true;
}

void StreamOperatorVdiImpl::FillCaptureErrorInfo(std::vector<VdiCaptureErrorInfo> &info, MessageGroup message)
{
    for (auto cm : message) {
        auto m = std::static_pointer_cast<CaptureErrorMessage>(cm);
        CHECK_IF_PTR_NULL_RETURN_VOID(m);
        VdiCaptureErrorInfo edi = {};
        edi.streamId_ = m->GetStreamId();
        edi.error_ = m->GetStreamError();
        info.push_back(edi);
    }
}

void StreamOperatorVdiImpl::FillCaptureEndedInfo(std::vector<VdiCaptureEndedInfo> &info, MessageGroup message)
{
    for (auto cm : message) {
        auto m = std::static_pointer_cast<CaptureEndedMessage>(cm);
        CHECK_IF_PTR_NULL_RETURN_VOID(m);
        VdiCaptureEndedInfo edi = {};
        edi.streamId_ = m->GetStreamId();
        edi.frameCount_ = m->GetFrameCount();
        info.push_back(edi);
    }
}

void StreamOperatorVdiImpl::HandleCallbackMessage(MessageGroup &message)
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
            std::vector<VdiCaptureErrorInfo> info = {};
            FillCaptureErrorInfo(info, message);
            OnCaptureError(message[0]->GetCaptureId(), info);
            break;
        }
        case CAPTURE_MESSAGE_TYPE_ON_ENDED: {
            std::vector<VdiCaptureEndedInfo> info = {};
            FillCaptureEndedInfo(info, message);
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

void StreamOperatorVdiImpl::OnCaptureStarted(int32_t captureId, const std::vector<int32_t> &streamIds)
{
    CHECK_IF_EQUAL_RETURN_VOID(callback_, nullptr);
    callback_->OnCaptureStarted(captureId, streamIds);
}

void StreamOperatorVdiImpl::OnCaptureEnded(int32_t captureId, const std::vector<VdiCaptureEndedInfo> &infos)
{
    CHECK_IF_EQUAL_RETURN_VOID(callback_, nullptr);
    int32_t ret = callback_->OnCaptureEnded(captureId, infos);
    if (ret != 0) {
        CAMERA_LOGE("OnCaptureEnded captureId: %{public}d failed, ret = %{public}d", captureId, ret);
        return;
    }

    std::lock_guard<std::mutex> l(requestLock_);
    auto itr = requestMap_.find(captureId);
    if (itr == requestMap_.end()) {
        CAMERA_LOGE("OnCaptureEnded captureId: %{public}d not found request", captureId);
        return;
    }
    requestMap_.erase(itr);
}

void StreamOperatorVdiImpl::OnCaptureError(int32_t captureId, const std::vector<VdiCaptureErrorInfo> &infos)
{
    CHECK_IF_EQUAL_RETURN_VOID(callback_, nullptr);
    callback_->OnCaptureError(captureId, infos);
}

void StreamOperatorVdiImpl::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t> &streamIds, uint64_t timestamp)
{
    CHECK_IF_EQUAL_RETURN_VOID(callback_, nullptr);
    callback_->OnFrameShutter(captureId, streamIds, timestamp);
}
} // end namespace OHOS::Camera
