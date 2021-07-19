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

#include "stream_operator_impl.h"
#include "buffer_manager.h"
#include "camera_capture.h"
#include "camera_device_impl.h"
#include "camera_host_config.h"
#include "camera_metadata_info.h"
#include "ipipeline_core.h"
#include "istream_pipeline_core.h"
#include "offline_stream_context.h"
#include "stream_supported_config.h"
#include "watchdog.h"
#include "hitrace.h"

namespace {
    constexpr uint32_t IS_STREAMING_QUEUE_SIZE = 7;
    constexpr uint32_t OTHRE_QUEUE_SIZE = 1;
    const std::string SUPPORTED_CONFIG_PATH_NAME = "/system/etc/hdfconfig/stream_supported_config.hcb";
}

namespace OHOS::Camera {
StreamOperatorImpl::StreamOperatorImpl(
    const OHOS::sptr<IStreamOperatorCallback> &callback,
    const std::weak_ptr<CameraDevice> &device)
    : streamOperatorCallback_(callback), cameraDevice_(device), streamPipeCore_(nullptr)
{
}

StreamOperatorImpl::~StreamOperatorImpl()
{
    CAMERA_LOGV("enter");
    Stop();
    {
        std::unique_lock<std::mutex> streamLock(streamMutex_);
        std::map<int, std::shared_ptr<StreamBase>>().swap(streamMap_);
    }
    {
        std::unique_lock<std::mutex> lock(captureMutex_);
        std::map<int, std::shared_ptr<CameraCapture>>().swap(camerCaptureMap_);
    }
}

CamRetCode StreamOperatorImpl::IsStreamsSupported(OperationMode mode,
                                                  const std::shared_ptr<CameraStandard::CameraMetadata>& modeSetting,
                                                  const std::shared_ptr<StreamInfo>& pInfo,
                                                  StreamSupportType& pType)
{
    WatchDog watchDog;
    watchDog.Init(WATCHDOG_TIMEOUT, requestCallback_);
    HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTrace::Begin("streamOperator", HITRACE_FLAG_DEFAULT);

    if (modeSetting == nullptr || pInfo == nullptr) {
        CAMERA_LOGE("stream info is null.");
        return INVALID_ARGUMENT;
    }

    if (config_ == nullptr) {
        config_ = std::make_unique<StreamSupportedConfig>(SUPPORTED_CONFIG_PATH_NAME);
    }

    if (config_ == nullptr) {
        CAMERA_LOGE("stream suuported config new failed.");
        return INVALID_ARGUMENT;
    }

    RetCode rc = config_->Init();
    if (rc != RC_OK) {
        CAMERA_LOGE("config read failed. [pathname = %{public}s]", SUPPORTED_CONFIG_PATH_NAME.c_str());
        return INVALID_ARGUMENT;
    }

    std::vector<std::shared_ptr<StreamSupported>> streamSupporteds;
    config_->GetStreamSupporteds(streamSupporteds);

    SelectSupportedForMode(mode, streamSupporteds);
    if (streamSupporteds.empty()) {
        pType = NOT_SUPPORTED;
        return NO_ERROR;
    }

    SelectSupportedForStreamInfo(pInfo, streamSupporteds);
    if (streamSupporteds.empty()) {
        pType = NOT_SUPPORTED;
        return NO_ERROR;
    }

    bool bRet = IsSupportedForMeta(modeSetting);
    if (!bRet) {
        std::vector<std::shared_ptr<StreamSupported>>().swap(streamSupporteds);
        pType = NOT_SUPPORTED;
        return INVALID_ARGUMENT;
    }

    pType = streamSupporteds.front()->streamSupportType_;
    OHOS::HiviewDFX::HiTrace::End(traceId);

    return NO_ERROR;
}

void StreamOperatorImpl::SelectSupportedForMode(OperationMode mode,
                                                std::vector<std::shared_ptr<StreamSupported>>& streamSupporteds)
{
    std::vector<std::shared_ptr<StreamSupported>> selectSupported;
    for (auto& supported : streamSupporteds) {
        if (supported->operationMode_ == mode) {
            selectSupported.push_back(supported);
        }
    }

    streamSupporteds.swap(selectSupported);
}

bool StreamOperatorImpl::IsSupportedForMeta(const std::shared_ptr<CameraStandard::CameraMetadata>& modeSetting)
{
    // get metadata tags
    std::shared_ptr<CameraStandard::CameraMetadata> ability;
    GetConfigAbility(ability);
    if (ability == nullptr) {
        return false;
    }

    std::vector<MetaType> cfgTags;
    GetTagsForMetadata(ability, cfgTags);
    if (cfgTags.empty()) {
        return false;
    }

    std::vector<MetaType> settings;
    GetTagsForMetadata(modeSetting, settings);
    if (settings.empty()) {
        return false;
    }

    for (auto& type : settings) {
        auto itr = std::find(cfgTags.begin(), cfgTags.end(), type);
        if (itr == cfgTags.end()) {
            return false;
        }
    }
    return true;
}

void StreamOperatorImpl::GetConfigAbility(std::shared_ptr<CameraStandard::CameraMetadata>& ability)
{
    CameraHostConfig* config = CameraHostConfig::GetInstance();
    if (config == nullptr) {
        return;
    }

    std::string cameraId;
    auto device = cameraDevice_.lock();
    if (device == nullptr) {
        CAMERA_LOGE("cameradevice is null.");
        return;
    }
    device->GetCameraId(cameraId);

    RetCode rc = config->GetCameraAbility(cameraId, ability);
    if (rc != RC_OK) {
        CAMERA_LOGD("get ability failed.");
        return;
    }
}

void StreamOperatorImpl::GetTagsForMetadata(const std::shared_ptr<CameraStandard::CameraMetadata>& cameraMetadata,
                                            std::vector<MetaType>& tags)
{
    if (cameraMetadata == nullptr) {
        return;
    }

    common_metadata_header_t* meta = cameraMetadata->get();
    if (meta == nullptr) {
        return;
    }

    size_t tagCount = get_camera_metadata_item_count(meta);
    for (int i = 0; i < tagCount; i++) {
        camera_metadata_item_t entry;
        int ret = find_camera_metadata_item(meta, i, &entry);
        if (ret == 0) {
            tags.push_back(entry.item);
        }
    }
}

void StreamOperatorImpl::SelectSupportedForStreamInfo(const std::shared_ptr<StreamInfo>& pInfo,
                                                      std::vector<std::shared_ptr<StreamSupported>>& streamSupporteds)
{
    std::vector<std::shared_ptr<StreamSupported>> selectSupported;
    for (auto& supported : streamSupporteds) {
        auto itr = std::find_if(supported->streamInfos_.begin(), supported->streamInfos_.end(),
                                [pInfo](const std::shared_ptr<StreamInfo> streamInfo) {
                                    if (pInfo->width_ != streamInfo->width_) {
                                        return false;
                                    }
                                    if (pInfo->height_ != streamInfo->height_) {
                                        return false;
                                    }
                                    if (pInfo->format_ != streamInfo->format_) {
                                        return false;
                                    }
                                    if (pInfo->datasapce_ != streamInfo->datasapce_) {
                                        return false;
                                    }
                                    if (pInfo->intent_ != streamInfo->intent_) {
                                        return false;
                                    }
                                    if (pInfo->tunneledMode_ != streamInfo->tunneledMode_) {
                                        return false;
                                    }
                                    if (pInfo->minFrameDuration_ != streamInfo->minFrameDuration_) {
                                        return false;
                                    }
                                    return true;
                                });
        if (itr != supported->streamInfos_.end()) {
            selectSupported.push_back(supported);
        }
    }

    streamSupporteds.swap(selectSupported);
}

CamRetCode StreamOperatorImpl::CreateStreams(const std::vector<std::shared_ptr<StreamInfo>>& streamInfos)
{
    CAMERA_LOGV("enter");

    WatchDog watchDog;
    watchDog.Init(WATCHDOG_TIMEOUT, requestCallback_);
    HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTrace::Begin("streamOperator", HITRACE_FLAG_DEFAULT);

    if (streamInfos.empty()) {
        CAMERA_LOGE("streamInfo is empty.");
        return INVALID_ARGUMENT;
    }

    for (auto& streamInfo : streamInfos) {
        if (streamInfo == nullptr || !ValidStreamInfo(streamInfo)) {
            CAMERA_LOGE("stream info is null.");
            return INVALID_ARGUMENT;
        }
        auto prod = streamInfo->bufferQueue_;
        if (prod == nullptr) {
            CAMERA_LOGV("get queue is null");
        } else {
            CAMERA_LOGV("get queue size = %d", prod->GetQueueSize());
        }
    }

    for (auto& streamInfo : streamInfos) {
        if (CreateStream(streamInfo) != RC_OK) {
            std::map<int, std::shared_ptr<StreamBase>>().swap(streamMap_);
            return METHOD_NOT_SUPPORTED;
        }

        if (CreatePipeStream(streamInfo) != RC_OK) {
            return METHOD_NOT_SUPPORTED;
        }
    }
    OHOS::HiviewDFX::HiTrace::End(traceId);

    return NO_ERROR;
}

RetCode StreamOperatorImpl::CreateStream(const std::shared_ptr<StreamInfo>& streamInfo)
{
    static std::map<StreamIntent, std::string> typeMap = {
        {PREVIEW, "PREVIEW"},
        {VIDEO, "VIDEO"},
        {STILL_CAPTURE, "STILL_CAPTURE"},
        {POST_VIEW, "POST_VIEW"}, {ANALYZE, "ANALYZE"},
        {CUSTOM, "CUSTOM"}
    };

    auto itr = typeMap.find(streamInfo->intent_);
    if (itr == typeMap.end()) {
        CAMERA_LOGE("do not support stream type. [type = %{public}d]", streamInfo->intent_);
        return RC_ERROR;
    }

    std::shared_ptr<StreamBase> stream = StreamFactory::Instance().CreateShared(itr->second);
    if (stream == nullptr) {
        CAMERA_LOGE("create stream failed. [streamId = %{public}d]", streamInfo->streamId_);
        return RC_ERROR;
    }

    RetCode rc = stream->Init(streamInfo);
    if (rc == RC_OK) {
        std::unique_lock<std::mutex> streamLock(streamMutex_);
        streamMap_.insert(std::make_pair(streamInfo->streamId_, stream));
    }

    return RC_OK;
}

RetCode StreamOperatorImpl::CreatePipeStream(const std::shared_ptr<StreamInfo>& streamInfo)
{
    auto cameraDevice = cameraDevice_.lock();
    if (cameraDevice == nullptr) {
        CAMERA_LOGE("camera device closed.");
        return RC_ERROR;
    }

    std::shared_ptr<IPipelineCore> PipelineCore =
        std::static_pointer_cast<CameraDeviceImpl>(cameraDevice)->GetPipelineCore();
    if (PipelineCore == nullptr) {
        CAMERA_LOGE("get pipeline core failed.");
        return RC_ERROR;
    }

    std::shared_ptr<HostStreamMgr> hostStreamMgr = PipelineCore->GetHostStreamMgr();
    if (hostStreamMgr == nullptr) {
        CAMERA_LOGE("get host stream manager failed.");
        return RC_ERROR;
    }

    auto itr = streamMap_.find(streamInfo->streamId_);
    if (itr == streamMap_.end() || itr->second == nullptr) {
        return RC_ERROR;
    }
    int streamId = streamInfo->streamId_;

    HostStreamInfo hStreamInfo;
    hStreamInfo.bufferPoolId_ = itr->second->GetBufferPoolId();
    ChangeHostStreamInfo(streamInfo, hStreamInfo);
    CAMERA_LOGV("host stream info id[%d], w[%d], h[%d], poolId[%llu]", hStreamInfo.streamId_,
                hStreamInfo.width_, hStreamInfo.height_, hStreamInfo.bufferPoolId_);
    RetCode rc = hostStreamMgr->CreateHostStream(hStreamInfo, [this, streamId](std::shared_ptr<IBuffer> buffer) {
        ResultBuffer(streamId, buffer);
    });
    if (rc != RC_OK) {
        CAMERA_LOGE("create stream manager failed.");
        return RC_ERROR;
    }

    return RC_OK;
}

void StreamOperatorImpl::ResultBuffer(int streamId, const std::shared_ptr<IBuffer>& buffer)
{
    auto device = cameraDevice_.lock();
    if (device != nullptr) {
        device->ResultMetadata();
    }

    std::vector<std::shared_ptr<CameraCapture>> resultCapture = {};
    {
        for (auto &capture : camerCaptureMap_) {
            std::shared_ptr<CaptureInfo> captureInfo = capture.second->GetCaptureInfo();
            if (captureInfo == nullptr) {
                CAMERA_LOGD("captureInfo is null.");
                continue;
            }

            auto itr = std::find(captureInfo->streamIds_.begin(), captureInfo->streamIds_.end(), streamId);
            if (itr == captureInfo->streamIds_.end()) {
                CAMERA_LOGD("streamId find is failed. streamId = %d.", streamId);
                continue;
            }
            resultCapture.emplace_back(capture.second);
        }
    }
    for (auto it : resultCapture) {
        it->ResultBuffer(streamId, buffer);
    }
}

uint64_t StreamOperatorImpl::GetCurrentLocalTimeStamp()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return tmp.count();
}

bool StreamOperatorImpl::ValidStreamInfo(const std::shared_ptr<StreamInfo>& streamInfo)
{
    if (streamInfo->streamId_ < 0 || streamInfo->width_ < 0 || streamInfo->height_ < 0 || streamInfo->format_ < 0 ||
        streamInfo->datasapce_ < 0 || streamInfo->intent_ > CUSTOM || streamInfo->intent_ < PREVIEW ||
        streamInfo->minFrameDuration_ < 0) {
        return false;
    }
    return true;
}

void StreamOperatorImpl::ChangeHostStreamInfo(const std::shared_ptr<StreamInfo>& streamInfo,
                                              HostStreamInfo& hStreamInfo)
{
    hStreamInfo.type_ = streamInfo->intent_;
    hStreamInfo.streamId_ = streamInfo->streamId_;
    hStreamInfo.width_ = streamInfo->width_;
    hStreamInfo.height_ = streamInfo->height_;
    hStreamInfo.format_ = streamInfo->format_;
    if (streamInfo->bufferQueue_ != nullptr) {
        hStreamInfo.bufferCount_ = streamInfo->bufferQueue_->GetQueueSize();
    } else if (hStreamInfo.format_ == PREVIEW || hStreamInfo.format_ == VIDEO) {
        hStreamInfo.bufferCount_ = IS_STREAMING_QUEUE_SIZE;
    } else {
        hStreamInfo.bufferCount_ = OTHRE_QUEUE_SIZE;
    }
}

CamRetCode StreamOperatorImpl::ReleaseStreams(const std::vector<int>& streamIds)
{
    CAMERA_LOGI("begin to release stream");
    WatchDog watchDog;
    watchDog.Init(WATCHDOG_TIMEOUT, requestCallback_);
    HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTrace::Begin("streamOperator", HITRACE_FLAG_DEFAULT);

    RetCode rc = DestroyStreamPipeline(streamIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("destroy stream pipe failed.");
        return CAMERA_CLOSED;
    }
    CAMERA_LOGV("DestroyStreamPipeline success.");

    rc = DestroyHostStreamMgr(streamIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("destroy host stream manager failed.");
        return CAMERA_CLOSED;
    }
    CAMERA_LOGV("DestroyHostStreamMgr success.");

    rc = DestroyStreams(streamIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("destroy stream failed.");
        return CAMERA_CLOSED;
    }

    OHOS::HiviewDFX::HiTrace::End(traceId);
    CAMERA_LOGI("release streams success");

    return NO_ERROR;
}

RetCode StreamOperatorImpl::DestroyStreams(const std::vector<int>& streamIds)
{
    CAMERA_LOGV("enter");
    for (auto& streamId : streamIds) {
        uint32_t streamCount = 0;
        for (auto itr = camerCaptureMap_.begin(); itr != camerCaptureMap_.end();) {
            streamCount = itr->second->DeleteStream(streamId);
            if (streamCount <= 0) {
                std::unique_lock<std::mutex> lock(captureMutex_);
                CAMERA_LOGI("all streams of capture [id:%d] request are destroyed", itr->first);
                itr = camerCaptureMap_.erase(itr);
            } else {
                itr++;
            }
        }

        if (streamId < 0) {
            continue;
        }

        auto itr = streamMap_.find(streamId);
        if (itr == streamMap_.end()) {
            continue;
        }

        itr->second->Release();
        std::unique_lock<std::mutex> streamLock(streamMutex_);
        itr = streamMap_.erase(itr);
    }

    {
        std::unique_lock<std::mutex> streamLock(streamMutex_);
        if (streamMap_.empty()) {
            Stop();
        }
    }

    return RC_OK;
}

RetCode StreamOperatorImpl::DestroyStreamPipeline(const std::vector<int>& streamIds)
{
    if (streamIds.empty()) {
        return RC_ERROR;
    }

    if (streamPipeCore_ == nullptr) {
        CAMERA_LOGE("stream pipeline is null.");
        return RC_OK;
    }

    RetCode rc = streamPipeCore_->Stop(streamIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("stream pipeline stop failed.");
        return RC_ERROR;
    }

    rc = streamPipeCore_->DestroyPipeline(streamIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("destory pipeline failed.");
        return RC_ERROR;
    }

    return RC_OK;
}

RetCode StreamOperatorImpl::DestroyHostStreamMgr(const std::vector<int>& streamIds)
{
    if (streamIds.empty()) {
        return RC_ERROR;
    }

    auto cameraDevice = cameraDevice_.lock();
    if (cameraDevice == nullptr) {
        CAMERA_LOGE("camera device is null.");
        return RC_ERROR;
    }

    std::shared_ptr<IPipelineCore> PipelineCore = cameraDevice->GetPipelineCore();
    if (PipelineCore == nullptr) {
        CAMERA_LOGE("get pipeline core failed.");
        return RC_ERROR;
    }

    std::shared_ptr<HostStreamMgr> hostStreamMgr = PipelineCore->GetHostStreamMgr();
    if (hostStreamMgr == nullptr) {
        CAMERA_LOGE("get host stream manager failed.");
        return RC_ERROR;
    }

    RetCode rc = hostStreamMgr->DestroyHostStream(streamIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("destory host stream failed.");
        return RC_ERROR;
    }

    return RC_OK;
}

void StreamOperatorImpl::GetStreamTypes(const std::vector<int>& streamIds, std::vector<int32_t>& types)
{
    for (auto& streamId : streamIds) {
        if (streamId < 0) {
            continue;
        }

        auto itr = streamMap_.find(streamId);
        if (itr == streamMap_.end()) {
            continue;
        }

        std::shared_ptr<StreamInfo> streamInfo = itr->second->GetStreamInfo();
        if (streamInfo == nullptr) {
            CAMERA_LOGE("input streamId is invalid. [streamId = %{public}d]", streamId);
            continue;
        }
        types.push_back(streamInfo->intent_);
    }
}

CamRetCode StreamOperatorImpl::CommitStreams(OperationMode mode, const std::shared_ptr<CameraStandard::CameraMetadata>& modeSetting)
{
    CAMERA_LOGV("enter");
    WatchDog watchDog;
    watchDog.Init(WATCHDOG_TIMEOUT, requestCallback_);
    HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTrace::Begin("streamOperator", HITRACE_FLAG_DEFAULT);

    auto cameraDevice = cameraDevice_.lock();
    if (cameraDevice == nullptr) {
        CAMERA_LOGE("camera device closed.");
        return CAMERA_CLOSED;
    }

    std::shared_ptr<IPipelineCore> PipelineCore =
        std::static_pointer_cast<CameraDeviceImpl>(cameraDevice)->GetPipelineCore();
    if (PipelineCore == nullptr) {
        CAMERA_LOGE("get pipeline core failed.");
        return CAMERA_CLOSED;
    }

    streamPipeCore_ = PipelineCore->GetStreamPipelineCore();
    if (streamPipeCore_ == nullptr) {
        CAMERA_LOGE("get stream pipeline core failed.");
        return DEVICE_ERROR;
    }

    RetCode rc = streamPipeCore_->Init();
    if (rc != RC_OK) {
        CAMERA_LOGE("stream pipeline core init failed.");
        return DEVICE_ERROR;
    }

    rc = streamPipeCore_->CreatePipeline(mode);
    if (rc != RC_OK) {
        CAMERA_LOGE("create pipeline failed.");
        return INVALID_ARGUMENT;
    }
    OHOS::HiviewDFX::HiTrace::End(traceId);

    return NO_ERROR;
}

CamRetCode StreamOperatorImpl::GetStreamAttributes(std::vector<std::shared_ptr<StreamAttribute>>& attributes)
{
    RetCode rc = RC_OK;
    std::shared_ptr<StreamAttribute> attribute = nullptr;
    for (auto& streamPair : streamMap_) {
        rc = streamPair.second->GetStreamAttribute(attribute);
        if (rc == RC_OK) {
            attributes.push_back(attribute);
        }
    }
    return NO_ERROR;
}

CamRetCode StreamOperatorImpl::AttachBufferQueue(int streamId,
    const OHOS::sptr<OHOS::IBufferProducer> &producer)
{
    CAMERA_LOGD("AttachBufferQueue streamId = %d", streamId);
    WatchDog watchDog;
    watchDog.Init(WATCHDOG_TIMEOUT, requestCallback_);
    HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTrace::Begin("streamOperator", HITRACE_FLAG_DEFAULT);

    if (producer == nullptr || streamId < 0) {
        CAMERA_LOGW("input buffer producer is null.");
        return INVALID_ARGUMENT;
    }

    auto itr = streamMap_.find(streamId);
    if (itr != streamMap_.end()) {
        itr->second->AttachBufferQueue(producer);
        return NO_ERROR;
    }

    OHOS::HiviewDFX::HiTrace::End(traceId);
    CAMERA_LOGD("input streamId find not found. [streamId = %d]", streamId);
    return INVALID_ARGUMENT;
}

CamRetCode StreamOperatorImpl::DetachBufferQueue(int streamId)
{
    WatchDog watchDog;
    watchDog.Init(WATCHDOG_TIMEOUT, requestCallback_);
    HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTrace::Begin("streamOperator", HITRACE_FLAG_DEFAULT);

    std::shared_ptr<StreamInfo> streamInfo = nullptr;
    for (auto& itr : streamMap_) {
        std::shared_ptr<StreamBase> stream = itr.second;
        streamInfo = stream->GetStreamInfo();
        if (streamInfo->streamId_ == streamId) {
            stream->DetachBufferQueue();
            return NO_ERROR;
        }
    }

    OHOS::HiviewDFX::HiTrace::End(traceId);
    CAMERA_LOGD("input streamId find not found. [streamId = %d]", streamId);
    return INVALID_ARGUMENT;
}

CamRetCode StreamOperatorImpl::Capture(int captureId, const std::shared_ptr<CaptureInfo>& captureInfo, bool isStreaming)
{
    WatchDog watchDog;
    watchDog.Init(WATCHDOG_TIMEOUT, requestCallback_);
    HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTrace::Begin("streamOperator", HITRACE_FLAG_DEFAULT);

    if (!ValidCaptureInfo(captureId, captureInfo)) {
        CAMERA_LOGE("capture streamIds is empty. [captureId = %d]", captureId);
        return INVALID_ARGUMENT;
    }

    std::shared_ptr<CameraCapture> cameraCapture = nullptr;
    RetCode rc = CreateCapture(captureId, captureInfo, isStreaming, cameraCapture);
    if (rc != RC_OK) {
        CAMERA_LOGE("create capture is failed.");
        return DEVICE_ERROR;
    }

    {
        std::unique_lock<std::mutex> lock(captureMutex_);
        camerCaptureMap_.insert(std::make_pair(captureId, cameraCapture));
    }

    rc = StartThread();
    if (rc != RC_OK) {
        CAMERA_LOGE("preview start failed.");
        return DEVICE_ERROR;
    }
    OHOS::HiviewDFX::HiTrace::End(traceId);

    return NO_ERROR;
}

RetCode StreamOperatorImpl::CreateCapture(int captureId, const std::shared_ptr<CaptureInfo> &captureInfo,
                                          bool isStreaming, std::shared_ptr<CameraCapture> &cameraCapture)
{
    CAMERA_LOGD("enter");
    std::shared_ptr<CameraCapture> capture =
        std::make_shared<CameraCapture>(captureId, captureInfo, isStreaming, streamPipeCore_);
    if (capture == nullptr) {
        CAMERA_LOGE("create camera capture failed. [captureId = %d]", captureId);
        return RC_ERROR;
    }

    for (auto& streamId : captureInfo->streamIds_) {
        CAMERA_LOGI("stream %d create a capture", streamId);
        auto itr = streamMap_.find(streamId);
        if (itr != streamMap_.end()) {
            capture->AddStream(itr->second);
        }
    }

    captureCallbcak_ = std::make_shared<CaptureCallback>();
    ConstructCaptureCallback(captureCallbcak_);
    capture->SetCaptureCallback(captureCallbcak_);

    RetCode rc = capture->Start();
    if (rc != RC_OK) {
        CAMERA_LOGE("capture start failed.");
        return RC_ERROR;
    }

    cameraCapture = capture;
    CAMERA_LOGD("create capture success");

    return RC_OK;
}

void StreamOperatorImpl::ConstructCaptureCallback(std::shared_ptr<CaptureCallback>& callback)
{
    if (callback == nullptr) {
        return;
    }
    callback->OnCaptureStarted = [this](int32_t captureId, const std::vector<int32_t>& streamId) {
        OnCaptureStarted(captureId, streamId);
    };
    callback->OnCaptureEnded = [this](int32_t captureId, const std::vector<std::shared_ptr<CaptureEndedInfo>>& info) {
        OnCaptureEnded(captureId, info);
    };
    callback->OnCaptureError = [this](int32_t captureId, const std::vector<std::shared_ptr<CaptureErrorInfo>>& info) {
        OnCaptureError(captureId, info);
    };
    callback->OnFrameShutter = [this](int32_t captureId, const std::vector<int>& streamIds) {
        OnFrameShutter(captureId, streamIds);
    };
}

void StreamOperatorImpl::OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamId)
{
    if (streamOperatorCallback_ != nullptr) {
        streamOperatorCallback_->OnCaptureStarted(captureId, streamId);
    }
}

void StreamOperatorImpl::OnCaptureEnded(int32_t captureId, const std::vector<std::shared_ptr<CaptureEndedInfo>>& info)
{
    CAMERA_LOGV("enter");
    if (streamOperatorCallback_ != nullptr) {
        streamOperatorCallback_->OnCaptureEnded(captureId, info);
    }

    auto itr = camerCaptureMap_.find(captureId);
    if (itr != camerCaptureMap_.end()) {
        std::unique_lock<std::mutex> lock(captureMutex_);
        camerCaptureMap_.erase(itr);
        CAMERA_LOGI("capture [id = %d] completed.", captureId);
    }
}

void StreamOperatorImpl::OnCaptureError(int32_t captureId, const std::vector<std::shared_ptr<CaptureErrorInfo>>& info)
{
    CAMERA_LOGV("enter");
    if (streamOperatorCallback_ != nullptr) {
        streamOperatorCallback_->OnCaptureError(captureId, info);
    }

    auto itr = camerCaptureMap_.find(captureId);
    if (itr != camerCaptureMap_.end()) {
        std::unique_lock<std::mutex> lock(captureMutex_);
        camerCaptureMap_.erase(itr);
    }
}

void StreamOperatorImpl::OnFrameShutter(int32_t captureId, const std::vector<int>& streamIds)
{
    if (streamOperatorCallback_ != nullptr) {
        streamOperatorCallback_->OnFrameShutter(captureId, streamIds, GetCurrentLocalTimeStamp());
    }
}

bool StreamOperatorImpl::ValidCaptureInfo(int captureId, const std::shared_ptr<CaptureInfo>& captureInfo)
{
    if (captureId < 0 || captureInfo == nullptr || captureInfo->streamIds_.empty()) {
        return false;
    }

    for (auto& streamId : captureInfo->streamIds_) {
        if (streamId < 0) {
            return false;
        }
    }
    return true;
}

RetCode StreamOperatorImpl::StartThread()
{
    RetCode rc = RC_ERROR;
    ThreadState state = GetState();
    if (state == THREAD_STOP) {
        rc = Start();
    } else if (state == THREAD_PAUSED) {
        rc = Resume();
    } else {
        rc = RC_OK;
    }

    if (rc != RC_OK) {
        CAMERA_LOGE("loop thread start failed.");
        return RC_ERROR;
    }

    return rc;
}

CamRetCode StreamOperatorImpl::CancelCapture(int captureId)
{
    CAMERA_LOGI("cancel capture [id = %d] begin.", captureId);
    auto itr = camerCaptureMap_.find(captureId);
    if (itr == camerCaptureMap_.end()) {
        CAMERA_LOGI("cancel capture id not found. [captureId = %d]", captureId);
        return INVALID_ARGUMENT;
    }

    RetCode rc = itr->second->Cancel();
    if (rc != RC_OK) {
        CAMERA_LOGI("capture cancel failed. [captureId = %d]", captureId);
        return DEVICE_ERROR;
    }

    std::unique_lock<std::mutex> lock(captureMutex_);
    camerCaptureMap_.erase(itr);
    CAMERA_LOGI("cancel capture [id = %d] end.", captureId);

    return NO_ERROR;
}

void StreamOperatorImpl::SetRequestCallback(std::function<void()> cb)
{
    requestCallback_ = cb;
}

CamRetCode StreamOperatorImpl::ChangeToOfflineStream(const std::vector<int> &streamIds,
                                                     OHOS::sptr<IStreamOperatorCallback> &callback,
                                                     OHOS::sptr<IOfflineStreamOperator> &offlineOperator)
{
    WatchDog watchDog;
    watchDog.Init(WATCHDOG_TIMEOUT, requestCallback_);
    HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTrace::Begin("streamOperator", HITRACE_FLAG_DEFAULT);

    if (callback == nullptr) {
        return INVALID_ARGUMENT;
    }

    oflstor_ = new(std::nothrow) OfflineStreamOperator(callback);
    if (oflstor_ == nullptr) {
        CAMERA_LOGE("can't create OfflineStreamOperator");
        return DEVICE_ERROR;
    }

    for (auto it : streamIds) {
        auto context = std::make_shared<OfflineStreamContext>();
        if (context == nullptr) {
            CAMERA_LOGE("can not create offline stream context");
            return DEVICE_ERROR;
        }

        std::shared_ptr<StreamBase> onlineStream = nullptr;
        {
            std::unique_lock<std::mutex> streamLock(streamMutex_);
            auto s = streamMap_.find(it);
            if (s == streamMap_.end()) {
                CAMERA_LOGE("can't find stream %{public}d.", it);
                return INVALID_ARGUMENT;
            }
            onlineStream = s->second;
        }
        if (onlineStream == nullptr) {
            CAMERA_LOGE("fatal error, can't get online stream for id %{public}d", it);
            return DEVICE_ERROR;
        }

        RetCode ret = onlineStream->HandleOverStaticContext(context);
        if (ret != RC_OK) {
            CAMERA_LOGE("handle over static context failed.");
            return DEVICE_ERROR;
        }

        ret = onlineStream->SwitchToOffline();
        if (ret != RC_OK) {
            CAMERA_LOGE("stream %{public}d switch to offline failed.", it);
            return DEVICE_ERROR;
        }

        ret = onlineStream->HandleOverDynamicContext(context);
        if (ret != RC_OK) {
            CAMERA_LOGE("handle over dynamic context failed.");
            return DEVICE_ERROR;
        }

        context->pipeline = streamPipeCore_;
        ret = oflstor_->CreateOfflineStream(it, context);
        if (ret != RC_OK) {
            CAMERA_LOGE("create offline stream failed");
            return DEVICE_ERROR;
        }

        CAMERA_LOGI("stream %d switch to offline success.", it);
    }

    offlineOperator = oflstor_;
    OHOS::HiviewDFX::HiTrace::End(traceId);

    return NO_ERROR;
}

void StreamOperatorImpl::Process()
{
    std::unique_lock<std::mutex> lock(captureMutex_);
    for (auto& capture : camerCaptureMap_) {
        if (capture.second != nullptr) {
            capture.second->RequestBuffer();
        }
    }
}
} // end namespace OHOS::Camera
