/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "dstream_operator.h"
#include "dbuffer_manager.h"
#include "dcamera_provider.h"
#include "dcamera.h"
#include "distributed_hardware_log.h"
#include "metadata_utils.h"

namespace OHOS {
namespace DistributedHardware {
DStreamOperator::DStreamOperator(std::shared_ptr<DMetadataProcessor> &dMetadataProcessor)
    : dMetadataProcessor_(dMetadataProcessor)
{
    DHLOGI("DStreamOperator::ctor, instance = %p", this);
}

int32_t DStreamOperator::IsStreamsSupported(OperationMode mode, const std::vector<uint8_t> &modeSetting,
    const std::vector<StreamInfo> &infos, StreamSupportType &type)
{
    (void)mode;
    (void)modeSetting;
    type = DYNAMIC_SUPPORTED;

    for (const auto &it : infos) {
        int id = it.streamId_;
        if (halStreamMap_.find(id) != halStreamMap_.end()) {
            DHLOGE("Repeat streamId.");
            return CamRetCode::INVALID_ARGUMENT;
        }
    }
    return CamRetCode::NO_ERROR;
}

int32_t DStreamOperator::CreateStreams(const std::vector<StreamInfo> &streamInfos)
{
    DHLOGI("DStreamOperator::CreateStreams, input stream info size=%d.", streamInfos.size());
    if (streamInfos.empty()) {
        DHLOGE("DStreamOperator::CreateStreams, input stream info is empty.");
        return CamRetCode::INVALID_ARGUMENT;
    }

    for (const auto &info : streamInfos) {
        DHLOGI("DStreamOperator::CreateStreams, streamInfo: id=%d, intent=%d, width=%d, height=%d, format=%d, " +
            "dataspace=%d, encodeType=%d", info.streamId_, info.intent_, info.width_, info.height_, info.format_,
            info.dataspace_, info.encodeType_);
        if (halStreamMap_.find(info.streamId_) != halStreamMap_.end()) {
            return CamRetCode::INVALID_ARGUMENT;
        }
        if (!info.tunneledMode_) {
            return CamRetCode::METHOD_NOT_SUPPORTED;
        }

        std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
        DCamRetCode ret = dcStream->InitDCameraStream(info);
        if (ret != SUCCESS) {
            DHLOGE("Init distributed camera stream failed.");
            return CamRetCode::INVALID_ARGUMENT;
        }
        halStreamMap_[info.streamId_] = dcStream;

        std::shared_ptr<DCStreamInfo> dcStreamInfo = std::make_shared<DCStreamInfo>();
        ConvertStreamInfo(info, dcStreamInfo);
        dcStreamInfoMap_[info.streamId_] = dcStreamInfo;
        DHLOGI("DStreamOperator::CreateStreams, dcStreamInfo: id=%d, type=%d, width=%d, height=%d, format=%d, " +
            "dataspace=%d, encodeType=%d", dcStreamInfo->streamId_, dcStreamInfo->type_, dcStreamInfo->width_,
            dcStreamInfo->height_, dcStreamInfo->format_, dcStreamInfo->dataspace_, dcStreamInfo->encodeType_);
    }
    DHLOGI("DStreamOperator::Create distributed camera streams success.");
    return CamRetCode::NO_ERROR;
}

int32_t DStreamOperator::ReleaseStreams(const std::vector<int32_t> &streamIds)
{
    DHLOGI("DStreamOperator::ReleaseStreams, input stream id list size=%d.", streamIds.size());
    if (IsCapturing()) {
        DHLOGE("Can not release streams when capture.");
        return CamRetCode::CAMERA_BUSY;
    }

    for (int id : streamIds) {
        auto iter = halStreamMap_.find(id);
        if (iter != halStreamMap_.end()) {
            auto stream = iter->second;
            DCamRetCode ret = stream->ReleaseDCameraBufferQueue();
            if (ret != SUCCESS) {
                DHLOGE("Release distributed camera buffer queue for stream %d failed.", id);
                return MapToExternalRetCode(ret);
            } else {
                DHLOGI("Release distributed camera buffer queue for stream %d success.", id);
            }
            stream = nullptr;
            halStreamMap_.erase(id);
            dcStreamInfoMap_.erase(id);
        } else {
            DHLOGE("Error streamId %d.", id);
            return CamRetCode::INVALID_ARGUMENT;
        }
    }

    OHOS::sptr<DCameraProvider> provider = DCameraProvider::GetInstance();
    if (provider == nullptr) {
        DHLOGE("Distributed camera provider not init.");
        return CamRetCode::DEVICE_ERROR;
    }
    int32_t ret = provider->ReleaseStreams(dhBase_, streamIds);
    if (ret != SUCCESS) {
        DHLOGE("Release distributed camera streams failed.");
        return MapToExternalRetCode(static_cast<DCamRetCode>(ret));
    }

    DHLOGI("DStreamOperator::Release distributed camera streams success.");
    return CamRetCode::NO_ERROR;
}

void DStreamOperator::ExtractStreamInfo(DCStreamInfo &dstStreamInfo,
    const std::shared_ptr<DCStreamInfo> &srcStreamInfo)
{
    dstStreamInfo.streamId_ = srcStreamInfo->streamId_;
    dstStreamInfo.width_ = srcStreamInfo->width_;
    dstStreamInfo.height_ = srcStreamInfo->height_;
    dstStreamInfo.stride_ = srcStreamInfo->stride_;
    dstStreamInfo.format_ = srcStreamInfo->format_;
    dstStreamInfo.dataspace_ = srcStreamInfo->dataspace_;
    dstStreamInfo.encodeType_ = srcStreamInfo->encodeType_;
    dstStreamInfo.type_ = srcStreamInfo->type_;
}

int32_t DStreamOperator::CommitStreams(OperationMode mode, const std::vector<uint8_t> &modeSetting)
{
    DHLOGI("DStreamOperator::CommitStreams, input operation mode=%d.", mode);
    if (IsCapturing()) {
        DHLOGE("Can not commit streams when capture.");
        return CamRetCode::CAMERA_BUSY;
    }

    if (currentOperMode_ != mode) {
        currentOperMode_ = mode;
    }

    std::shared_ptr<OHOS::Camera::CameraMetadata> setting = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(modeSetting, setting);
    if (setting == nullptr || setting.get() == nullptr) {
        DHLOGE("Input stream mode setting is invalid.");
    } else {
        latestStreamSetting_ = setting;
    }

    if (dcStreamInfoMap_.size() == 0) {
        DHLOGE("No stream to commit.");
        return CamRetCode::INVALID_ARGUMENT;
    }
    std::vector<DCStreamInfo> dCameraStreams;
    for (auto streamInfo : dcStreamInfoMap_) {
        DCStreamInfo stream;
        ExtractStreamInfo(stream, streamInfo.second);
        dCameraStreams.push_back(stream);
    }

    OHOS::sptr<DCameraProvider> provider = DCameraProvider::GetInstance();
    if (provider == nullptr) {
        DHLOGE("Distributed camera provider not init.");
        return CamRetCode::DEVICE_ERROR;
    }
    int32_t ret = provider->ConfigureStreams(dhBase_, dCameraStreams);
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("Commit distributed camera streams failed.");
        return MapToExternalRetCode(static_cast<DCamRetCode>(ret));
    }

    for (size_t i = 0; i < dCameraStreams.size(); i++) {
        auto streamInfo = dCameraStreams[i];
        HalStreamCommit(streamInfo);
    }
    DHLOGI("DStreamOperator::Commit distributed camera streams success.");
    return CamRetCode::NO_ERROR;
}

int32_t DStreamOperator::HalStreamCommit(const DCStreamInfo &streamInfo)
{
    for (auto halStream : halStreamMap_) {
        if (streamInfo.streamId_ == halStream.first) {
            int32_t ret = halStream.second->FinishCommitStream();
            if (ret != DCamRetCode::SUCCESS) {
                DHLOGE("Stream %d cannot init.", streamInfo.streamId_);
                return MapToExternalRetCode(static_cast<DCamRetCode>(ret));
            }
        }
    }
    return CamRetCode::NO_ERROR;
}

int32_t DStreamOperator::GetStreamAttributes(std::vector<StreamAttribute> &attributes)
{
    attributes.clear();
    for (const auto &stream : halStreamMap_) {
        StreamAttribute attribute;
        DCamRetCode ret = stream.second->GetDCameraStreamAttribute(attribute);
        if (ret != SUCCESS) {
            DHLOGE("Get distributed camera stream attribute failed.");
            attributes.clear();
            return MapToExternalRetCode(ret);
        }
        attributes.push_back(attribute);
    }
    return CamRetCode::NO_ERROR;
}

int32_t DStreamOperator::AttachBufferQueue(int32_t streamId, const sptr<BufferProducerSequenceable> &bufferProducer)
{
    if (IsCapturing()) {
        DHLOGE("Can not attach buffer queue when capture.");
        return CamRetCode::CAMERA_BUSY;
    }

    auto iter = halStreamMap_.find(streamId);
    if (iter != halStreamMap_.end()) {
        DCamRetCode ret = iter->second->SetDCameraBufferQueue(bufferProducer);
        if (ret != SUCCESS) {
            DHLOGE("Attach distributed camera buffer queue failed.");
        }
        return MapToExternalRetCode(ret);
    } else {
        DHLOGE("Not found stream id %d when attach bubfer queue.", streamId);
        return CamRetCode::INVALID_ARGUMENT;
    }
}

int32_t DStreamOperator::DetachBufferQueue(int32_t streamId)
{
    if (IsCapturing()) {
        DHLOGE("Can not detach buffer queue when capture.");
        return CamRetCode::CAMERA_BUSY;
    }

    auto iter = halStreamMap_.find(streamId);
    if (iter != halStreamMap_.end()) {
        DCamRetCode ret = iter->second->ReleaseDCameraBufferQueue();
        if (ret != SUCCESS) {
            DHLOGE("Detach distributed camera buffer queue failed.");
        }
        return MapToExternalRetCode(ret);
    } else {
        DHLOGE("Not found stream id %d when detach bubfer queue.", streamId);
        return CamRetCode::INVALID_ARGUMENT;
    }
}

void DStreamOperator::ExtractCaptureInfo(std::vector<DCCaptureInfo> &captureInfos)
{
    for (auto &captureInfo : cachedDCaptureInfoList_) {
        DCCaptureInfo capture;
        capture.streamIds_.assign(captureInfo->streamIds_.begin(), captureInfo->streamIds_.end());
        capture.width_ = captureInfo->width_;
        capture.height_ = captureInfo->height_;
        capture.stride_ = captureInfo->stride_;
        capture.format_ = captureInfo->format_;
        capture.dataspace_ = captureInfo->dataspace_;
        capture.isCapture_ = captureInfo->isCapture_;
        capture.encodeType_ = captureInfo->encodeType_;
        capture.type_ = captureInfo->type_;
        capture.captureSettings_.assign(captureInfo->captureSettings_.begin(), captureInfo->captureSettings_.end());
        captureInfos.emplace_back(capture);
    }
}

int32_t DStreamOperator::Capture(int32_t captureId, const CaptureInfo &info, bool isStreaming)
{
    if (captureId < 0 || halCaptureInfoMap_.find(captureId) != halCaptureInfoMap_.end()) {
        DHLOGE("Input captureId %d is exist.", captureId);
        return CamRetCode::INVALID_ARGUMENT;
    }

    for (const auto &id : info.streamIds_) {
        auto iter = halStreamMap_.find(id);
        if (iter == halStreamMap_.end()) {
            DHLOGE("Invalid stream id %d", id);
            return CamRetCode::INVALID_ARGUMENT;
        }
        if (!iter->second->HasBufferQueue()) {
            DHLOGE("Stream %d has not bufferQueue.", iter->first);
            return CamRetCode::INVALID_ARGUMENT;
        }
        enableShutterCbkMap_[id] = info.enableShutterCallback_;
        DHLOGI("DStreamOperator::Capture info: captureId=%d, streamId=%d, isStreaming=%d", captureId, id, isStreaming);
    }

    DCamRetCode ret = NegotiateSuitableCaptureInfo(info, isStreaming);
    if (ret != SUCCESS) {
        DHLOGE("Negotiate suitable capture info failed.");
        return MapToExternalRetCode(ret);
    }

    OHOS::sptr<DCameraProvider> provider = DCameraProvider::GetInstance();
    if (provider == nullptr) {
        DHLOGE("Distributed camera provider not init.");
        return CamRetCode::DEVICE_ERROR;
    }
    std::vector<DCCaptureInfo> captureInfos;
    ExtractCaptureInfo(captureInfos);
    int32_t retProv = provider->StartCapture(dhBase_, captureInfos);
    if (retProv != SUCCESS) {
        DHLOGE("Start distributed camera capture failed.");
        return MapToExternalRetCode(static_cast<DCamRetCode>(retProv));
    }
    std::shared_ptr<CaptureInfo> captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_.assign(info.streamIds_.begin(), info.streamIds_.end());
    captureInfo->captureSetting_.assign(info.captureSetting_.begin(), info.captureSetting_.end());
    captureInfo->enableShutterCallback_ = info.enableShutterCallback_;
    halCaptureInfoMap_[captureId] = captureInfo;

    if (dcStreamOperatorCallback_) {
        dcStreamOperatorCallback_->OnCaptureStarted(captureId, info.streamIds_);
    }
    SetCapturing(true);
    DHLOGI("DStreamOperator::Capture, start distributed camera capture success.");

    return CamRetCode::NO_ERROR;
}

int32_t DStreamOperator::CancelCapture(int32_t captureId)
{
    DHLOGI("DStreamOperator::CancelCapture, cancel distributed camera capture, captureId=%d.", captureId);

    std::unique_lock<std::mutex> lock(requestLock_);
    if (captureId < 0 || halCaptureInfoMap_.find(captureId) == halCaptureInfoMap_.end()) {
        DHLOGE("Input captureId %d is not exist.", captureId);
        return CamRetCode::INVALID_ARGUMENT;
    }

    OHOS::sptr<DCameraProvider> provider = DCameraProvider::GetInstance();
    if (provider == nullptr) {
        DHLOGE("Distributed camera provider not init.");
        return CamRetCode::DEVICE_ERROR;
    }

    std::vector<int> streamIds = halCaptureInfoMap_[captureId]->streamIds_;
    int32_t ret = provider->StopCapture(dhBase_, streamIds);
    if (ret != SUCCESS) {
        DHLOGE("Cancel distributed camera capture failed.");
        return MapToExternalRetCode(static_cast<DCamRetCode>(ret));
    }

    std::vector<CaptureEndedInfo> info;
    for (auto id : halCaptureInfoMap_[captureId]->streamIds_) {
        CaptureEndedInfo tmp;
        tmp.frameCount_ = acceptedBufferNum_[std::make_pair(captureId, id)];
        tmp.streamId_ = id;
        info.push_back(tmp);
        acceptedBufferNum_.erase(std::make_pair(captureId, id));
    }
    if (dcStreamOperatorCallback_) {
        dcStreamOperatorCallback_->OnCaptureEnded(captureId, info);
    }

    halCaptureInfoMap_.erase(captureId);
    if (!HasContinuousCaptureInfo(captureId)) {
        SetCapturing(false);
        cachedDCaptureInfoList_.clear();
    }
    DHLOGI("DStreamOperator::CancelCapture success, captureId=%d.", captureId);
    return CamRetCode::NO_ERROR;
}

bool DStreamOperator::HasContinuousCaptureInfo(int captureId)
{
    bool flag = false;
    for (auto iter : halCaptureInfoMap_) {
        for (auto id : iter.second->streamIds_) {
            auto dcStreamInfo = dcStreamInfoMap_.find(id);
            if (dcStreamInfo == dcStreamInfoMap_.end()) {
                continue;
            }

            DHLOGI("DStreamOperator::HasContinuousCaptureInfo, captureId=%d, streamId=%d, streamType=%d",
                captureId, id, dcStreamInfo->second->type_);
            if (dcStreamInfo->second->type_ == DCStreamType::CONTINUOUS_FRAME) {
                DHLOGI("DStreamOperator::HasContinuousCaptureInfo, captureId=%d, stream %d is continuous stream.",
                    captureId, id);
                flag = true;
                break;
            }
        }
    }
    return flag;
}

int32_t DStreamOperator::ChangeToOfflineStream(const std::vector<int32_t> &streamIds,
    const sptr<IStreamOperatorCallback> &callbackObj, sptr<IOfflineStreamOperator> &offlineOperator)
{
    (void)streamIds;
    (void)callbackObj;
    offlineOperator = nullptr;
    return CamRetCode::METHOD_NOT_SUPPORTED;
}

void DStreamOperator::ExtractCameraAttr(Json::Value &rootValue, std::set<int> &allFormats,
    std::vector<int> &photoFormats)
{
    if (rootValue["CodecType"].isArray()) {
        uint32_t size = rootValue["CodecType"].size();
        for (uint32_t i = 0; i < size; i++) {
            std::string codeType = (rootValue["CodecType"][i]).asString();
            dcSupportedCodecType_.push_back(ConvertDCEncodeType(codeType));
        }
    }

    if (rootValue["OutputFormat"]["Preview"].isArray() && (rootValue["OutputFormat"]["Preview"].size() > 0)) {
        std::vector<int> previewFormats;
        uint32_t size = rootValue["OutputFormat"]["Preview"].size();
        for (uint32_t i = 0; i < size; i++) {
            previewFormats.push_back(rootValue["OutputFormat"]["Preview"][i].asInt());
            allFormats.insert((rootValue["OutputFormat"]["Preview"][i]).asInt());
        }
        dcSupportedFormatMap_[DCSceneType::PREVIEW] = previewFormats;
    }

    if (rootValue["OutputFormat"]["Video"].isArray() && (rootValue["OutputFormat"]["Video"].size() > 0)) {
        std::vector<int> videoFormats;
        uint32_t size = rootValue["OutputFormat"]["Video"].size();
        for (uint32_t i = 0; i < size; i++) {
            videoFormats.push_back(rootValue["OutputFormat"]["Video"][i].asInt());
            allFormats.insert((rootValue["OutputFormat"]["Video"][i]).asInt());
        }
        dcSupportedFormatMap_[DCSceneType::VIDEO] = videoFormats;
    }

    if (rootValue["OutputFormat"]["Photo"].isArray() && (rootValue["OutputFormat"]["Photo"].size() > 0)) {
        uint32_t size = rootValue["OutputFormat"]["Photo"].size();
        for (uint32_t i = 0; i < size; i++) {
            photoFormats.push_back(rootValue["OutputFormat"]["Photo"][i].asInt());
            allFormats.insert((rootValue["OutputFormat"]["Photo"][i]).asInt());
        }
        dcSupportedFormatMap_[DCSceneType::PHOTO] = photoFormats;
    }
}

DCamRetCode DStreamOperator::InitOutputConfigurations(const DHBase &dhBase, const std::string &abilityInfo)
{
    dhBase_ = dhBase;

    JSONCPP_STRING errs;
    Json::CharReaderBuilder readerBuilder;
    Json::Value rootValue;

    std::unique_ptr<Json::CharReader> const jsonReader(readerBuilder.newCharReader());
    if (!jsonReader->parse(abilityInfo.c_str(), abilityInfo.c_str() + abilityInfo.length(), &rootValue, &errs) ||
        !rootValue.isObject()) {
        DHLOGE("Input ablity info is not json object.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    std::set<int> allFormats;
    std::vector<int> photoFormats;
    ExtractCameraAttr(rootValue, allFormats, photoFormats);

    for (const auto &format : allFormats) {
        bool isPhotoFormat = count(photoFormats.begin(), photoFormats.end(), format);
        std::string formatStr = std::to_string(format);
        if (rootValue["Resolution"][formatStr].isArray() && rootValue["Resolution"][formatStr].size() > 0) {
            std::vector<DCResolution> resolutionVec;
            uint32_t size = rootValue["Resolution"][formatStr].size();
            for (uint32_t i = 0; i < size; i++) {
                std::string resoStr = rootValue["Resolution"][formatStr][i].asString();
                std::vector<std::string> reso;
                SplitString(resoStr, reso, STAR_SEPARATOR);
                if (reso.size() != SIZE_FMT_LEN) {
                    continue;
                }
                uint32_t width = static_cast<uint32_t>(std::stoi(reso[0]));
                uint32_t height = static_cast<uint32_t>(std::stoi(reso[1]));
                if (height == 0 || width == 0 ||
                    (isPhotoFormat && (width > MAX_SUPPORT_PHOTO_WIDTH || height > MAX_SUPPORT_PHOTO_HEIGHT)) ||
                    (!isPhotoFormat &&
                    (width > MAX_SUPPORT_PREVIEW_WIDTH || height > MAX_SUPPORT_PREVIEW_HEIGHT))) {
                    continue;
                }
                DCResolution resolution(width, height);
                resolutionVec.push_back(resolution);
            }
            if (!resolutionVec.empty()) {
                std::sort(resolutionVec.begin(), resolutionVec.end());
                dcSupportedResolutionMap_[format] = resolutionVec;
            }
        }
    }

    if (dcSupportedCodecType_.empty() || dcSupportedFormatMap_.empty() || dcSupportedResolutionMap_.empty()) {
        DHLOGE("Input ablity info is invalid.");
        return DEVICE_NOT_INIT;
    }
    return SUCCESS;
}

DCamRetCode DStreamOperator::AcquireBuffer(int streamId, DCameraBuffer &buffer)
{
    std::unique_lock<std::mutex> lock(requestLock_);
    if (!IsCapturing()) {
        DHLOGE("Not in capturing state, can not acquire buffer.");
        return DCamRetCode::CAMERA_OFFLINE;
    }

    auto iter = halStreamMap_.find(streamId);
    if (iter == halStreamMap_.end()) {
        DHLOGE("streamId %d is invalid, can not acquire buffer.", streamId);
        return DCamRetCode::INVALID_ARGUMENT;
    }

    DCamRetCode ret = iter->second->GetDCameraBuffer(buffer);
    if (ret == DCamRetCode::EXCEED_MAX_NUMBER) {
        DHLOGE("Buffer list is full, cannot get new idle buffer.");
    } else if (ret == DCamRetCode::INVALID_ARGUMENT) {
        DHLOGE("Get distributed camera buffer failed, invalid buffer parameter.");
    }
    return ret;
}

DCamRetCode DStreamOperator::ShutterBuffer(int streamId, const DCameraBuffer &buffer)
{
    DHLOGD("DStreamOperator::ShutterBuffer begin shutter buffer for streamId = %d", streamId);

    int32_t captureId = -1;
    for (auto iter = halCaptureInfoMap_.begin(); iter != halCaptureInfoMap_.end(); iter++) {
        std::shared_ptr<CaptureInfo> captureInfo = iter->second;
        std::vector<int> streamIds = captureInfo->streamIds_;
        if (std::find(streamIds.begin(), streamIds.end(), streamId) != streamIds.end()) {
            captureId = iter->first;
            break;
        }
    }
    if (captureId == -1) {
        DHLOGE("ShutterBuffer failed, invalid streamId = %d", streamId);
        return DCamRetCode::INVALID_ARGUMENT;
    }

    auto iter = halStreamMap_.find(streamId);
    if (iter != halStreamMap_.end()) {
        DCamRetCode ret = iter->second->ReturnDCameraBuffer(buffer);
        if (ret != DCamRetCode::SUCCESS) {
            DHLOGE("Flush distributed camera buffer failed.");
            return ret;
        }
        acceptedBufferNum_[std::make_pair(captureId, streamId)]++;

        SnapShotStreamOnCaptureEnded(captureId, streamId);
    }

    uint64_t resultTimestamp = GetCurrentLocalTimeStamp();
    dMetadataProcessor_->UpdateResultMetadata(resultTimestamp);

    auto anIter = enableShutterCbkMap_.find(streamId);
    if (anIter->second) {
        if (dcStreamOperatorCallback_ == nullptr) {
            DHLOGE("DStreamOperator::ShutterBuffer failed, need shutter frame, but stream operator callback is null.");
            return DCamRetCode::FAILED;
        }
        std::vector<int32_t> streamIds;
        streamIds.push_back(anIter->first);
        dcStreamOperatorCallback_->OnFrameShutter(captureId, streamIds, resultTimestamp);
    }
    return DCamRetCode::SUCCESS;
}

DCamRetCode DStreamOperator::SetCallBack(OHOS::sptr<IStreamOperatorCallback> const &callback)
{
    dcStreamOperatorCallback_ = callback;
    return SUCCESS;
}

DCamRetCode DStreamOperator::SetDeviceCallback(
    std::function<void(ErrorType, int)> &errorCbk,
    std::function<void(uint64_t, std::shared_ptr<OHOS::Camera::CameraMetadata>)> &resultCbk)
{
    errorCallback_ = errorCbk;
    dMetadataProcessor_->SetResultCallback(resultCbk);
    return SUCCESS;
}

void DStreamOperator::SnapShotStreamOnCaptureEnded(int32_t captureId, int streamId)
{
    auto dcStreamInfo = dcStreamInfoMap_.find(streamId);
    if (dcStreamInfo == dcStreamInfoMap_.end()) {
        return;
    }
    if (dcStreamInfo->second->type_ != DCStreamType::SNAPSHOT_FRAME) {
        return;
    }
    if (dcStreamOperatorCallback_ == nullptr) {
        return;
    }
    std::vector<CaptureEndedInfo> info;
    CaptureEndedInfo tmp;
    tmp.frameCount_ = acceptedBufferNum_[std::make_pair(captureId, streamId)];
    tmp.streamId_ = streamId;
    info.push_back(tmp);
    dcStreamOperatorCallback_->OnCaptureEnded(captureId, info);
    DHLOGD("snapshot stream successfully reported captureId = %d streamId = %d.", captureId, streamId);
}

void DStreamOperator::Release()
{
    DHLOGI("DStreamOperator::Release, begin release stream operator.");

    std::unique_lock<std::mutex> lock(requestLock_);
    std::vector<int> streamIds;
    for (auto iter : halStreamMap_) {
        streamIds.push_back(iter.first);
    }
    ReleaseStreams(streamIds);
    if (latestStreamSetting_) {
        latestStreamSetting_ = nullptr;
    }
    SetCapturing(false);
    halStreamMap_.clear();
    dcStreamInfoMap_.clear();
    halCaptureInfoMap_.clear();
    enableShutterCbkMap_.clear();
    acceptedBufferNum_.clear();
    cachedDCaptureInfoList_.clear();
    dcStreamOperatorCallback_ = nullptr;
}

std::vector<int> DStreamOperator::GetStreamIds()
{
    DHLOGI("DStreamOperator::GetStreamIds, begin get stream id.");
    std::vector<int> streamIds;
    std::string idString = "";
    for (auto iter : halStreamMap_) {
        streamIds.push_back(iter.first);
        idString += (std::to_string(iter.first) + ", ");
    }
    DHLOGI("DStreamOperator::GetStreamIds, ids=[%s]", idString.c_str());
    return streamIds;
}

bool DStreamOperator::IsCapturing()
{
    std::unique_lock<mutex> lock(isCapturingLock_);
    return isCapturing_;
}

void DStreamOperator::SetCapturing(bool isCapturing)
{
    std::unique_lock<mutex> lock(isCapturingLock_);
    isCapturing_ = isCapturing;
}

void DStreamOperator::ConvertStreamInfo(const StreamInfo &srcInfo, std::shared_ptr<DCStreamInfo> &dstInfo)
{
    dstInfo->streamId_ = srcInfo.streamId_;
    dstInfo->width_ = srcInfo.width_;
    dstInfo->stride_ = srcInfo.width_;
    dstInfo->height_ = srcInfo.height_;
    dstInfo->dataspace_ = srcInfo.dataspace_;
    dstInfo->encodeType_ = (DCEncodeType)srcInfo.encodeType_;

    if ((srcInfo.intent_ == STILL_CAPTURE) || (srcInfo.intent_ == POST_VIEW)) {
        dstInfo->type_ = DCStreamType::SNAPSHOT_FRAME;
        if (dstInfo->encodeType_ == DCEncodeType::ENCODE_TYPE_JPEG) {
            dstInfo->format_ = OHOS_CAMERA_FORMAT_JPEG;
        } else if (dstInfo->encodeType_ == DCEncodeType::ENCODE_TYPE_NULL) {
            dstInfo->format_ = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
        }
    } else {
        // Distributed Camera Do Not Support Encoding at HAL
        dstInfo->encodeType_ = DCEncodeType::ENCODE_TYPE_NULL;
        dstInfo->type_ = DCStreamType::CONTINUOUS_FRAME;
        dstInfo->format_ =
            static_cast<int>(DBufferManager::PixelFormatToDCameraFormat(static_cast<PixelFormat>(srcInfo.format_)));
    }
}

DCamRetCode DStreamOperator::NegotiateSuitableCaptureInfo(const CaptureInfo& srcCaptureInfo, bool isStreaming)
{
    for (auto streamId : srcCaptureInfo.streamIds_) {
        DHLOGI("DStreamOperator::NegotiateSuitableCaptureInfo, streamId=%d, isStreaming=%d", streamId, isStreaming);
    }

    std::shared_ptr<DCCaptureInfo> inputCaptureInfo = nullptr;
    DCamRetCode ret = GetInputCaptureInfo(srcCaptureInfo, isStreaming, inputCaptureInfo);
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("Negotiate input capture info failed.");
        return ret;
    }

    std::shared_ptr<DCCaptureInfo> appendCaptureInfo = nullptr;
    AppendCaptureInfo(appendCaptureInfo, isStreaming, inputCaptureInfo, srcCaptureInfo);
    cachedDCaptureInfoList_.clear();
    cachedDCaptureInfoList_.push_back(inputCaptureInfo);
    if (appendCaptureInfo != nullptr) {
        cachedDCaptureInfoList_.push_back(appendCaptureInfo);
    }

    for (auto info : cachedDCaptureInfoList_) {
        std::string idString = "";
        for (auto id : info->streamIds_) {
            idString += (std::to_string(id) + ", ");
        }
        DHLOGI("cachedDCaptureInfo: ids=[%s], width=%d, height=%d, format=%d, type=%d, isCapture=%d",
            idString.empty() ? idString.c_str() : (idString.substr(0, idString.length() - INGNORE_STR_LEN)).c_str(),
            info->width_, info->height_, info->format_, info->type_, info->isCapture_);
    }
    return SUCCESS;
}

void DStreamOperator::AppendCaptureInfo(std::shared_ptr<DCCaptureInfo> &appendCaptureInfo, bool isStreaming,
    std::shared_ptr<DCCaptureInfo> &inputCaptureInfo, const CaptureInfo& srcCaptureInfo)
{
    if (cachedDCaptureInfoList_.empty()) {
        std::vector<std::shared_ptr<DCStreamInfo>> appendStreamInfo;
        for (auto iter = dcStreamInfoMap_.begin(); iter != dcStreamInfoMap_.end(); iter++) {
            if ((isStreaming && (iter->second->type_ == DCStreamType::SNAPSHOT_FRAME)) ||
                (!isStreaming && (iter->second->type_ == DCStreamType::CONTINUOUS_FRAME))) {
                appendStreamInfo.push_back(iter->second);
            }
        }
        if (!appendStreamInfo.empty()) {
            appendCaptureInfo = BuildSuitableCaptureInfo(srcCaptureInfo, appendStreamInfo);
            appendCaptureInfo->type_ = isStreaming ? DCStreamType::SNAPSHOT_FRAME : DCStreamType::CONTINUOUS_FRAME;
            appendCaptureInfo->isCapture_ = false;
        }
    } else {
        for (auto cacheCapture : cachedDCaptureInfoList_) {
            if ((isStreaming && (cacheCapture->type_ == DCStreamType::SNAPSHOT_FRAME)) ||
                (!isStreaming && (cacheCapture->type_ == DCStreamType::CONTINUOUS_FRAME))) {
                cacheCapture->isCapture_ = false;
                appendCaptureInfo = cacheCapture;
                break;
            }
        }
        inputCaptureInfo->isCapture_ = isStreaming ? false : true;
    }
}

DCamRetCode DStreamOperator::GetInputCaptureInfo(const CaptureInfo& srcCaptureInfo, bool isStreaming,
    std::shared_ptr<DCCaptureInfo>& inputCaptureInfo)
{
    std::vector<std::shared_ptr<DCStreamInfo>> srcStreamInfo;
    for (auto &id : srcCaptureInfo.streamIds_) {
        auto iter = dcStreamInfoMap_.find(id);
        if (iter != dcStreamInfoMap_.end()) {
            srcStreamInfo.push_back(iter->second);
        }
    }

    if (srcStreamInfo.empty()) {
        DHLOGE("Input source stream info vector is empty.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    inputCaptureInfo = BuildSuitableCaptureInfo(srcCaptureInfo, srcStreamInfo);
    inputCaptureInfo->type_ = isStreaming ? DCStreamType::CONTINUOUS_FRAME : DCStreamType::SNAPSHOT_FRAME;
    inputCaptureInfo->isCapture_ = true;
    return DCamRetCode::SUCCESS;
}

std::shared_ptr<DCCaptureInfo> DStreamOperator::BuildSuitableCaptureInfo(const CaptureInfo& srcCaptureInfo,
    std::vector<std::shared_ptr<DCStreamInfo>> &srcStreamInfo)
{
    std::shared_ptr<DCCaptureInfo> captureInfo = std::make_shared<DCCaptureInfo>();

    ChooseSuitableFormat(srcStreamInfo, captureInfo);
    ChooseSuitableResolution(srcStreamInfo, captureInfo);
    ChooseSuitableDataSpace(srcStreamInfo, captureInfo);
    ChooseSuitableEncodeType(srcStreamInfo, captureInfo);

    DCameraSettings dcSetting;
    dcSetting.type_ = DCSettingsType::UPDATE_METADATA;
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSetting = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(srcCaptureInfo.captureSetting_, captureSetting);
    std::string settingStr = OHOS::Camera::MetadataUtils::EncodeToString(captureSetting);
    dcSetting.value_ = Base64Encode(reinterpret_cast<const unsigned char *>(settingStr.c_str()), settingStr.length());

    captureInfo->captureSettings_.push_back(dcSetting);

    return captureInfo;
}

void DStreamOperator::ChooseSuitableFormat(std::vector<std::shared_ptr<DCStreamInfo>> &streamInfo,
    std::shared_ptr<DCCaptureInfo> &captureInfo)
{
    for (auto stream : streamInfo) {
        if (dcSupportedResolutionMap_.count(stream->format_) > 0) {
            captureInfo->format_ = stream->format_;
            return;
        }
    }
    if ((streamInfo.at(0))->type_ == DCStreamType::CONTINUOUS_FRAME) {
        if (dcSupportedFormatMap_.count(DCSceneType::PREVIEW) > 0) {
            captureInfo->format_ = dcSupportedFormatMap_[DCSceneType::PREVIEW].at(0);
        } else if (dcSupportedFormatMap_.count(DCSceneType::VIDEO) > 0) {
            captureInfo->format_ = dcSupportedFormatMap_[DCSceneType::VIDEO].at(0);
        } else {
            captureInfo->format_ = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
        }
    } else {
        if (dcSupportedFormatMap_.count(DCSceneType::PHOTO) > 0) {
            captureInfo->format_ = dcSupportedFormatMap_[DCSceneType::PHOTO].at(0);
        } else {
            if ((streamInfo.at(0))->encodeType_ == DCEncodeType::ENCODE_TYPE_JPEG) {
                captureInfo->format_ = OHOS_CAMERA_FORMAT_JPEG;
            } else {
                captureInfo->format_ = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
            }
        }
    }
}

void DStreamOperator::ChooseSuitableResolution(std::vector<std::shared_ptr<DCStreamInfo>> &streamInfo,
    std::shared_ptr<DCCaptureInfo> &captureInfo)
{
    if (captureInfo == nullptr) {
        DHLOGE("DStreamOperator::ChooseSuitableResolution, captureInfo is null.");
        return;
    }
    std::vector<DCResolution> supportedResolutionList = dcSupportedResolutionMap_[captureInfo->format_];

    for (auto stream : streamInfo) {
        captureInfo->streamIds_.push_back(stream->streamId_);
    }

    DCResolution tempResolution = { 0, 0 };
    for (auto iter : dcStreamInfoMap_) {
        if (iter.second->type_ != (streamInfo.at(0))->type_) {
            continue;
        }
        for (auto resolution : supportedResolutionList) {
            if ((resolution.width_ == iter.second->width_) &&
                (resolution.height_ == iter.second->height_) &&
                (tempResolution < resolution)) {
                tempResolution = resolution;
                break;
            }
        }
    }

    if ((tempResolution.width_ == 0) || (tempResolution.height_ == 0)) {
        captureInfo->width_ = MAX_SUPPORT_PREVIEW_WIDTH;
        captureInfo->height_ = MAX_SUPPORT_PREVIEW_HEIGHT;
    } else {
        captureInfo->width_ = tempResolution.width_;
        captureInfo->height_ = tempResolution.height_;
    }
}

void DStreamOperator::ChooseSuitableDataSpace(std::vector<std::shared_ptr<DCStreamInfo>> &streamInfo,
    std::shared_ptr<DCCaptureInfo> &captureInfo)
{
    captureInfo->dataspace_ = (streamInfo.at(0))->dataspace_;
}

void DStreamOperator::ChooseSuitableEncodeType(std::vector<std::shared_ptr<DCStreamInfo>> &streamInfo,
    std::shared_ptr<DCCaptureInfo> &captureInfo)
{
    if ((streamInfo.at(0))->type_ == DCStreamType::CONTINUOUS_FRAME) {
        if (count(dcSupportedCodecType_.begin(), dcSupportedCodecType_.end(), DCEncodeType::ENCODE_TYPE_H265)) {
            captureInfo->encodeType_ = DCEncodeType::ENCODE_TYPE_H265;
        } else if (count(dcSupportedCodecType_.begin(), dcSupportedCodecType_.end(), DCEncodeType::ENCODE_TYPE_H264)) {
            captureInfo->encodeType_ = DCEncodeType::ENCODE_TYPE_H264;
        } else {
            captureInfo->encodeType_ = DCEncodeType::ENCODE_TYPE_NULL;
        }
    } else {
        if ((streamInfo.at(0))->encodeType_ == DCEncodeType::ENCODE_TYPE_JPEG) {
            captureInfo->encodeType_ = DCEncodeType::ENCODE_TYPE_JPEG;
        } else {
            captureInfo->encodeType_ = DCEncodeType::ENCODE_TYPE_NULL;
        }
    }
}

DCEncodeType DStreamOperator::ConvertDCEncodeType(std::string &srcEncodeType)
{
    if (srcEncodeType == ENCODE_TYPE_STR_H264) {
        return DCEncodeType::ENCODE_TYPE_H264;
    } else if (srcEncodeType == ENCODE_TYPE_STR_H265) {
        return DCEncodeType::ENCODE_TYPE_H265;
    } else if (srcEncodeType == ENCODE_TYPE_STR_JPEG) {
        return DCEncodeType::ENCODE_TYPE_JPEG;
    } else {
        return DCEncodeType::ENCODE_TYPE_NULL;
    }
}
} // namespace DistributedHardware
} // namespace OHOS
