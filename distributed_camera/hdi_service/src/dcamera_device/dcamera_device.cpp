/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "dcamera_device.h"

#include "anonymous_string.h"
#include "constants.h"
#include "dcamera.h"
#include "dcamera_host.h"
#include "dcamera_provider.h"
#include "distributed_hardware_log.h"
#include "metadata_utils.h"

namespace OHOS {
namespace DistributedHardware {
using ErrorCallback = std::function<void (ErrorType, int32_t)>;
using ResultCallback = std::function<void (uint64_t, std::shared_ptr<OHOS::Camera::CameraMetadata>)>;
DCameraDevice::DCameraDevice(const DHBase &dhBase, const std::string &sinkAbilityInfo,
    const std::string &sourceCodecInfo)
    : isOpened_(false),
      dCameraId_(GenerateCameraId(dhBase)),
      dhBase_(dhBase),
      dCameraAbilityInfo_(sinkAbilityInfo),
      sourceCodecInfo_(sourceCodecInfo),
      dCameraDeviceCallback_(nullptr),
      dCameraStreamOperator_(nullptr),
      dMetadataProcessor_(nullptr)
{
    DHLOGI("DCameraDevice construct");
    Init(sinkAbilityInfo);
}

void DCameraDevice::Init(const std::string &sinkAbilityInfo)
{
    if (dMetadataProcessor_ == nullptr) {
        dMetadataProcessor_ = std::make_shared<DMetadataProcessor>();
    }
    dMetadataProcessor_->InitDCameraAbility(sinkAbilityInfo);
}

DCamRetCode DCameraDevice::CreateDStreamOperator()
{
    if (dCameraStreamOperator_ == nullptr) {
        dCameraStreamOperator_ = sptr<DStreamOperator>(new (std::nothrow) DStreamOperator(dMetadataProcessor_));
        if (dCameraStreamOperator_ == nullptr) {
            DHLOGE("Create distributed camera stream operator failed.");
            return DEVICE_NOT_INIT;
        }
    }

    DCamRetCode ret = dCameraStreamOperator_->SetOutputVal(dhBase_, dCameraAbilityInfo_,
        sourceCodecInfo_);
    if (ret != SUCCESS) {
        DHLOGE("set output value failed, ret=%{public}d.", ret);
        return ret;
    }

    ErrorCallback onErrorCallback =
        [this](ErrorType type, int32_t errorMsg) -> void {
            if (dCameraDeviceCallback_) {
                DHLOGI("DCameraDevice onErrorCallback type: %{public}u, errorMsg: %{public}d", type, errorMsg);
                dCameraDeviceCallback_->OnError(type, errorMsg);
            }
        };
    ResultCallback onResultCallback =
        [this](uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata> &result) -> void {
            if (dCameraDeviceCallback_) {
                DHLOGI("DCameraDevice onResultCallback timestamp: %{public}" PRIu64, timestamp);
                std::vector<uint8_t> metadata;
                OHOS::Camera::MetadataUtils::ConvertMetadataToVec(result, metadata);
                dCameraDeviceCallback_->OnResult(timestamp, metadata);
            }
        };
    dCameraStreamOperator_->SetDeviceCallback(onErrorCallback, onResultCallback);

    return ret;
}

int32_t DCameraDevice::GetStreamOperator(const sptr<HDI::Camera::V1_0::IStreamOperatorCallback> &callbackObj,
    sptr<HDI::Camera::V1_0::IStreamOperator> &streamOperator)
{
    if (callbackObj == nullptr) {
        DHLOGE("DCameraDevice::GetStreamOperator, input stream operator callback is null.");
        return CamRetCode::INVALID_ARGUMENT;
    }

    if (dCameraStreamOperator_ == nullptr) {
        DHLOGE("DCameraDevice::GetStreamOperator, input distributed camera stream operator is null.");
        return CamRetCode::DEVICE_ERROR;
    }

    DCamRetCode ret = dCameraStreamOperator_->SetCallBack(callbackObj);
    if (ret != SUCCESS) {
        DHLOGE("Set stream operator callbackObj failed, ret=%{public}d.", ret);
        return MapToExternalRetCode(ret);
    }

    streamOperator = dCameraStreamOperator_;
    return CamRetCode::NO_ERROR;
}

int32_t DCameraDevice::GetStreamOperator_V1_1(const sptr<HDI::Camera::V1_0::IStreamOperatorCallback> &callbackObj,
    sptr<HDI::Camera::V1_1::IStreamOperator> &streamOperator)
{
    if (callbackObj == nullptr) {
        DHLOGE("DCameraDevice::GetStreamOperator_V1_1, input stream operator callback is null.");
        return CamRetCode::INVALID_ARGUMENT;
    }

    if (dCameraStreamOperator_ == nullptr) {
        DHLOGE("DCameraDevice::GetStreamOperator_V1_1, input distributed camera stream operator is null.");
        return CamRetCode::DEVICE_ERROR;
    }

    DCamRetCode ret = dCameraStreamOperator_->SetCallBack(callbackObj);
    if (ret != SUCCESS) {
        DHLOGE("Set stream operator callbackObj failed, ret=%{public}d.", ret);
        return MapToExternalRetCode(ret);
    }

    streamOperator = dCameraStreamOperator_;
    return CamRetCode::NO_ERROR;
}

int32_t DCameraDevice::GetStreamOperator_V1_2(const sptr<HDI::Camera::V1_2::IStreamOperatorCallback> &callbackObj,
    sptr<IStreamOperator> &streamOperator)
{
    if (callbackObj == nullptr) {
        DHLOGE("DCameraDevice::GetStreamOperator_V1_2, input stream operator callback is null.");
        return CamRetCode::INVALID_ARGUMENT;
    }

    if (dCameraStreamOperator_ == nullptr) {
        DHLOGE("DCameraDevice::GetStreamOperator_V1_2, input distributed camera stream operator is null.");
        return CamRetCode::DEVICE_ERROR;
    }

    DCamRetCode ret = dCameraStreamOperator_->SetCallBack(callbackObj);
    if (ret != SUCCESS) {
        DHLOGE("Set stream operator callbackObj failed, ret=%{public}d.", ret);
        return MapToExternalRetCode(ret);
    }

    streamOperator = dCameraStreamOperator_;
    return CamRetCode::NO_ERROR;
}

int32_t DCameraDevice::GetStreamOperator_V1_3(const sptr<HDI::Camera::V1_3::IStreamOperatorCallback> &callbackObj,
    sptr<IStreamOperator> &streamOperator)
{
    if (callbackObj == nullptr) {
        DHLOGE("DCameraDevice::GetStreamOperator_V1_3, input stream operator callback is null.");
        return CamRetCode::INVALID_ARGUMENT;
    }

    if (dCameraStreamOperator_ == nullptr) {
        DHLOGE("DCameraDevice::GetStreamOperator_V1_3, input distributed camera stream operator is null.");
        return CamRetCode::DEVICE_ERROR;
    }

    DCamRetCode ret = dCameraStreamOperator_->SetCallBack(callbackObj);
    if (ret != SUCCESS) {
        DHLOGE("Set stream operator callbackObj failed, ret=%{public}d.", ret);
        return MapToExternalRetCode(ret);
    }

    streamOperator = dCameraStreamOperator_;
    return CamRetCode::NO_ERROR;
}

int32_t DCameraDevice::GetSecureCameraSeq(uint64_t &seqId)
{
    (void)seqId;
    return CamRetCode::NO_ERROR;
}

int32_t DCameraDevice::GetStatus(const std::vector<uint8_t> &metaIn, std::vector<uint8_t> &metaOut)
{
    (void)metaIn;
    (void)metaOut;
    return CamRetCode::NO_ERROR;
}

int32_t DCameraDevice::Reset()
{
    return CamRetCode::NO_ERROR;
}

int32_t DCameraDevice::GetDefaultSettings(std::vector<uint8_t> &settings)
{
    (void)settings;
    return CamRetCode::NO_ERROR;
}

int32_t DCameraDevice::UpdateSettings(const std::vector<uint8_t>& settings)
{
    if (settings.empty() || settings.size() > METADATA_CAPACITY_MAX_SIZE) {
        DHLOGE("DCameraDevice::UpdateSettings, input settings is invalid.");
        return CamRetCode::INVALID_ARGUMENT;
    }

    if (!IsOpened()) {
        DHLOGE("DCameraDevice::UpdateSettings, dcamera device %{public}s already closed.",
            GetAnonyString(dCameraId_).c_str());
        return CamRetCode::CAMERA_CLOSED;
    }

    std::shared_ptr<OHOS::Camera::CameraMetadata> updateSettings = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(settings, updateSettings);
    std::string abilityString = OHOS::Camera::MetadataUtils::EncodeToString(updateSettings);
    std::string encodeString = Base64Encode(reinterpret_cast<const unsigned char *>(abilityString.c_str()),
        abilityString.length());

    DCameraSettings dcSetting;
    dcSetting.type_ = DCSettingsType::UPDATE_METADATA;
    dcSetting.value_ = encodeString;

    std::vector<DCameraSettings> dcSettings;
    dcSettings.push_back(dcSetting);

    OHOS::sptr<DCameraProvider> provider = DCameraProvider::GetInstance();
    if (provider == nullptr) {
        DHLOGE("Distributed camera provider instance is null.");
        return CamRetCode::DEVICE_ERROR;
    }
    int32_t ret = provider->UpdateSettings(dhBase_, dcSettings);

    return MapToExternalRetCode(static_cast<DCamRetCode>(ret));
}

int32_t DCameraDevice::GetSettings(std::vector<uint8_t> &settings)
{
    if (settings.empty()) {
        DHLOGE("Get settings failed.");
        return CamRetCode::DEVICE_ERROR;
    }
    return CamRetCode::NO_ERROR;
}

int32_t DCameraDevice::SetResultMode(ResultCallbackMode mode)
{
    if (dMetadataProcessor_ == nullptr) {
        DHLOGE("Metadata processor not init.");
        return CamRetCode::DEVICE_ERROR;
    }

    DCamRetCode ret = dMetadataProcessor_->SetMetadataResultMode(mode);
    if (ret != SUCCESS) {
        DHLOGE("Set metadata result mode failed, ret=%{public}d.", ret);
    }
    return MapToExternalRetCode(ret);
}

int32_t DCameraDevice::GetEnabledResults(std::vector<int32_t> &results)
{
    if (dMetadataProcessor_ == nullptr) {
        DHLOGE("Metadata processor not init.");
        return CamRetCode::DEVICE_ERROR;
    }

    DCamRetCode ret = dMetadataProcessor_->GetEnabledMetadataResults(results);
    if (ret != SUCCESS) {
        DHLOGE("Get enabled metadata results failed, ret=%{public}d.", ret);
    }
    return MapToExternalRetCode(ret);
}

int32_t DCameraDevice::EnableResult(const std::vector<int32_t> &results)
{
    if (results.empty() || results.size() > METADATA_CAPACITY_MAX_SIZE) {
        DHLOGE("DCameraDevice::EnableResult, input results is invalid.");
        return CamRetCode::DEVICE_ERROR;
    }

    if (dMetadataProcessor_ == nullptr) {
        DHLOGE("Metadata processor not init.");
        return CamRetCode::DEVICE_ERROR;
    }

    DCamRetCode ret = dMetadataProcessor_->EnableMetadataResult(results);
    if (ret != SUCCESS) {
        DHLOGE("Enable metadata result failed, ret=%{public}d.", ret);
        return MapToExternalRetCode(ret);
    }

    stringstream sstream;
    std::reverse_copy(results.begin(), results.end(), ostream_iterator<int32_t>(sstream, ""));
    DCameraSettings dcSetting;
    dcSetting.type_ = DCSettingsType::ENABLE_METADATA;
    dcSetting.value_ = sstream.str();

    OHOS::sptr<DCameraProvider> provider = DCameraProvider::GetInstance();
    if (provider == nullptr) {
        DHLOGE("Enable metadata failed, provider is nullptr.");
        return CamRetCode::DEVICE_ERROR;
    }
    std::vector<DCameraSettings> dcSettings;
    dcSettings.push_back(dcSetting);
    int32_t retProv = provider->UpdateSettings(dhBase_, dcSettings);
    return MapToExternalRetCode(static_cast<DCamRetCode>(retProv));
}

int32_t DCameraDevice::DisableResult(const std::vector<int32_t> &results)
{
    if (results.empty() || results.size() > METADATA_CAPACITY_MAX_SIZE) {
        DHLOGE("DCameraDevice::DisableResult, input results is invalid.");
        return CamRetCode::DEVICE_ERROR;
    }

    if (dMetadataProcessor_ == nullptr) {
        DHLOGE("Metadata processor not init.");
        return CamRetCode::DEVICE_ERROR;
    }

    DCamRetCode ret = dMetadataProcessor_->DisableMetadataResult(results);
    if (ret != SUCCESS) {
        DHLOGE("Disable metadata result failed, ret=%{public}d.", ret);
        return MapToExternalRetCode(ret);
    }

    stringstream sstream;
    std::reverse_copy(results.begin(), results.end(), ostream_iterator<int32_t>(sstream, ""));
    DCameraSettings dcSetting;
    dcSetting.type_ = DCSettingsType::DISABLE_METADATA;
    dcSetting.value_ = sstream.str();

    OHOS::sptr<DCameraProvider> provider = DCameraProvider::GetInstance();
    if (provider == nullptr) {
        DHLOGE("Metadata processor provider is nullptr.");
        return CamRetCode::DEVICE_ERROR;
    }
    std::vector<DCameraSettings> dcSettings;
    dcSettings.push_back(dcSetting);
    int32_t retProv = provider->UpdateSettings(dhBase_, dcSettings);
    return MapToExternalRetCode(static_cast<DCamRetCode>(retProv));
}

int32_t DCameraDevice::Close()
{
    DHLOGI("DCameraDevice::Close distributed camera: %{public}s", GetAnonyString(dCameraId_).c_str());

    OHOS::sptr<DCameraProvider> provider = DCameraProvider::GetInstance();
    if ((provider != nullptr) && (dCameraStreamOperator_ != nullptr)) {
        std::vector<int> streamIds = dCameraStreamOperator_->GetStreamIds();
        provider->StopCapture(dhBase_, streamIds);
    }
    if (dCameraStreamOperator_ != nullptr) {
        dCameraStreamOperator_->Release();
        dCameraStreamOperator_ = nullptr;
    }
    if (provider != nullptr) {
        provider->CloseSession(dhBase_);
    }
    if (dMetadataProcessor_ != nullptr) {
        dMetadataProcessor_->ResetEnableResults();
    }
    dCameraDeviceCallback_ = nullptr;
    isOpenSessFailed_ = false;
    isOpened_ = false;
    return CamRetCode::NO_ERROR;
}

CamRetCode DCameraDevice::OpenDCamera(const OHOS::sptr<ICameraDeviceCallback> &callback)
{
    if (callback == nullptr) {
        DHLOGE("Input callback is null.");
        return CamRetCode::INVALID_ARGUMENT;
    }
    dCameraDeviceCallback_ = callback;

    OHOS::sptr<DCameraProvider> provider = DCameraProvider::GetInstance();
    if (provider == nullptr) {
        DHLOGE("Get distributed camera provider instance is null.");
        return CamRetCode::DEVICE_ERROR;
    }
    int32_t ret = provider->OpenSession(dhBase_);
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("Open distributed camera control session failed, ret = %{public}d.", ret);
        return MapToExternalRetCode(static_cast<DCamRetCode>(ret));
    }

    unique_lock<mutex> lock(openSesslock_);
    auto st = openSessCV_.wait_for(lock, chrono::seconds(WAIT_OPEN_TIMEOUT_SEC));
    if (st == cv_status::timeout) {
        DHLOGE("Wait for distributed camera session open timeout.");
        return CamRetCode::DEVICE_ERROR;
    }
    {
        unique_lock<mutex> openStateLock(isOpenSessFailedlock_);
        if (isOpenSessFailed_) {
            DHLOGE("Open distributed camera session failed.");
            return CamRetCode::DEVICE_ERROR;
        }
    }

    DCamRetCode retDCode = CreateDStreamOperator();
    if (ret != SUCCESS) {
        DHLOGE("Create distributed camera stream operator failed.");
        return MapToExternalRetCode(retDCode);
    }
    isOpened_ = true;

    return MapToExternalRetCode(retDCode);
}

CamRetCode DCameraDevice::TriggerGetFullCaps()
{
    DHLOGI("DCameraDevice TriggerGetFullCaps enter.");
    DCameraHDFEvent dCameraEvent;
    dCameraEvent.type_ = DCameraEventType::DCAMERE_GETFULLCAP;
    if (dCameraProviderCallback_ == nullptr) {
        DHLOGE("The dCameraProviderCallback_ is null.");
        return CamRetCode::INVALID_ARGUMENT;
    }
    dCameraProviderCallback_->NotifyEvent(dhBase_, dCameraEvent);
    {
        std::unique_lock<std::mutex> lck(getFullLock_);
        DHLOGI("Wait get full caps");
        auto status = getFullWaitCond_.wait_for(lck, std::chrono::seconds(GET_FULL_WAIT_SECONDS));
        if (status == std::cv_status::timeout) {
            DHLOGE("Wait get full caps timeout(%{public}ds).", GET_FULL_WAIT_SECONDS);
            return CamRetCode::INVALID_ARGUMENT;
        }
        if (!GetRefreshFlag()) {
            DHLOGI("It is not refreshed.");
            return CamRetCode::INVALID_ARGUMENT;
        }
    }
    DHLOGI("DCameraDevice TriggerGetFullCaps wait end.");
    return CamRetCode::NO_ERROR;
}

CamRetCode DCameraDevice::GetDCameraAbility(std::shared_ptr<CameraAbility> &ability)
{
    DHLOGI("DCameraDevice GetDCameraAbility enter.");
    if (dCameraAbilityInfo_.find(FULL_DATA_KEY) == dCameraAbilityInfo_.npos) {
        auto res = TriggerGetFullCaps();
        if (res != CamRetCode::NO_ERROR) {
            DHLOGE("TriggerGetFullCaps failed");
            return res;
        }
    } else {
        DHLOGI("DCameraDevice has full ability, no need to GetDCameraAbility.");
    }
    if (dMetadataProcessor_ == nullptr) {
        DHLOGE("Metadata processor not init.");
        return CamRetCode::DEVICE_ERROR;
    }
    DCamRetCode ret = dMetadataProcessor_->GetDCameraAbility(ability);
    if (ret != SUCCESS) {
        DHLOGE("Get distributed camera ability failed, ret=%{public}d.", ret);
    }
    return MapToExternalRetCode(ret);
}

DCamRetCode DCameraDevice::AcquireBuffer(int streamId, DCameraBuffer &buffer)
{
    if (dCameraStreamOperator_ == nullptr) {
        DHLOGE("Stream operator not init.");
        return DEVICE_NOT_INIT;
    }

    DCamRetCode ret = dCameraStreamOperator_->AcquireBuffer(streamId, buffer);
    if (ret != SUCCESS) {
        DHLOGE("Acquire buffer failed, ret=%{public}d.", ret);
    }
    return ret;
}

DCamRetCode DCameraDevice::ShutterBuffer(int streamId, const DCameraBuffer &buffer)
{
    if (dCameraStreamOperator_ == nullptr) {
        DHLOGE("Stream operator not init.");
        return DEVICE_NOT_INIT;
    }

    DCamRetCode ret = dCameraStreamOperator_->ShutterBuffer(streamId, buffer);
    if (ret != SUCCESS) {
        DHLOGE("Shutter buffer failed, ret=%{public}d.", ret);
    }
    return ret;
}

DCamRetCode DCameraDevice::OnSettingsResult(const std::shared_ptr<DCameraSettings> &result)
{
    if (result == nullptr) {
        DHLOGE("Input camera settings is null.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    if (dMetadataProcessor_ == nullptr) {
        DHLOGE("Metadata processor not init.");
        return DCamRetCode::DEVICE_NOT_INIT;
    }

    if (result->type_ != DCSettingsType::METADATA_RESULT) {
        DHLOGE("Invalid camera setting type = %{public}d.", result->type_);
        return DCamRetCode::INVALID_ARGUMENT;
    }
    if ((result->value_).empty()) {
        DHLOGE("Camera settings result is empty.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    DCamRetCode ret = dMetadataProcessor_->SaveResultMetadata(result->value_);
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("Save result metadata failed, ret = %{public}d", ret);
    }
    return ret;
}

DCamRetCode DCameraDevice::Notify(const std::shared_ptr<DCameraHDFEvent> &event)
{
    CHECK_AND_RETURN_RET_LOG(event == nullptr, DCamRetCode::INVALID_ARGUMENT, "event is nullptr");
    DHLOGI("DCameraDevice::Notify for event type = %{public}d, result = %{public}d, content = %{public}s.",
        event->type_, event->result_, event->content_.c_str());
    if ((event->type_ != DCameraEventType::DCAMERA_MESSAGE) && (event->type_ != DCameraEventType::DCAMERA_OPERATION)) {
        DHLOGE("Invalid distributed camera event type = %{public}d.", event->type_);
        return DCamRetCode::INVALID_ARGUMENT;
    }
    switch (event->result_) {
        case DCameraEventResult::DCAMERA_EVENT_CHANNEL_CONNECTED: {
            IsOpenSessFailedState(false);
            break;
        }
        case DCameraEventResult::DCAMERA_EVENT_OPEN_CHANNEL_ERROR: {
            IsOpenSessFailedState(true);
            break;
        }
        case DCameraEventResult::DCAMERA_EVENT_CHANNEL_DISCONNECTED: {
            NotifyCameraError(ErrorType::DEVICE_DISCONNECT);
            break;
        }
        case DCameraEventResult::DCAMERA_EVENT_CONFIG_STREAMS_ERROR:
        case DCameraEventResult::DCAMERA_EVENT_START_CAPTURE_ERROR: {
            NotifyStartCaptureError();
            break;
        }
        case DCameraEventResult::DCAMERA_EVENT_DEVICE_ERROR: {
            NotifyCameraError(ErrorType::DRIVER_ERROR);
            break;
        }
        case DCameraEventResult::DCAMERA_EVENT_DEVICE_PREEMPT: {
            NotifyCameraError(ErrorType::DEVICE_PREEMPT);
            break;
        }
        case DCameraEventResult::DCAMERA_EVENT_DEVICE_IN_USE: {
            NotifyCameraError(ErrorType::DCAMERA_ERROR_DEVICE_IN_USE);
            break;
        }
        case DCameraEventResult::DCAMERA_EVENT_NO_PERMISSION: {
            NotifyCameraError(ErrorType::DCAMERA_ERROR_NO_PERMISSION);
            break;
        }
        default:
            break;
    }
    return SUCCESS;
}

void DCameraDevice::IsOpenSessFailedState(bool state)
{
    {
        unique_lock<mutex> lock(isOpenSessFailedlock_);
        isOpenSessFailed_ = state;
    }
    openSessCV_.notify_one();
}

void DCameraDevice::NotifyStartCaptureError()
{
    if (dCameraDeviceCallback_ != nullptr) {
        dCameraDeviceCallback_->OnError(ErrorType::REQUEST_TIMEOUT, 0);
    }
    OHOS::sptr<DCameraProvider> provider = DCameraProvider::GetInstance();
    if ((provider != nullptr) && (dCameraStreamOperator_ != nullptr)) {
        std::vector<int> streamIds = dCameraStreamOperator_->GetStreamIds();
        provider->StopCapture(dhBase_, streamIds);
    }
    if (dCameraStreamOperator_ != nullptr) {
        dCameraStreamOperator_->Release();
    }
}

void DCameraDevice::NotifyCameraError(const ErrorType type)
{
    if (dCameraDeviceCallback_ != nullptr) {
        dCameraDeviceCallback_->OnError(type, 0);
        Close();
    }
}

void DCameraDevice::SetProviderCallback(const OHOS::sptr<IDCameraProviderCallback> &callback)
{
    dCameraProviderCallback_ = callback;
}

OHOS::sptr<IDCameraProviderCallback> DCameraDevice::GetProviderCallback()
{
    return dCameraProviderCallback_;
}

std::string DCameraDevice::GenerateCameraId(const DHBase &dhBase)
{
    return dhBase.deviceId_ + "__" + dhBase.dhId_;
}

std::string DCameraDevice::GetDCameraId()
{
    return dCameraId_;
}

bool DCameraDevice::IsOpened()
{
    return isOpened_;
}

void DCameraDevice::SetDcameraAbility(const std::string& sinkAbilityInfo)
{
    DHLOGI("DCameraDevice SetDcameraAbility enter.");
    if (dCameraAbilityInfo_.find(FULL_DATA_KEY) != sinkAbilityInfo.npos &&
        sinkAbilityInfo.find(META_DATA_KEY) != sinkAbilityInfo.npos) {
        SetRefreshFlag(false);
        DHLOGE("The sinkAbilityInfo is meta data, it is not allowed to refresh full data.");
    } else {
        SetRefreshFlag(true);
        dCameraAbilityInfo_ = sinkAbilityInfo;
        CHECK_AND_RETURN_LOG(dMetadataProcessor_ == nullptr, "dMetadataProcessor_ is nullptr");
        DCamRetCode ret = dMetadataProcessor_->InitDCameraAbility(sinkAbilityInfo);
        if (ret != SUCCESS) {
            DHLOGE("The dMetadataProcessor_ InitDCameraAbility failed, check.");
            SetRefreshFlag(false);
        }
    }
    std::lock_guard<std::mutex> dataLock(getFullLock_);
    getFullWaitCond_.notify_all();
    DHLOGI("DCameraDevice SetDcameraAbility end.");
}

void DCameraDevice::SetRefreshFlag(bool flag)
{
    refreshFlag_.store(flag);
}

bool DCameraDevice::GetRefreshFlag()
{
    return refreshFlag_.load();
}
} // namespace DistributedHardware
} // namespace OHOS
