/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "dcamera_provider.h"
#include "anonymous_string.h"
#include "constants.h"
#include "dcamera_device.h"
#include "dcamera_host.h"
#include "distributed_hardware_log.h"
#include "dcamera.h"

namespace OHOS {
namespace DistributedHardware {
OHOS::sptr<DCameraProvider> DCameraProvider::instance_ = nullptr;
DCameraProvider::AutoRelease DCameraProvider::autoRelease_;

extern "C" IDCameraProvider *HdiImplGetInstance(void)
{
    return static_cast<IDCameraProvider *>(DCameraProvider::GetInstance().GetRefPtr());
}

OHOS::sptr<DCameraProvider> DCameraProvider::GetInstance()
{
    if (instance_ == nullptr) {
        instance_ = sptr<DCameraProvider>(new DCameraProvider());
        if (instance_ == nullptr) {
            DHLOGE("Get distributed camera provider instance failed.");
            return nullptr;
        }
    }
    return instance_;
}

bool DCameraProvider::GetAbilityInfo(const std::string& abilityInfo, std::string& sinkAbilityInfo,
    std::string& sourceCodecInfo)
{
    cJSON *rootValue = cJSON_Parse(abilityInfo.c_str());
    CHECK_NULL_RETURN_LOG(rootValue, false, "The abilityInfo is null.");
    CHECK_OBJECT_FREE_RETURN(rootValue, false, "The abilityInfo is not object.");

    cJSON *sinkRootValue = cJSON_GetObjectItemCaseSensitive(rootValue, "SinkAbility");
    if (sinkRootValue == nullptr || !cJSON_IsObject(sinkRootValue)) {
        cJSON_Delete(rootValue);
        DHLOGE("Get sink ability error.");
        return false;
    }

    cJSON *srcRootValue = cJSON_GetObjectItemCaseSensitive(rootValue, "SourceCodec");
    if (srcRootValue == nullptr || !cJSON_IsObject(srcRootValue)) {
        cJSON_Delete(rootValue);
        DHLOGE("Get source ability error.");
        return false;
    }

    char *jsonSink = cJSON_Print(sinkRootValue);
    if (jsonSink == nullptr) {
        cJSON_Delete(rootValue);
        return false;
    }
    sinkAbilityInfo = std::string(jsonSink);

    char *jsonSource = cJSON_Print(srcRootValue);
    if (jsonSource == nullptr) {
        cJSON_Delete(rootValue);
        cJSON_free(jsonSink);
        return false;
    }
    sourceCodecInfo = std::string(jsonSource);
    cJSON_Delete(rootValue);
    cJSON_free(jsonSink);
    cJSON_free(jsonSource);
    return true;
}

int32_t DCameraProvider::EnableDCameraDevice(const DHBase& dhBase, const std::string& abilityInfo,
    const sptr<IDCameraProviderCallback>& callbackObj)
{
    if (IsDhBaseInfoInvalid(dhBase)) {
        DHLOGE("DCameraProvider::EnableDCameraDevice, devId or dhId is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    DHLOGI("DCameraProvider::EnableDCameraDevice for {devId: %{public}s, dhId: %{public}s, sinkAbilityInfo length: "
        "%{public}zu}.", GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str(),
        abilityInfo.length());
    if (abilityInfo.empty() || abilityInfo.length() > ABILITYINFO_MAX_LENGTH) {
        DHLOGE("DCameraProvider::EnableDCameraDevice, dcamera ability is empty or over limit.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    if (callbackObj == nullptr) {
        DHLOGE("DCameraProvider::EnableDCameraDevice, dcamera provider callback is null.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    OHOS::sptr<DCameraHost> dCameraHost = DCameraHost::GetInstance();
    if (dCameraHost == nullptr) {
        DHLOGE("DCameraProvider::EnableDCameraDevice, dcamera host is null.");
        return DCamRetCode::DEVICE_NOT_INIT;
    }
    std::string sourceCodecInfo;
    std::string sinkAbilityInfo;
    if (!GetAbilityInfo(abilityInfo, sinkAbilityInfo, sourceCodecInfo)) {
        return DCamRetCode::INVALID_ARGUMENT;
    }

    DCamRetCode ret = dCameraHost->AddDCameraDevice(dhBase, sinkAbilityInfo, sourceCodecInfo, callbackObj);
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("DCameraProvider::EnableDCameraDevice failed, ret = %{public}d.", ret);
    }
    return ret;
}

int32_t DCameraProvider::DisableDCameraDevice(const DHBase& dhBase)
{
    if (IsDhBaseInfoInvalid(dhBase)) {
        DHLOGE("DCameraProvider::DisableDCameraDevice, devId or dhId is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    DHLOGI("DCameraProvider::DisableDCameraDevice for {devId: %{public}s, dhId: %{public}s}.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    OHOS::sptr<DCameraHost> dCameraHost = DCameraHost::GetInstance();
    if (dCameraHost == nullptr) {
        DHLOGE("DCameraProvider::DisableDCameraDevice, dcamera host is null.");
        return DCamRetCode::DEVICE_NOT_INIT;
    }
    DCamRetCode ret = dCameraHost->RemoveDCameraDevice(dhBase);
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("DCameraProvider::DisableDCameraDevice failed, ret = %{public}d.", ret);
        return ret;
    }

    return DCamRetCode::SUCCESS;
}

int32_t DCameraProvider::AcquireBuffer(const DHBase& dhBase, int32_t streamId, DCameraBuffer& buffer)
{
    if (IsDhBaseInfoInvalid(dhBase)) {
        DHLOGE("DCameraProvider::AcquireBuffer, devId or dhId is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    if (streamId < 0) {
        DHLOGE("DCameraProvider::AcquireBuffer, input streamId is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    DHLOGD("DCameraProvider::AcquireBuffer for {devId: %{public}s, dhId: %{public}s}, streamId: %{public}d.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str(), streamId);

    OHOS::sptr<DCameraDevice> device = GetDCameraDevice(dhBase);
    if (device == nullptr) {
        DHLOGE("DCameraProvider::AcquireBuffer failed, dcamera device not found.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    DCamRetCode ret = device->AcquireBuffer(streamId, buffer);
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("DCameraProvider::AcquireBuffer failed, ret = %{public}d.", ret);
        return ret;
    }
    return DCamRetCode::SUCCESS;
}

int32_t DCameraProvider::ShutterBuffer(const DHBase& dhBase, int32_t streamId, const DCameraBuffer& buffer)
{
    if (IsDhBaseInfoInvalid(dhBase)) {
        DHLOGE("DCameraProvider::ShutterBuffer, devId or dhId is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    if (buffer.index_ < 0 || buffer.size_ < 0) {
        DHLOGE("DCameraProvider::ShutterBuffer, input dcamera buffer is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    if (streamId < 0) {
        DHLOGE("DCameraProvider::ShutterBuffer, input streamId is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    DHLOGD("DCameraProvider::ShutterBuffer for {devId: %{public}s, dhId: %{public}s}, streamId = %{public}d, "
        "buffer index = %{public}d.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str(), streamId, buffer.index_);
    OHOS::sptr<DCameraDevice> device = GetDCameraDevice(dhBase);
    if (device == nullptr) {
        DHLOGE("DCameraProvider::ShutterBuffer failed, dcamera device not found.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    return device->ShutterBuffer(streamId, buffer);
}

int32_t DCameraProvider::OnSettingsResult(const DHBase& dhBase, const DCameraSettings& result)
{
    if (IsDhBaseInfoInvalid(dhBase)) {
        DHLOGE("DCameraProvider::OnSettingsResult, devId or dhId is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    if (IsDCameraSettingsInvalid(result)) {
        DHLOGE("DCameraProvider::OnSettingsResult, input dcamera settings is valid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    DHLOGI("DCameraProvider::OnSettingsResult for {devId: %{public}s, dhId: %{public}s}.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    OHOS::sptr<DCameraDevice> device = GetDCameraDevice(dhBase);
    if (device == nullptr) {
        DHLOGE("DCameraProvider::OnSettingsResult failed, dcamera device not found.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    std::shared_ptr<DCameraSettings> dCameraResult = std::make_shared<DCameraSettings>();
    dCameraResult->type_ = result.type_;
    dCameraResult->value_ = result.value_;
    return device->OnSettingsResult(dCameraResult);
}

int32_t DCameraProvider::Notify(const DHBase& dhBase, const DCameraHDFEvent& event)
{
    if (IsDhBaseInfoInvalid(dhBase)) {
        DHLOGE("DCameraProvider::Notify, devId or dhId is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    if (IsDCameraHDFEventInvalid(event)) {
        DHLOGE("DCameraProvider::Notify, input dcamera hdf event is null.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    DHLOGI("DCameraProvider::Notify for {devId: %{public}s, dhId: %{public}s}.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    OHOS::sptr<DCameraDevice> device = GetDCameraDevice(dhBase);
    if (device == nullptr) {
        DHLOGE("DCameraProvider::Notify failed, dcamera device not found.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    std::shared_ptr<DCameraHDFEvent> dCameraEvent = std::make_shared<DCameraHDFEvent>();
    dCameraEvent->type_ = event.type_;
    dCameraEvent->result_ = event.result_;
    dCameraEvent->content_ = event.content_;
    return device->Notify(dCameraEvent);
}

int32_t DCameraProvider::RegisterCameraHdfListener(const std::string &serviceName,
    const sptr<IDCameraHdfCallback> &callbackObj)
{
    DHLOGI("Register camera HDF listener, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    if (callbackObj == nullptr) {
        DHLOGE("dcamera hdf callback is null.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    OHOS::sptr<DCameraHost> dCameraHost = DCameraHost::GetInstance();
    if (dCameraHost == nullptr) {
        DHLOGE("dcamera host is null.");
        return DCamRetCode::DEVICE_NOT_INIT;
    }
    auto ret = dCameraHost->RegisterCameraHdfListener(serviceName, callbackObj);
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("call dcamera host RegisterCameraHdfListener failed, ret = %{public}d.", ret);
        return ret;
    }
    DHLOGI("Register camera HDF listener success.");
    return DCamRetCode::SUCCESS;
}

int32_t DCameraProvider::UnRegisterCameraHdfListener(const std::string &serviceName)
{
    DHLOGI("Unregister camera HDF listener, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    OHOS::sptr<DCameraHost> dCameraHost = DCameraHost::GetInstance();
    if (dCameraHost == nullptr) {
        DHLOGE("dcamera host is null.");
        return DCamRetCode::DEVICE_NOT_INIT;
    }
    auto ret = dCameraHost->UnRegisterCameraHdfListener(serviceName);
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("call dcamera host UnRegisterCameraHdfListener failed, ret = %{public}d.", ret);
        return ret;
    }
    DHLOGI("Unregister camera HDF listener success.");
    return DCamRetCode::SUCCESS;
}

int32_t DCameraProvider::OpenSession(const DHBase &dhBase)
{
    DHLOGI("DCameraProvider::OpenSession for {devId: %{public}s, dhId: %{public}s}.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    sptr<IDCameraProviderCallback> callback = GetCallbackBydhBase(dhBase);
    if (callback == nullptr) {
        DHLOGE("DCameraProvider::OpenSession, dcamera provider callback not found.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    return callback->OpenSession(dhBase);
}

int32_t DCameraProvider::CloseSession(const DHBase &dhBase)
{
    DHLOGI("DCameraProvider::CloseSession for {devId: %{public}s, dhId: %{public}s}.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    sptr<IDCameraProviderCallback> callback = GetCallbackBydhBase(dhBase);
    if (callback == nullptr) {
        DHLOGE("DCameraProvider::CloseSession, dcamera provider callback not found.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    return callback->CloseSession(dhBase);
}

int32_t DCameraProvider::ConfigureStreams(const DHBase &dhBase, const std::vector<DCStreamInfo> &streamInfos)
{
    DHLOGI("DCameraProvider::ConfigureStreams for {devId: %{public}s, dhId: %{public}s}.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    sptr<IDCameraProviderCallback> callback = GetCallbackBydhBase(dhBase);
    if (callback == nullptr) {
        DHLOGE("DCameraProvider::ConfigStreams, dcamera provider callback not found.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    for (auto info = streamInfos.begin(); info != streamInfos.end(); info++) {
        DHLOGI("ConfigureStreams: id=%{public}d, width=%{public}d, height=%{public}d, format=%{public}d, "
               "type=%{public}d, mode=%{public}d.", info->streamId_, info->width_, info->height_, info->format_,
               info->type_, info->mode_);
    }
    return callback->ConfigureStreams(dhBase, streamInfos);
}

int32_t DCameraProvider::ReleaseStreams(const DHBase &dhBase, const std::vector<int> &streamIds)
{
    DHLOGI("DCameraProvider::ReleaseStreams for {devId: %{public}s, dhId: %{public}s}.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    sptr<IDCameraProviderCallback> callback = GetCallbackBydhBase(dhBase);
    if (callback == nullptr) {
        DHLOGE("DCameraProvider::ReleaseStreams, dcamera provider callback not found.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    std::string idString = "";
    for (int id : streamIds) {
        idString += (std::to_string(id) + ", ");
    }
    DHLOGI("ReleaseStreams: ids=[%{public}s].", idString.c_str());
    return callback->ReleaseStreams(dhBase, streamIds);
}

int32_t DCameraProvider::StartCapture(const DHBase &dhBase, const std::vector<DCCaptureInfo> &captureInfos)
{
    DHLOGI("DCameraProvider::StartCapture for {devId: %{public}s, dhId: %{public}s}.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    sptr<IDCameraProviderCallback> callback = GetCallbackBydhBase(dhBase);
    if (callback == nullptr) {
        DHLOGE("DCameraProvider::StartCapture, dcamera provider callback not found.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    for (auto info = captureInfos.begin(); info != captureInfos.end(); info++) {
        std::string idString = "";
        for (int id : info->streamIds_) {
            idString += (std::to_string(id) + ", ");
        }
        DHLOGI("DCameraProvider::StartCapture: ids=[%{public}s], width=%{public}d, height=%{public}d, format="
            "%{public}d, type=%{public}d, isCapture=%{public}d.",
            (idString.empty() ? idString.c_str() : (idString.substr(0, idString.length() - INGNORE_STR_LEN)).c_str()),
            info->width_, info->height_, info->format_, info->type_, info->isCapture_);
    }
    return callback->StartCapture(dhBase, captureInfos);
}

int32_t DCameraProvider::StopCapture(const DHBase &dhBase, const std::vector<int> &streamIds)
{
    DHLOGI("DCameraProvider::StopCapture for {devId: %{public}s, dhId: %{public}s}.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    sptr<IDCameraProviderCallback> callback = GetCallbackBydhBase(dhBase);
    if (callback == nullptr) {
        DHLOGE("DCameraProvider::StopCapture, dcamera provider callback not found.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    std::string idString = "";
    for (int id : streamIds) {
        idString += (std::to_string(id) + ", ");
    }
    DHLOGI("DCameraProvider::StopCapture: ids=[%{public}s].",
        idString.empty() ? idString.c_str() : (idString.substr(0, idString.length() - INGNORE_STR_LEN)).c_str());
    return callback->StopCapture(dhBase, streamIds);
}

int32_t DCameraProvider::UpdateSettings(const DHBase &dhBase, const std::vector<DCameraSettings> &settings)
{
    DHLOGI("DCameraProvider::UpdateSettings for {devId: %{public}s, dhId: %{public}s}.",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    sptr<IDCameraProviderCallback> callback = GetCallbackBydhBase(dhBase);
    if (callback == nullptr) {
        DHLOGE("DCameraProvider::UpdateSettings, dcamera provider callback not found.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    return callback->UpdateSettings(dhBase, settings);
}

bool DCameraProvider::IsDCameraSettingsInvalid(const DCameraSettings& result)
{
    return result.value_.empty() || result.value_.length() > SETTING_VALUE_MAX_LENGTH;
}

bool DCameraProvider::IsDCameraHDFEventInvalid(const DCameraHDFEvent& event)
{
    return event.content_.length() > HDF_EVENT_CONTENT_MAX_LENGTH;
}

sptr<IDCameraProviderCallback> DCameraProvider::GetCallbackBydhBase(const DHBase &dhBase)
{
    OHOS::sptr<DCameraDevice> device = GetDCameraDevice(dhBase);
    if (device == nullptr) {
        DHLOGE("DCameraProvider::GetCallbackBydhBase failed, dcamera device not found.");
        return nullptr;
    }
    return device->GetProviderCallback();
}

OHOS::sptr<DCameraDevice> DCameraProvider::GetDCameraDevice(const DHBase &dhBase)
{
    OHOS::sptr<DCameraHost> dCameraHost = DCameraHost::GetInstance();
    if (dCameraHost == nullptr) {
        DHLOGE("DCameraProvider::GetDCameraDevice, dcamera host is null.");
        return nullptr;
    }
    return dCameraHost->GetDCameraDeviceByDHBase(dhBase);
}
} // namespace DistributedHardware
} // namespace OHOS
