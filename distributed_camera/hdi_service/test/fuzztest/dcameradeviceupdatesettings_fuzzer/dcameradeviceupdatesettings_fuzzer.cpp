/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>

#include "dcameradeviceupdatesettings_fuzzer.h"

#include "dcamera_device.h"
#include "dcamera_host.h"
#include "v1_1/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
void DcameraDeviceUpdateSettingsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint8_t))) {
        return;
    }
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::vector<uint8_t> results;
    results.push_back(*(reinterpret_cast<const uint8_t*>(data)));

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }
    dcameraDevice->UpdateSettings(results);
}

void DcameraDeviceGetStreamOperatorFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint8_t))) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }
    OHOS::sptr<HDI::Camera::V1_0::IStreamOperatorCallback> callbackObj = nullptr;
    OHOS::sptr<HDI::Camera::V1_0::IStreamOperator> streamOperator = nullptr;

    dcameraDevice->GetStreamOperator(callbackObj, streamOperator);
}

void DcameraDeviceGetStreamOperatorV1_1FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint8_t))) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    OHOS::sptr<HDI::Camera::V1_0::IStreamOperatorCallback> callbackObj = nullptr;
    OHOS::sptr<HDI::Camera::V1_1::IStreamOperator> streamOperator = nullptr;

    dcameraDevice->GetStreamOperator_V1_1(callbackObj, streamOperator);
}

void DcameraDeviceGetStreamOperatorV1_2FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint8_t))) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    OHOS::sptr<HDI::Camera::V1_2::IStreamOperatorCallback> callbackObj = nullptr;
    OHOS::sptr<HDI::Camera::V1_2::IStreamOperator> streamOperator = nullptr;

    dcameraDevice->GetStreamOperator_V1_2(callbackObj, streamOperator);
}

void DcameraDeviceGetStreamOperatorV1_3FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint8_t))) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    OHOS::sptr<HDI::Camera::V1_3::IStreamOperatorCallback> callbackObj = nullptr;
    OHOS::sptr<HDI::Camera::V1_3::IStreamOperator> streamOperator = nullptr;

    dcameraDevice->GetStreamOperator_V1_3(callbackObj, streamOperator);
}

void DCameraGetSecureCameraSeqFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint64_t))) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    uint64_t seqId = *(reinterpret_cast<const uint64_t*>(data));
    dcameraDevice->GetSecureCameraSeq(seqId);
}

void DCameraDeviceGetStatusFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    std::vector<uint8_t> metaIn(data, data + size);
    std::vector<uint8_t> metaOut;

    dcameraDevice->GetStatus(metaIn, metaOut);
}

void DCameraDeviceResetFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }
    dcameraDevice->Reset();
}

void DCameraDeviceGetDefaultSettingsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    std::vector<uint8_t> settings;
    dcameraDevice->GetDefaultSettings(settings);
}

void DCameraDeviceSetResultModeFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(ResultCallbackMode))) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    ResultCallbackMode mode = *(reinterpret_cast<const ResultCallbackMode*>(data));
    dcameraDevice->SetResultMode(mode);
}

void DCameraDeviceGetEnabledResultsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    std::vector<int32_t> results;
    dcameraDevice->GetEnabledResults(results);
}

void DCameraEnableResultFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    std::vector<int32_t> results;
    results.push_back(*(reinterpret_cast<const int32_t*>(data)));

    dcameraDevice->EnableResult(results);
}

void DCameraDisableResultFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    std::vector<int32_t> results;
    results.push_back(*(reinterpret_cast<const int32_t*>(data)));

    dcameraDevice->DisableResult(results);
}

void DCameraAcquireBufferFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string deviceId = "deviceId";
    std::string dhId = "dhId";
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo = "sinkAbilityInfo";
    std::string sourceCodecInfo = "sourceCodecInfo";
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, sourceCodecInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    DCameraBuffer buffer;
    buffer.index_ = fdp.ConsumeIntegral<int32_t>();
    buffer.size_ = fdp.ConsumeIntegral<uint32_t>();

    dcameraDevice->AcquireBuffer(streamId, buffer);
}

void DCameraShutterBufferFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string deviceId = "deviceId";
    std::string dhId = "dhId";
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo = "sinkAbilityInfo";
    std::string sourceCodecInfo = "sourceCodecInfo";
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, sourceCodecInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    DCameraBuffer buffer;
    buffer.index_ = fdp.ConsumeIntegral<int32_t>();
    buffer.size_ = fdp.ConsumeIntegral<uint32_t>();

    dcameraDevice->ShutterBuffer(streamId, buffer);
}

void DCameraOnSettingsResultFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string deviceId = "deviceId";
    std::string dhId = "dhId";
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo = "sinkAbilityInfo";
    std::string sourceCodecInfo = "sourceCodecInfo";
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, sourceCodecInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    DCameraSettings result;
    result.type_ = static_cast<DCSettingsType>(fdp.ConsumeIntegral<int32_t>());
    result.value_ = fdp.ConsumeRemainingBytesAsString();

    dcameraDevice->OnSettingsResult(std::make_shared<DCameraSettings>(result));
}

void DCameraNotifyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string deviceId = "deviceId";
    std::string dhId = "dhId";
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo = "sinkAbilityInfo";
    std::string sourceCodecInfo = "sourceCodecInfo";
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, sourceCodecInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::shared_ptr<DCameraHDFEvent> event = std::make_shared<DCameraHDFEvent>();
    event->type_ = static_cast<DCameraEventType>(fdp.ConsumeIntegral<int32_t>());
    event->result_ = static_cast<DCameraEventResult>(fdp.ConsumeIntegral<int32_t>());
    event->content_ = fdp.ConsumeRemainingBytesAsString();

    dcameraDevice->Notify(event);
}

void DCameraIsOpenSessFailedStateFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string deviceId = "deviceId";
    std::string dhId = "dhId";
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo = "sinkAbilityInfo";
    std::string sourceCodecInfo = "sourceCodecInfo";
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, sourceCodecInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool state = fdp.ConsumeBool();

    dcameraDevice->IsOpenSessFailedState(state);
}

void DCameraNotifyStartCaptureErrorFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string deviceId = "deviceId";
    std::string dhId = "dhId";
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo = "sinkAbilityInfo";
    std::string sourceCodecInfo = "sourceCodecInfo";
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, sourceCodecInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    dcameraDevice->NotifyStartCaptureError();
}

void DCameraNotifyCameraErrorFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string deviceId = "deviceId";
    std::string dhId = "dhId";
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo = "sinkAbilityInfo";
    std::string sourceCodecInfo = "sourceCodecInfo";
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, sourceCodecInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    ErrorType errorType = static_cast<ErrorType>(fdp.ConsumeIntegral<int32_t>());

    dcameraDevice->NotifyCameraError(errorType);
}

void DCameraSetDcameraAbilityFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string deviceId = "deviceId";
    std::string dhId = "dhId";
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo = "sinkAbilityInfo";
    std::string sourceCodecInfo = "sourceCodecInfo";
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, sourceCodecInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string randomSinkAbilityInfo = fdp.ConsumeRemainingBytesAsString();

    dcameraDevice->SetDcameraAbility(randomSinkAbilityInfo);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DcameraDeviceUpdateSettingsFuzzTest(data, size);
    OHOS::DistributedHardware::DcameraDeviceGetStreamOperatorFuzzTest(data, size);
    OHOS::DistributedHardware::DcameraDeviceGetStreamOperatorV1_1FuzzTest(data, size);
    OHOS::DistributedHardware::DcameraDeviceGetStreamOperatorV1_2FuzzTest(data, size);
    OHOS::DistributedHardware::DcameraDeviceGetStreamOperatorV1_3FuzzTest(data, size);
    OHOS::DistributedHardware::DCameraGetSecureCameraSeqFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraDeviceGetStatusFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraDeviceResetFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraDeviceGetDefaultSettingsFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraDeviceSetResultModeFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraDeviceGetEnabledResultsFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraEnableResultFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraDisableResultFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraAcquireBufferFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraShutterBufferFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraOnSettingsResultFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraNotifyFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraIsOpenSessFailedStateFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraNotifyStartCaptureErrorFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraNotifyCameraErrorFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraSetDcameraAbilityFuzzTest(data, size);
    return 0;
}

