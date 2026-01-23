/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "dcamerahost_fuzzer.h"
#include "dcamera_test_utils.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dcamera_host.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "v1_1/id_camera_provider_callback.h"

namespace OHOS {
namespace DistributedHardware {

namespace {
    constexpr size_t MAX_ID_LEN = 128;
    constexpr size_t MAX_ABILITY_LEN = 2048;
    constexpr size_t MAX_MOCK_DEVICES_COUNT = 5;
    constexpr const char* CAM_ID_SEPARATOR = "__";
}

enum class FuzzTarget : uint8_t {
    GET_ABILITY,
    ADD_PARAM_CHECK,
    GET_DEV_NUM,
    IS_ID_INVALID,
    GET_ID_BY_DHBASE,
    GET_RESOURCE_COST,
    NOTIFY_DEV_STATE,
    PRE_SWITCH,
    PRELAUNCH_OPMODE,
    ADD_RECIPIENT,
    REMOVE_RECIPIENT,
    MAX_VALUE,
    kMaxValue = MAX_VALUE // NOLINT
};

DHBase FuzzDHBase(FuzzedDataProvider& fdp)
{
    DHBase dhBase;
    dhBase.deviceId_ = fdp.ConsumeRandomLengthString(MAX_ID_LEN);
    dhBase.dhId_ = fdp.ConsumeRandomLengthString(MAX_ID_LEN);
    return dhBase;
}
void FuzzCameraAbility(FuzzedDataProvider& fdp, std::shared_ptr<CameraAbility>& cameraAbility)
{
    int32_t abilityParam1 = fdp.ConsumeIntegral<int32_t>();
    int32_t abilityParam2 = fdp.ConsumeIntegral<int32_t>();
    cameraAbility = std::make_shared<CameraAbility>(abilityParam1, abilityParam2);
}

void FuzzPrelaunchConfig(FuzzedDataProvider& fdp, PrelaunchConfig& config)
{
}

void ClearSingletonState()
{
    DCameraHost::GetInstance()->dCameraDeviceMap_.clear();
}

std::string EmplaceFuzzedDevice(FuzzedDataProvider& fdp, DCameraHost* host)
{
    DHBase dhBase = FuzzDHBase(fdp);
    std::string sink = fdp.ConsumeRandomLengthString(MAX_ABILITY_LEN);
    std::string source = fdp.ConsumeRandomLengthString(MAX_ABILITY_LEN);
    std::string camId = dhBase.deviceId_ + CAM_ID_SEPARATOR + dhBase.dhId_;

    OHOS::sptr<DCameraDevice> dev(new (std::nothrow) DCameraDevice(dhBase, sink, source));
    if (dev == nullptr) {
        return "";
    }
    
    std::string mapKey = fdp.ConsumeRandomLengthString(MAX_ID_LEN);
    host->dCameraDeviceMap_.emplace(mapKey, dev);
    return mapKey;
}

void DCameraGetCameraAbilityFromDevFuzzTest(FuzzedDataProvider& fdp)
{
    ClearSingletonState();
    auto host = DCameraHost::GetInstance();

    std::string cameraIdToGet = fdp.ConsumeRandomLengthString(MAX_ID_LEN);
    if (fdp.ConsumeBool()) {
        DHBase dhBase = FuzzDHBase(fdp);
        sptr<DCameraDevice> dev(new (std::nothrow) DCameraDevice(dhBase, "", ""));
        if (dev != nullptr) {
            host->dCameraDeviceMap_.emplace(cameraIdToGet, dev);
        }
    } else {
        EmplaceFuzzedDevice(fdp, host);
    }
    
    std::shared_ptr<CameraAbility> cameraAbility;
    FuzzCameraAbility(fdp, cameraAbility);
    host->GetCameraAbilityFromDev(cameraIdToGet, cameraAbility);
}

void DCameraAddDeviceParamCheckFuzzTest(FuzzedDataProvider& fdp)
{
    ClearSingletonState();
    DHBase dhBase = FuzzDHBase(fdp);
    std::string sinkAbilityInfo = fdp.ConsumeRandomLengthString(MAX_ABILITY_LEN);
    std::string srcAbilityInfo = fdp.ConsumeRandomLengthString(MAX_ABILITY_LEN);
    sptr<IDCameraProviderCallback> callback = nullptr;
    DCameraHost::GetInstance()->AddDeviceParamCheck(dhBase, sinkAbilityInfo, srcAbilityInfo, callback);
}

void DCameraGetCamDevNumFuzzTest(FuzzedDataProvider& fdp)
{
    ClearSingletonState();
    auto host = DCameraHost::GetInstance();

    size_t devCount = fdp.ConsumeIntegralInRange<size_t>(0, MAX_MOCK_DEVICES_COUNT);
    for (size_t i = 0; i < devCount; ++i) {
        EmplaceFuzzedDevice(fdp, host);
    }

    host->GetCamDevNum();
}

void DCameraIsCameraIdInvalidFuzzTest(FuzzedDataProvider& fdp)
{
    ClearSingletonState();
    auto host = DCameraHost::GetInstance();

    std::string cameraIdToGet = fdp.ConsumeRandomLengthString(MAX_ID_LEN);

    if (fdp.ConsumeBool()) {
        DHBase dhBase = FuzzDHBase(fdp);
        sptr<DCameraDevice> dev(new (std::nothrow) DCameraDevice(dhBase, "", ""));
        if (dev != nullptr) {
            host->dCameraDeviceMap_.emplace(cameraIdToGet, dev);
        }
    } else {
        EmplaceFuzzedDevice(fdp, host);
    }

    host->IsCameraIdInvalid(cameraIdToGet);
}

void DCameraGetCameraIdByDHBaseFuzzTest(FuzzedDataProvider& fdp)
{
    ClearSingletonState();
    auto host = DCameraHost::GetInstance();

    DHBase dhBaseToGet = FuzzDHBase(fdp);

    if (fdp.ConsumeBool()) {
        std::string sink = fdp.ConsumeRandomLengthString(MAX_ABILITY_LEN);
        std::string source = fdp.ConsumeRandomLengthString(MAX_ABILITY_LEN);
        std::string camId = dhBaseToGet.deviceId_ + CAM_ID_SEPARATOR + dhBaseToGet.dhId_;
        sptr<DCameraDevice> dev(new (std::nothrow) DCameraDevice(dhBaseToGet, sink, source));
        if (dev != nullptr) {
            host->dCameraDeviceMap_.emplace(camId, dev);
        }
    } else {
        EmplaceFuzzedDevice(fdp, host);
    }

    host->GetCameraIdByDHBase(dhBaseToGet);
}

void DCameraGetResourceCostFuzzTest(FuzzedDataProvider& fdp)
{
    ClearSingletonState();
    
    std::string cameraId = fdp.ConsumeRandomLengthString(MAX_ID_LEN);
    OHOS::HDI::Camera::V1_3::CameraDeviceResourceCost resourceCost;
    DCameraHost::GetInstance()->GetResourceCost(cameraId, resourceCost);
}

void DCameraNotifyDeviceStateChangeInfoFuzzTest(FuzzedDataProvider& fdp)
{
    ClearSingletonState();
    
    int32_t notifyType = fdp.ConsumeIntegral<int32_t>();
    int32_t deviceState = fdp.ConsumeIntegral<int32_t>();
    DCameraHost::GetInstance()->NotifyDeviceStateChangeInfo(notifyType, deviceState);
}

void DCameraPreCameraSwitchFuzzTest(FuzzedDataProvider& fdp)
{
    ClearSingletonState();
    std::string cameraId = fdp.ConsumeRandomLengthString(MAX_ID_LEN);
    DCameraHost::GetInstance()->PreCameraSwitch(cameraId);
}

void DCameraPrelaunchWithOpModeFuzzTest(FuzzedDataProvider& fdp)
{
    ClearSingletonState();
    
    int32_t operationMode = fdp.ConsumeIntegral<int32_t>();
    PrelaunchConfig config;
    FuzzPrelaunchConfig(fdp, config);
    DCameraHost::GetInstance()->PrelaunchWithOpMode(config, operationMode);
}

void DCameraAddClearRegisterRecipientFuzzTest(FuzzedDataProvider& fdp)
{
    ClearSingletonState();
    
    sptr<IRemoteObject> remote = sptr<MockIRemoteObject>(new (std::nothrow) MockIRemoteObject());
    if (remote == nullptr) {
        return;
    }
    DHBase dhBase = FuzzDHBase(fdp);
    DCameraHost::GetInstance()->AddClearRegisterRecipient(remote, dhBase);
}

void DCameraRemoveClearRegisterRecipientFuzzTest(FuzzedDataProvider& fdp)
{
    ClearSingletonState();
    
    sptr<IRemoteObject> remote = sptr<MockIRemoteObject>(new (std::nothrow) MockIRemoteObject());
    if (remote == nullptr) {
        return;
    }
    DHBase dhBase = FuzzDHBase(fdp);
    
    DCameraHost::GetInstance()->RemoveClearRegisterRecipient(remote, dhBase);
}

} // namespace DistributedHardware
} // namespace OHOS
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }
    using namespace OHOS::DistributedHardware;

    FuzzedDataProvider fdp(data, size);
    auto testCase = fdp.ConsumeEnum<FuzzTarget>();
    switch (testCase) {
        case FuzzTarget::GET_ABILITY:
            DCameraGetCameraAbilityFromDevFuzzTest(fdp);
            break;
        case FuzzTarget::ADD_PARAM_CHECK:
            DCameraAddDeviceParamCheckFuzzTest(fdp);
            break;
        case FuzzTarget::GET_DEV_NUM:
            DCameraGetCamDevNumFuzzTest(fdp);
            break;
        case FuzzTarget::IS_ID_INVALID:
            DCameraIsCameraIdInvalidFuzzTest(fdp);
            break;
        case FuzzTarget::GET_ID_BY_DHBASE:
            DCameraGetCameraIdByDHBaseFuzzTest(fdp);
            break;
        case FuzzTarget::GET_RESOURCE_COST:
            DCameraGetResourceCostFuzzTest(fdp);
            break;
        case FuzzTarget::NOTIFY_DEV_STATE:
            DCameraNotifyDeviceStateChangeInfoFuzzTest(fdp);
            break;
        case FuzzTarget::PRE_SWITCH:
            DCameraPreCameraSwitchFuzzTest(fdp);
            break;
        case FuzzTarget::PRELAUNCH_OPMODE:
            DCameraPrelaunchWithOpModeFuzzTest(fdp);
            break;
        case FuzzTarget::ADD_RECIPIENT:
            DCameraAddClearRegisterRecipientFuzzTest(fdp);
            break;
        case FuzzTarget::REMOVE_RECIPIENT:
            DCameraRemoveClearRegisterRecipientFuzzTest(fdp);
            break;
        case FuzzTarget::MAX_VALUE:
        default:
            break;
    }

    return 0;
}