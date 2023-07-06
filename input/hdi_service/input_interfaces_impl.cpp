/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "input_interfaces_impl.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <iproxy_broker.h>
#include <mutex>
#include <securec.h>
#include "input_manager.h"
#include "input_type.h"

#define HDF_LOG_TAG InputInterfacesImpl

namespace OHOS {
namespace HDI {
namespace Input {
namespace V1_0 {
namespace {
    constexpr uint32_t MAX_DEVICES = 32;
    InputEventCb eventCb;
    InputHostCb hostCb;
    sptr<IInputCallback> g_inputEventCallback = nullptr;
    sptr<IInputCallback> g_hotplugEventCallback = nullptr;
    std::mutex g_mutex;
}

extern "C" IInputInterfaces *InputInterfacesImplGetInstance(void)
{
    using OHOS::HDI::Input::V1_0::InputInterfacesImpl;
    InputInterfacesImpl *service = new (std::nothrow) InputInterfacesImpl();
    if (service == nullptr) {
        return nullptr;
    }

    service->Init();
    return service;
}

static struct DeviceInfo TransferDevInfo(InputDeviceInfo &halDevInfo)
{
    DeviceInfo hdiDevInfo;
    hdiDevInfo.devIndex = halDevInfo.devIndex;
    hdiDevInfo.devType = halDevInfo.devType;
    hdiDevInfo.chipInfo = halDevInfo.chipInfo;
    hdiDevInfo.vendorName = halDevInfo.vendorName;
    hdiDevInfo.chipName = halDevInfo.chipName;
    hdiDevInfo.attrSet.devName = halDevInfo.attrSet.devName;
    hdiDevInfo.attrSet.id.busType = halDevInfo.attrSet.id.busType;
    hdiDevInfo.attrSet.id.vendor = halDevInfo.attrSet.id.vendor;
    hdiDevInfo.attrSet.id.product = halDevInfo.attrSet.id.product;
    hdiDevInfo.attrSet.id.version = halDevInfo.attrSet.id.version;
    hdiDevInfo.attrSet.axisInfo.resize(ABS_CNT);
    for (int32_t i = 0; i < ABS_CNT; i++) {
        hdiDevInfo.attrSet.axisInfo[i].axis = halDevInfo.attrSet.axisInfo[i].axis;
        hdiDevInfo.attrSet.axisInfo[i].min = halDevInfo.attrSet.axisInfo[i].min;
        hdiDevInfo.attrSet.axisInfo[i].max = halDevInfo.attrSet.axisInfo[i].max;
        hdiDevInfo.attrSet.axisInfo[i].fuzz = halDevInfo.attrSet.axisInfo[i].fuzz;
        hdiDevInfo.attrSet.axisInfo[i].flat = halDevInfo.attrSet.axisInfo[i].flat;
        hdiDevInfo.attrSet.axisInfo[i].range = halDevInfo.attrSet.axisInfo[i].range;
    }
    hdiDevInfo.abilitySet.devProp.assign(halDevInfo.abilitySet.devProp,
        halDevInfo.abilitySet.devProp + BITS_TO_UINT64(INPUT_PROP_CNT));
    hdiDevInfo.abilitySet.eventType.assign(halDevInfo.abilitySet.eventType,
        halDevInfo.abilitySet.eventType + BITS_TO_UINT64(EV_CNT));
    hdiDevInfo.abilitySet.absCode.assign(halDevInfo.abilitySet.absCode,
        halDevInfo.abilitySet.absCode + BITS_TO_UINT64(ABS_CNT));
    hdiDevInfo.abilitySet.relCode.assign(halDevInfo.abilitySet.relCode,
        halDevInfo.abilitySet.relCode + BITS_TO_UINT64(REL_CNT));
    hdiDevInfo.abilitySet.keyCode.assign(halDevInfo.abilitySet.keyCode,
        halDevInfo.abilitySet.keyCode + BITS_TO_UINT64(KEY_CNT));
    hdiDevInfo.abilitySet.ledCode.assign(halDevInfo.abilitySet.ledCode,
        halDevInfo.abilitySet.ledCode + BITS_TO_UINT64(LED_CNT));
    hdiDevInfo.abilitySet.miscCode.assign(halDevInfo.abilitySet.miscCode,
        halDevInfo.abilitySet.miscCode + BITS_TO_UINT64(MSC_CNT));
    hdiDevInfo.abilitySet.soundCode.assign(halDevInfo.abilitySet.soundCode,
        halDevInfo.abilitySet.soundCode + BITS_TO_UINT64(SND_CNT));
    hdiDevInfo.abilitySet.forceCode.assign(halDevInfo.abilitySet.forceCode,
        halDevInfo.abilitySet.forceCode + BITS_TO_UINT64(HDF_FF_CNT));
    hdiDevInfo.abilitySet.switchCode.assign(halDevInfo.abilitySet.switchCode,
        halDevInfo.abilitySet.switchCode + BITS_TO_UINT64(SW_CNT));
    hdiDevInfo.abilitySet.keyType.assign(halDevInfo.abilitySet.keyType,
        halDevInfo.abilitySet.keyType + BITS_TO_UINT64(KEY_CNT));
    hdiDevInfo.abilitySet.ledType.assign(halDevInfo.abilitySet.ledType,
        halDevInfo.abilitySet.ledType + BITS_TO_UINT64(LED_CNT));
    hdiDevInfo.abilitySet.soundType.assign(halDevInfo.abilitySet.soundType,
        halDevInfo.abilitySet.soundType + BITS_TO_UINT64(SND_CNT));
    hdiDevInfo.abilitySet.switchType.assign(halDevInfo.abilitySet.switchType,
        halDevInfo.abilitySet.switchType + BITS_TO_UINT64(SW_CNT));
    return hdiDevInfo;
}

void InputEventDataCallback(const InputEventPackage **pkgs, uint32_t count, uint32_t devIndex)
{
    if (pkgs == nullptr || *pkgs == nullptr) {
        HDF_LOGE("%{public}s failed, pkgs is nullptr", __func__);
        return;
    }

    std::vector<EventPackage> tmp;
    for (uint32_t i = 0; i < count; i++) {
        if (pkgs[i] == nullptr) {
            HDF_LOGE("%{public}s failed, pkgs[%{public}u] is nullptr", __func__, i);
            return;
        }
        EventPackage InputEvents;
        InputEvents.type = pkgs[i]->type;
        InputEvents.code = pkgs[i]->code;
        InputEvents.value = pkgs[i]->value;
        InputEvents.timestamp = pkgs[i]->timestamp;
        tmp.push_back(InputEvents);
    }

    if (g_inputEventCallback == nullptr) {
        HDF_LOGE("%{public}s: g_inputEventCallback is nullptr", __func__);
        return;
    }
    g_inputEventCallback->EventPkgCallback(tmp, devIndex);
}

void HotplugEventDataCallback(const InputHotPlugEvent *event)
{
    if (event == nullptr) {
        HDF_LOGE("%{public}s failed, pkgs is nullptr", __func__);
        return;
    }

    HotPlugEvent HotPlugEvent;
    HotPlugEvent.devIndex = event->devIndex;
    HotPlugEvent.devType = event->devType;
    HotPlugEvent.status = event->status;

    if (g_hotplugEventCallback == nullptr) {
        HDF_LOGE("%{public}s: g_hotplugEventCallback is nullptr", __func__);
        return;
    }
    g_hotplugEventCallback->HotPlugCallback(HotPlugEvent);
}

void InputInterfacesImpl::Init()
{
    int32_t ret = GetInputInterface(&inputInterface_);
    if (inputInterface_ == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get input Module instance failed", __func__);
    }

    eventCb.EventPkgCallback = InputEventDataCallback;
    hostCb.HotPlugCallback = HotplugEventDataCallback;
}

int32_t InputInterfacesImpl::ScanInputDevice(std::vector<DevDesc> &staArr)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputManager == nullptr ||
        inputInterface_->iInputManager->ScanInputDevice == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    InputDevDesc staArrHdf[MAX_DEVICES];
    int32_t ret = memset_s(staArrHdf, MAX_DEVICES * sizeof(InputDevDesc), 0, MAX_DEVICES * sizeof(InputDevDesc));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: memset failed", __func__);
        return HDF_FAILURE;
    }

    ret = inputInterface_->iInputManager->ScanInputDevice(staArrHdf, MAX_DEVICES);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    for (uint32_t i = 0; i < MAX_DEVICES; i++) {
        DevDesc StaArr;
        StaArr.devIndex = staArrHdf[i].devIndex;
        StaArr.devType = staArrHdf[i].devType;
        staArr.push_back(StaArr);
    }

    return ret;
}

int32_t InputInterfacesImpl::OpenInputDevice(uint32_t devIndex)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputManager == nullptr ||
        inputInterface_->iInputManager->OpenInputDevice == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = inputInterface_->iInputManager->OpenInputDevice(devIndex);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t InputInterfacesImpl::CloseInputDevice(uint32_t devIndex)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputManager == nullptr ||
        inputInterface_->iInputManager->CloseInputDevice == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = inputInterface_->iInputManager->CloseInputDevice(devIndex);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t InputInterfacesImpl::GetInputDevice(uint32_t devIndex, DeviceInfo &devInfo)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputManager == nullptr ||
        inputInterface_->iInputManager->GetInputDevice == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    InputDeviceInfo *deviceInfo = nullptr;

    int32_t ret = inputInterface_->iInputManager->GetInputDevice(devIndex, &deviceInfo);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
        return ret;
    }

    if (deviceInfo == nullptr) {
        HDF_LOGE("%{public}s get deviceInfo failed, info is null", __func__);
        return HDF_FAILURE;
    }
    devInfo = TransferDevInfo(*deviceInfo);

    return ret;
}

int32_t InputInterfacesImpl::GetInputDeviceList(uint32_t &devNum, std::vector<DeviceInfo> &devList, uint32_t size)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputManager == nullptr ||
        inputInterface_->iInputManager->GetInputDeviceList == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    InputDeviceInfo *deviceList = nullptr;
    InputDeviceInfo *tmp = nullptr;
    DeviceInfo hdfDevInfo;
    int32_t ret = inputInterface_->iInputManager->GetInputDeviceList(&devNum, &deviceList, size);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    tmp = deviceList;
    if (tmp == nullptr) {
        HDF_LOGE("%{public}s deviceList is null", __func__);
        return HDF_FAILURE;
    }

    devList.reserve(devNum);
    for (uint32_t i = 0; i < devNum; i++) {
        hdfDevInfo = TransferDevInfo(*tmp);
        devList.push_back(hdfDevInfo);
        tmp++;
    }

    return ret;
}

int32_t InputInterfacesImpl::SetPowerStatus(uint32_t devIndex, uint32_t status)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputController == nullptr ||
        inputInterface_->iInputController->SetPowerStatus == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = inputInterface_->iInputController->SetPowerStatus(devIndex, status);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
    }
    
    return ret;
}

int32_t InputInterfacesImpl::GetPowerStatus(uint32_t devIndex, uint32_t &status)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputController == nullptr ||
        inputInterface_->iInputController->GetPowerStatus == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = inputInterface_->iInputController->GetPowerStatus(devIndex, &status);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t InputInterfacesImpl::GetDeviceType(uint32_t devIndex, uint32_t &deviceType)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputController == nullptr ||
        inputInterface_->iInputController->GetDeviceType == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = inputInterface_->iInputController->GetDeviceType(devIndex, &deviceType);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t InputInterfacesImpl::GetChipInfo(uint32_t devIndex, std::string &chipInfo)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputController == nullptr ||
        inputInterface_->iInputController->GetChipInfo == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    char infoStr[CHIP_INFO_LEN] = {0};
    int32_t ret = inputInterface_->iInputController->GetChipInfo(devIndex, infoStr, CHIP_INFO_LEN);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    chipInfo.assign(infoStr);
    return ret;
}

int32_t InputInterfacesImpl::GetVendorName(uint32_t devIndex, std::string &vendorName)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputController == nullptr ||
        inputInterface_->iInputController->GetVendorName == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    char infoStr[VENDOR_NAME_LEN] = {0};
    int32_t ret = inputInterface_->iInputController->GetVendorName(devIndex, infoStr, VENDOR_NAME_LEN);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    vendorName.assign(infoStr);
    return ret;
}

int32_t InputInterfacesImpl::GetChipName(uint32_t devIndex, std::string &chipName)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputController == nullptr ||
        inputInterface_->iInputController->GetChipName == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    char infoStr[CHIP_NAME_LEN] = {0};
    int32_t ret = inputInterface_->iInputController->GetChipName(devIndex, infoStr, CHIP_NAME_LEN);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    chipName.assign(infoStr);
    return ret;
}

int32_t InputInterfacesImpl::SetGestureMode(uint32_t devIndex, uint32_t gestureMode)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputController == nullptr ||
        inputInterface_->iInputController->SetGestureMode == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = inputInterface_->iInputController->SetGestureMode(devIndex, gestureMode);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t InputInterfacesImpl::RunCapacitanceTest(uint32_t devIndex, uint32_t testType, std::string &result,
    uint32_t length)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputController == nullptr ||
        inputInterface_->iInputController->RunCapacitanceTest == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = inputInterface_->iInputController->RunCapacitanceTest(devIndex, testType, result.data(), length);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t InputInterfacesImpl::RunExtraCommand(uint32_t devIndex, const ExtraCmd &cmd)
{
    InputExtraCmd cmdInfo;
    cmdInfo.cmdCode = cmd.cmdCode.c_str();
    cmdInfo.cmdValue = cmd.cmdValue.c_str();

    if (inputInterface_ == nullptr || inputInterface_->iInputController == nullptr ||
        inputInterface_->iInputController->RunExtraCommand == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = inputInterface_->iInputController->RunExtraCommand(devIndex, &cmdInfo);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t InputInterfacesImpl::RegisterReportCallback(uint32_t devIndex, const sptr<IInputCallback> &eventPkgCallback)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputReporter == nullptr ||
        inputInterface_->iInputReporter->RegisterReportCallback == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    if (devIndex >= MAX_INPUT_DEV_NUM) {
        HDF_LOGE("%{public}s: devIndex [%{public}d] out of range", __func__, devIndex);
        return INPUT_INVALID_PARAM;
    }

    if (eventPkgCallback == nullptr) {
        HDF_LOGE("%{public}s: eventPkgCallback is null", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = HDF_FAILURE;
    ret = inputInterface_->iInputReporter->RegisterReportCallback(devIndex, &eventCb);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, ret[%{public}d]", __func__, ret);
        return ret;
    }

    std::lock_guard<std::mutex> lock(g_mutex);
    g_inputEventCallback = eventPkgCallback;

    return ret;
}

int32_t InputInterfacesImpl::UnregisterReportCallback(uint32_t devIndex)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputReporter == nullptr ||
        inputInterface_->iInputReporter->UnregisterReportCallback == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = inputInterface_->iInputReporter->UnregisterReportCallback(devIndex);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
        return ret;
    }
    return ret;
}

int32_t InputInterfacesImpl::RegisterHotPlugCallback(const sptr<IInputCallback> &hotPlugCallback)
{
    if (inputInterface_ == nullptr || inputInterface_->iInputReporter == nullptr ||
        inputInterface_->iInputReporter->UnregisterReportCallback == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    if (hotPlugCallback == nullptr) {
        HDF_LOGE("%{public}s: hotPlugCallback is null", __func__);
        return HDF_FAILURE;
    }

    if (g_hotplugEventCallback != nullptr) {
        sptr<IRemoteObject> lhs = OHOS::HDI::hdi_objcast<IInputCallback>(hotPlugCallback);
        sptr<IRemoteObject> rhs = OHOS::HDI::hdi_objcast<IInputCallback>(g_hotplugEventCallback);
        if (lhs == rhs) {
            return HDF_SUCCESS;
        }
    }

    int32_t ret = HDF_FAILURE;
    ret = inputInterface_->iInputReporter->RegisterHotPlugCallback(&hostCb);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, ret[%{public}d]", __func__, ret);
        return ret;
    }

    std::lock_guard<std::mutex> lock(g_mutex);
    g_hotplugEventCallback = hotPlugCallback;

    return ret;
}

int32_t InputInterfacesImpl::UnregisterHotPlugCallback()
{
    if (inputInterface_ == nullptr || inputInterface_->iInputReporter == nullptr ||
        inputInterface_->iInputReporter->UnregisterHotPlugCallback == nullptr) {
        HDF_LOGE("%{public}s: get input device Module instance failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = inputInterface_->iInputReporter->UnregisterHotPlugCallback();
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
        return ret;
    }

    std::lock_guard<std::mutex> lock(g_mutex);
    g_hotplugEventCallback = nullptr;

    return ret;
}
} // V1_0
} // Input
} // HDI
} // OHOS
