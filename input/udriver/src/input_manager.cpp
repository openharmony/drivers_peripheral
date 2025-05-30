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
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <functional>
#include <malloc.h>
#include <sys/ioctl.h>
#include <securec.h>
#include <unistd.h>
#include "hdf_io_service_if.h"
#include "input_uhdf_log.h"
#include "input_device_manager.h"
#include "osal_mem.h"

#define HDF_LOG_TAG InputHdiManager

using namespace OHOS::Input;
static std::shared_ptr<InputDeviceManager> gInputDeviceManager_ {nullptr};
static int32_t ScanInputDevice(InputDevDesc *staArr, uint32_t arrLen)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->ScanDevice(staArr, arrLen);
}

static int32_t OpenInputDevice(uint32_t devIndex)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->OpenDevice(devIndex);
}

static int32_t CloseInputDevice(uint32_t devIndex)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->CloseDevice(devIndex);
}

static int32_t GetInputDevice(uint32_t devIndex, InputDeviceInfo **devInfo)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->GetDevice(devIndex, devInfo);
}

static int32_t GetInputDeviceList(uint32_t *devNum, InputDeviceInfo **devList, uint32_t size)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->GetDeviceList(devNum, devList, size);
}

static int32_t SetPowerStatus(uint32_t devIndex, uint32_t status)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->SetPowerStatus(devIndex, status);
}

static int32_t GetPowerStatus(uint32_t devIndex, uint32_t *status)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->GetPowerStatus(devIndex, status);
}

static int32_t GetChipInfo(uint32_t devIndex, char *chipInfo, uint32_t length)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->GetChipInfo(devIndex, chipInfo, length);
}

static int32_t GetVendorName(uint32_t devIndex, char *vendorName, uint32_t length)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->GetVendorName(devIndex, vendorName, length);
}

static int32_t GetChipName(uint32_t devIndex, char *chipName, uint32_t length)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->GetChipName(devIndex, chipName, length);
}

static int32_t GetDeviceType(uint32_t devIndex, uint32_t *deviceType)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->GetDeviceType(devIndex, deviceType);
}

static int32_t SetGestureMode(uint32_t devIndex, uint32_t gestureMode)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->SetGestureMode(devIndex, gestureMode);
}

static int32_t RunCapacitanceTest(uint32_t devIndex, uint32_t testType, char *result, uint32_t length)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->RunCapacitanceTest(devIndex, testType, result, length);
}

static int32_t RunExtraCommand(uint32_t devIndex, InputExtraCmd *cmd)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->RunExtraCommand(devIndex, cmd);
}

static int32_t RegisterReportCallback(uint32_t devIndex, InputEventCb *callback)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->RegisterReportCallback(devIndex, callback);
}

static int32_t UnregisterReportCallback(uint32_t devIndex)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->UnregisterReportCallback(devIndex);
}

static int32_t RegisterHotPlugCallback(InputHostCb *callback)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->RegisterHotPlugCallback(callback);
}

static int32_t UnregisterHotPlugCallback(void)
{
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        return INPUT_FAILURE;
    }
    return gInputDeviceManager_->UnregisterHotPlugCallback();
}

#ifdef __cplusplus
extern "C" {
#endif

static int32_t InstanceManagerHdi(InputManager **manager)
{
    InputManager *managerHdi = (InputManager *)OsalMemAlloc(sizeof(InputManager));
    if (managerHdi == nullptr) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed", __func__);
        return INPUT_NOMEM;
    }
    (void)memset_s(managerHdi, sizeof(InputManager), 0, sizeof(InputManager));
    gInputDeviceManager_ = std::make_shared<InputDeviceManager>();
    if (!gInputDeviceManager_) {
        HDF_LOGE("%{public}s: gInputDeviceManager_ is null", __func__);
        OsalMemFree(managerHdi);
        managerHdi = nullptr;
        return INPUT_NOMEM;
    }
    gInputDeviceManager_->Init();
    managerHdi->ScanInputDevice = ScanInputDevice;
    managerHdi->OpenInputDevice = OpenInputDevice;
    managerHdi->CloseInputDevice = CloseInputDevice;
    managerHdi->GetInputDevice = GetInputDevice;
    managerHdi->GetInputDeviceList = GetInputDeviceList;
    *manager = managerHdi;
    return INPUT_SUCCESS;
}

static int32_t InstanceControllerHdi(InputController **controller)
{
    InputController *controllerHdi = (InputController *)OsalMemAlloc(sizeof(InputController));
    if (controllerHdi == nullptr) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed", __func__);
        return INPUT_NOMEM;
    }
    (void)memset_s(controllerHdi, sizeof(InputController), 0, sizeof(InputController));
    controllerHdi->SetPowerStatus = SetPowerStatus;
    controllerHdi->GetPowerStatus = GetPowerStatus;
    controllerHdi->GetDeviceType = GetDeviceType;
    controllerHdi->GetChipInfo = GetChipInfo;
    controllerHdi->GetVendorName = GetVendorName;
    controllerHdi->GetChipName = GetChipName;
    controllerHdi->SetGestureMode = SetGestureMode;
    controllerHdi->RunCapacitanceTest = RunCapacitanceTest;
    controllerHdi->RunExtraCommand = RunExtraCommand;
    *controller = controllerHdi;
    return INPUT_SUCCESS;
}

static int32_t InstanceReporterHdi(InputReporter **reporter)
{
    InputReporter *reporterHdi = (InputReporter *)OsalMemAlloc(sizeof(InputReporter));
    if (reporterHdi == nullptr) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed", __func__);
        return INPUT_NOMEM;
    }
    (void)memset_s(reporterHdi, sizeof(InputReporter), 0, sizeof(InputReporter));
    reporterHdi->RegisterReportCallback = RegisterReportCallback;
    reporterHdi->UnregisterReportCallback = UnregisterReportCallback;
    reporterHdi->RegisterHotPlugCallback = RegisterHotPlugCallback;
    reporterHdi->UnregisterHotPlugCallback = UnregisterHotPlugCallback;
    *reporter = reporterHdi;
    return INPUT_SUCCESS;
}

static void FreeInputHdi(IInputInterface **hdi)
{
    if (hdi == nullptr || *hdi == nullptr) {
        return;
    }
    if ((*hdi)->iInputManager != nullptr) {
        OsalMemFree((*hdi)->iInputManager);
        (*hdi)->iInputManager = nullptr;
    }
    if ((*hdi)->iInputController != nullptr) {
        OsalMemFree((*hdi)->iInputController);
        (*hdi)->iInputController = nullptr;
    }
    if ((*hdi)->iInputReporter != nullptr) {
        OsalMemFree((*hdi)->iInputReporter);
        (*hdi)->iInputReporter = nullptr;
    }
    OsalMemFree((*hdi));
    *hdi = nullptr;
}

static IInputInterface *InstanceInputHdi(void)
{
    int32_t ret;
    IInputInterface *hdi = (IInputInterface *)OsalMemAlloc(sizeof(IInputInterface));
    if (hdi == nullptr) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed", __func__);
        return nullptr;
    }
    (void)memset_s(hdi, sizeof(IInputInterface), 0, sizeof(IInputInterface));

    ret = InstanceManagerHdi(&hdi->iInputManager);
    if (ret != INPUT_SUCCESS) {
        FreeInputHdi(&hdi);
        return nullptr;
    }
    ret = InstanceControllerHdi(&hdi->iInputController);
    if (ret != INPUT_SUCCESS) {
        FreeInputHdi(&hdi);
        return nullptr;
    }
    ret = InstanceReporterHdi(&hdi->iInputReporter);
    if (ret != INPUT_SUCCESS) {
        FreeInputHdi(&hdi);
        return nullptr;
    }
    return hdi;
}

int32_t GetInputInterface(IInputInterface **inputInterface)
{
    IInputInterface *inputHdi = nullptr;
    if (inputInterface == nullptr) {
        HDF_LOGE("%{public}s: parameter is null", __func__);
        return INPUT_INVALID_PARAM;
    }
    inputHdi = InstanceInputHdi();
    if (inputHdi == nullptr) {
        HDF_LOGE("%{public}s: failed to instance hdi", __func__);
        return INPUT_NULL_PTR;
    }
    *inputInterface = inputHdi;
    HDF_LOGI("%{public}s: exit succ", __func__);
    return INPUT_SUCCESS;
}

void ReleaseInputInterface(IInputInterface **inputInterface)
{
    if (inputInterface == nullptr || *inputInterface == nullptr) {
        return;
    }
    FreeInputHdi(inputInterface);
}
#ifdef __cplusplus
}
#endif
