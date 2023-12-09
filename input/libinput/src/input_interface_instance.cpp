/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <mutex>
#include <securec.h>
#include "hdf_log.h"
#include "input_interface_implement.h"
#include "input_type.h"
#include "input_manager.h"
#include "osal_mem.h"

#define HDF_LOG_TAG InputIfManager

using namespace OHOS::Input;
static std::shared_ptr<InputIfImpl> g_inputIfImpl {nullptr};
static std::mutex g_ifInstanceMtx;

static int32_t ScanInputDevice(InputDevDesc *staArr, uint32_t arrLen)
{
    return INPUT_SUCCESS;
}

static int32_t OpenInputDevice(uint32_t devIndex)
{
    return INPUT_SUCCESS;
}

static int32_t CloseInputDevice(uint32_t devIndex)
{
    return INPUT_SUCCESS;
}

static int32_t GetInputDevice(uint32_t devIndex, InputDeviceInfo **devInfo)
{
    return INPUT_SUCCESS;
}

static int32_t GetInputDeviceList(uint32_t *devNum, InputDeviceInfo **devList, uint32_t size)
{
    return INPUT_SUCCESS;
}

static int32_t SetPowerStatus(uint32_t devIndex, uint32_t status)
{
    return INPUT_SUCCESS;
}

static int32_t GetPowerStatus(uint32_t devIndex, uint32_t *status)
{
    return INPUT_SUCCESS;
}

static int32_t GetChipInfo(uint32_t devIndex, char *chipInfo, uint32_t length)
{
    return INPUT_SUCCESS;
}

static int32_t GetVendorName(uint32_t devIndex, char *vendorName, uint32_t length)
{
    return INPUT_SUCCESS;
}

static int32_t GetChipName(uint32_t devIndex, char *chipName, uint32_t length)
{
    return INPUT_SUCCESS;
}

static int32_t GetDeviceType(uint32_t devIndex, uint32_t *deviceType)
{
    return INPUT_SUCCESS;
}

static int32_t SetGestureMode(uint32_t devIndex, uint32_t gestureMode)
{
    return INPUT_SUCCESS;
}

static int32_t RunCapacitanceTest(uint32_t devIndex, uint32_t testType, char *result, uint32_t length)
{
    return INPUT_SUCCESS;
}

static int32_t RunExtraCommand(uint32_t devIndex, InputExtraCmd *cmd)
{
    return INPUT_SUCCESS;
}

static int32_t RegisterReportCallback(uint32_t devIndex, InputEventCb *callback)
{
    std::lock_guard<std::mutex> guard(g_ifInstanceMtx);
    if (!g_inputIfImpl) {
        HDF_LOGE("g_inputIfImpl is null");
        return INPUT_FAILURE;
    }
    return g_inputIfImpl->RegisterReportCallback(callback);
}

static int32_t UnregisterReportCallback(uint32_t devIndex)
{
    std::lock_guard<std::mutex> guard(g_ifInstanceMtx);
    if (!g_inputIfImpl) {
        HDF_LOGE("g_inputIfImpl is null");
        return INPUT_FAILURE;
    }
    return g_inputIfImpl->UnregisterReportCallback();
}

static int32_t RegisterHotPlugCallback(InputHostCb *callback)
{
    return INPUT_SUCCESS;
}

static int32_t UnregisterHotPlugCallback(void)
{
    return INPUT_SUCCESS;
}

static int32_t InstanceManagerIf(InputManager **manager)
{
    InputManager *managerIf = (InputManager *)OsalMemAlloc(sizeof(InputManager));
    if (managerIf == nullptr) {
        HDF_LOGE("OsalMemAlloc failed");
        return INPUT_NOMEM;
    }
    (void)memset_s(managerIf, sizeof(InputManager), 0, sizeof(InputManager));
    managerIf->ScanInputDevice = ScanInputDevice;
    managerIf->OpenInputDevice = OpenInputDevice;
    managerIf->CloseInputDevice = CloseInputDevice;
    managerIf->GetInputDevice = GetInputDevice;
    managerIf->GetInputDeviceList = GetInputDeviceList;
    *manager = managerIf;
    return INPUT_SUCCESS;
}

static int32_t InstanceControllerIf(InputController **controller)
{
    InputController *controllerIf = (InputController *)OsalMemAlloc(sizeof(InputController));
    if (controllerIf == nullptr) {
        HDF_LOGE("OsalMemAlloc failed");
        return INPUT_NOMEM;
    }
    (void)memset_s(controllerIf, sizeof(InputController), 0, sizeof(InputController));
    controllerIf->SetPowerStatus = SetPowerStatus;
    controllerIf->GetPowerStatus = GetPowerStatus;
    controllerIf->GetDeviceType = GetDeviceType;
    controllerIf->GetChipInfo = GetChipInfo;
    controllerIf->GetVendorName = GetVendorName;
    controllerIf->GetChipName = GetChipName;
    controllerIf->SetGestureMode = SetGestureMode;
    controllerIf->RunCapacitanceTest = RunCapacitanceTest;
    controllerIf->RunExtraCommand = RunExtraCommand;
    *controller = controllerIf;
    return INPUT_SUCCESS;
}

static int32_t InstanceReporterIf(InputReporter **reporter)
{
    InputReporter *reporterIf = (InputReporter *)OsalMemAlloc(sizeof(InputReporter));
    if (reporterIf == nullptr) {
        HDF_LOGE("OsalMemAlloc failed");
        return INPUT_NOMEM;
    }
    (void)memset_s(reporterIf, sizeof(InputReporter), 0, sizeof(InputReporter));
    reporterIf->RegisterReportCallback = RegisterReportCallback;
    reporterIf->UnregisterReportCallback = UnregisterReportCallback;
    reporterIf->RegisterHotPlugCallback = RegisterHotPlugCallback;
    reporterIf->UnregisterHotPlugCallback = UnregisterHotPlugCallback;
    *reporter = reporterIf;
    return INPUT_SUCCESS;
}

static void FreeInputIf(IInputInterface **If)
{
    if (If == nullptr || *If == nullptr) {
        return;
    }
    if ((*If)->iInputManager != nullptr) {
        OsalMemFree((*If)->iInputManager);
        (*If)->iInputManager = nullptr;
    }
    if ((*If)->iInputController != nullptr) {
        OsalMemFree((*If)->iInputController);
        (*If)->iInputController = nullptr;
    }
    if ((*If)->iInputReporter != nullptr) {
        OsalMemFree((*If)->iInputReporter);
        (*If)->iInputReporter = nullptr;
    }
    OsalMemFree((*If));
    *If = nullptr;
}

static IInputInterface *InstanceInputIf(void)
{
    int32_t ret;
    IInputInterface *inputIf = (IInputInterface *)OsalMemAlloc(sizeof(IInputInterface));
    if (inputIf == nullptr) {
        HDF_LOGE("OsalMemAlloc failed");
        return nullptr;
    }
    (void)memset_s(inputIf, sizeof(IInputInterface), 0, sizeof(IInputInterface));

    do {
        g_inputIfImpl = std::make_shared<InputIfImpl>();
        if (!g_inputIfImpl) {
            HDF_LOGE("g_inputIfImpl is null");
            ret = INPUT_NOMEM;
            break;
        }
        ret = g_inputIfImpl->Init();
        if (ret != INPUT_SUCCESS) {
            break;
        }

        ret = InstanceManagerIf(&inputIf->iInputManager);
        if (ret != INPUT_SUCCESS) {
            break;
        }
        ret = InstanceControllerIf(&inputIf->iInputController);
        if (ret != INPUT_SUCCESS) {
            break;
        }
        ret = InstanceReporterIf(&inputIf->iInputReporter);
        if (ret != INPUT_SUCCESS) {
            break;
        }
    } while (0);

    if (ret != INPUT_SUCCESS) {
        FreeInputIf(&inputIf);
        g_inputIfImpl = nullptr;
        return nullptr;
    }

    return inputIf;
}

int32_t GetInputInterface(IInputInterface **inputInterface)
{
    std::lock_guard<std::mutex> guard(g_ifInstanceMtx);
    IInputInterface *inputIf = nullptr;
    if (inputInterface == nullptr) {
        HDF_LOGE("parameter is null");
        return INPUT_INVALID_PARAM;
    }
    inputIf = InstanceInputIf();
    if (inputIf == nullptr) {
        HDF_LOGE("failed to instance If");
        return INPUT_NULL_PTR;
    }
    *inputInterface = inputIf;
    HDF_LOGI("exit succ");
    return INPUT_SUCCESS;
}

void ReleaseInputInterface(IInputInterface **inputInterface)
{
    std::lock_guard<std::mutex> guard(g_ifInstanceMtx);
    if (inputInterface == nullptr || *inputInterface == nullptr) {
        return;
    }
    FreeInputIf(inputInterface);
    g_inputIfImpl = nullptr;
}
