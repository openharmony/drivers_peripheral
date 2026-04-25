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

#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_log.h>
#include <hdf_sbuf_ipc.h>
#include "v1_0/hci_interface_stub.h"
#ifdef BLUETOOTH_PLUGGABLE_SUPPORTED
#include "file_ex.h"
#include "parameter.h"
#include "param_wrapper.h"
#endif

using namespace OHOS::HDI::Bluetooth::Hci::V1_0;

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD000105

#ifdef BLUETOOTH_PLUGGABLE_SUPPORTED
namespace {
const std::string BLUETOOTH_CHIP_UNSUPPORTED_PATH = "/proc/connectivity/wifi_chip_no_support";
const char* BLUETOOTH_PLUGGABLE_STATE = "persist.bluetooth.pluggable.state";
const char* BLUETOOTH_PLUGGABLE_STATE_EXTRACT = "0";
const char* BLUETOOTH_PLUGGABLE_STATE_EMPLACE = "1";
const char* BLUETOOTH_EMPLACE_ENABLE_STATE = "bluetooth.emplace_enable.state";
const char* BLUETOOTH_EMPLACE_NEED_ENABLE_BT = "1";
}
#endif

struct HdfHciInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
    HdfHciInterfaceHost()
    {
        ioService.object.objectId = 0;
        ioService.Open = nullptr;
        ioService.Release = nullptr;
        ioService.Dispatch = nullptr;
    }
};

static int32_t HciInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfHciInterfaceHost = CONTAINER_OF(client->device->service, struct HdfHciInterfaceHost, ioService);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfHciInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

#ifdef BLUETOOTH_PLUGGABLE_SUPPORTED
static bool IsBluetoothSupported()
{
    std::string content;
    bool res = LoadStringFromFile(BLUETOOTH_CHIP_UNSUPPORTED_PATH, content);
    return !(res && content == "1"); // 蓝牙模组不在位才将节点写为“1”
}

static bool CheckNeedAutoEnableBluetooth()
{
    std::string persistState = BLUETOOTH_PLUGGABLE_STATE_EXTRACT;
    int32_t res = system::GetStringParameter(BLUETOOTH_PLUGGABLE_STATE, persistState,
        BLUETOOTH_PLUGGABLE_STATE_EXTRACT);
    if (res != 0) {
        HDF_LOGE("%{public}s: read last Bt supported state failed, res: %{public}d", res);
    }
    bool lastBtSupportedState = (res == 0 && persistState == BLUETOOTH_PLUGGABLE_STATE_EMPLACE);
    bool curBtSupportedState = IsBluetoothSupported();
    SetParameter(BLUETOOTH_PLUGGABLE_STATE, curBtSupportedState ?
        BLUETOOTH_PLUGGABLE_STATE_EMPLACE : BLUETOOTH_PLUGGABLE_STATE_EXTRACT);
    if (!lastBtSupportedState && curBtSupportedState) {
        return true;
    }
    return false;
}
#endif

static int HdfHciInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    (void)deviceObject;
    HDF_LOGI("HdfHciInterfaceDriverInit enter");
#ifdef BLUETOOTH_PLUGGABLE_SUPPORTED
    if (CheckNeedAutoEnableBluetooth()) {
        SetParameter(BLUETOOTH_EMPLACE_ENABLE_STATE, BLUETOOTH_EMPLACE_NEED_ENABLE_BT);
    }
#endif
    return HDF_SUCCESS;
}

static int HdfHciInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfHciInterfaceDriverBind enter");

    auto *hdfHciInterfaceHost = new (std::nothrow) HdfHciInterfaceHost;
    if (hdfHciInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfHciInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfHciInterfaceHost->ioService.Dispatch = HciInterfaceDriverDispatch;
    hdfHciInterfaceHost->ioService.Open = NULL;
    hdfHciInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = IHciInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfHciInterfaceHost;
        return HDF_FAILURE;
    }

    hdfHciInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IHciInterface::GetDescriptor());
    if (hdfHciInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfHciInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfHciInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfHciInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfHciInterfaceDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfHciInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfHciInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfHciInterfaceHost, ioService);
    delete hdfHciInterfaceHost;
}

static struct HdfDriverEntry g_hciinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "bluetooth_hci",
    .Bind = HdfHciInterfaceDriverBind,
    .Init = HdfHciInterfaceDriverInit,
    .Release = HdfHciInterfaceDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_hciinterfaceDriverEntry);
#ifndef __cplusplus
}
#endif
