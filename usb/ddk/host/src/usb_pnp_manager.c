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

#include "usb_pnp_manager.h"
#include <pthread.h>
#include <unistd.h>

#include "ddk_device_manager.h"
#include "ddk_pnp_listener_mgr.h"
#include "ddk_uevent_handle.h"
#include "device_resource_if.h"
#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "hdf_device_object.h"
#include "hdf_io_service_if.h"
#include "hdf_log.h"
#include "osal_mem.h"
#include "securec.h"
#include "usb_ddk_pnp_loader.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG    usb_pnp_manager
#define MODULENAMESIZE 128

#ifdef USB_EMULATOR_MODE
#define USB_GADGET_STATE_PATH "gadget_state_path"
#define USB_GADGET_UEVENT_PATH "gadget_uevent_path"
const char USB_EMULATOR_DEFAULT_STATE_PATH[] =  "/sys/class/gadget_usb/gadget0/state";
const char USB_EMULATOR_DEFAULT_UEVENT_PATH[] = "/devices/virtual/gadget_usb/gadget0";
#endif

bool UsbPnpManagerWriteModuleName(struct HdfSBuf *sbuf, const char *moduleName)
{
    char modName[MODULENAMESIZE] = {0};
    if (sprintf_s(modName, MODULENAMESIZE, "lib%s.z.so", moduleName) < 0) {
        HDF_LOGE("%{public}s: sprintf_s modName failed", __func__);
        return false;
    }

    return HdfSbufWriteString(sbuf, modName);
}

static int32_t UsbPnpManagerDispatch(
    struct HdfDeviceIoClient *client, int32_t cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    HDF_LOGI("received cmd = %{public}d", cmd);
    return HDF_SUCCESS;
}

static int32_t UsbPnpManagerBind(struct HdfDeviceObject *device)
{
    static struct IDeviceIoService pnpLoaderService = {
        .Dispatch = UsbPnpManagerDispatch,
    };

    if (device == NULL) {
        return HDF_ERR_INVALID_OBJECT;
    }

    device->service = &pnpLoaderService;
    HDF_LOGI("usb pnp manager bind success");

    return HDF_SUCCESS;
}

#ifdef USB_EVENT_NOTIFY_LINUX_NATIVE_MODE
int32_t UsbPnpManagerStartUeventThread(void)
{
    pthread_t tid;
    int32_t ret = pthread_create(&tid, NULL, DdkUeventMain, NULL);
    if (ret != 0) {
        HDF_LOGE("%{public}s: create thread failed:%{public}d", __func__, ret);
        return ret;
    }

    ret = pthread_setname_np(tid, "usbpnpUeventThd");
    if (ret != 0) {
        HDF_LOGE("%{public}s: set thread name failed:%{public}d", __func__, ret);
    }
    return ret;
}
#endif

static const char *UsbPnpMgrGetGadgetPath(struct HdfDeviceObject *device, const char *attrName)
{
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (iface == NULL) {
        HDF_LOGE("%{public}s: DeviceResourceGetIfaceInstance failed", __func__);
        return NULL;
    }

    const char *path = NULL;
    const char *pathDef = NULL;
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is empty", __func__);
        return NULL;
    }
#ifdef USB_EMULATOR_MODE
    if (iface->GetString(device->property, attrName, &path, pathDef) != HDF_SUCCESS) {
        HDF_LOGW("%{public}s: emulator read %{public}s failed", __func__, attrName);

        if (strncmp(attrName, USB_GADGET_STATE_PATH, strlen(USB_GADGET_STATE_PATH)) == 0) {
            path = USB_EMULATOR_DEFAULT_STATE_PATH;
        } else {
            path = USB_EMULATOR_DEFAULT_UEVENT_PATH;
        }
    }
#else
    if (iface->GetString(device->property, attrName, &path, pathDef) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: read %{public}s failed", __func__, attrName);
        return NULL;
    }
#endif
    return path;
}

static int32_t UsbPnpManagerInit(struct HdfDeviceObject *device)
{
    static struct HdfDevEventlistener usbPnpListener = {
        .callBack = UsbDdkPnpLoaderEventReceived,
    };
    usbPnpListener.priv = (void *)(device);

    int32_t ret = DdkDevMgrInit(UsbPnpMgrGetGadgetPath(device, "gadget_state_path"));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: DdkDevMgrInit error", __func__);
        return HDF_FAILURE;
    }

    ret = DdkListenerMgrInit();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: DdkListenerMgrInit error", __func__);
        return HDF_FAILURE;
    }

    ret = DdkUeventInit(UsbPnpMgrGetGadgetPath(device, "gadget_uevent_path"));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: DdkUeventInit error", __func__);
        return ret;
    }
#ifdef USB_EVENT_NOTIFY_LINUX_NATIVE_MODE
    if (UsbPnpManagerStartUeventThread() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: start uevent thread failed", __func__);
        return HDF_FAILURE;
    }
#endif

#ifdef USB_EMULATOR_MODE
    ret = UsbDdkPnpLoaderEventHandle();
    if (ret != HDF_SUCCESS) {
        HDF_LOGW("%{public}s: emulator, UsbDdkPnpLoaderEventHandle failed", __func__);
    }
    if (DdkListenerMgrAdd(&usbPnpListener) != HDF_SUCCESS) {
        HDF_LOGW("%{public}s: emulator, add listener failed", __func__);
    }
#else
    ret = UsbDdkPnpLoaderEventHandle();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbDdkPnpLoaderEventHandle failed", __func__);
        return ret;
    }
    if (DdkListenerMgrAdd(&usbPnpListener) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: add listener failed", __func__);
        return HDF_FAILURE;
    }
#endif
    HDF_LOGI("UsbPnpManagerInit done");
    return HDF_SUCCESS;
}

static void UsbPnpManagerRelease(struct HdfDeviceObject *device)
{
    (void)device;
    return;
}

struct HdfDriverEntry g_usbPnpManagerEntry = {
    .moduleVersion = 1,
    .Bind = UsbPnpManagerBind,
    .Init = UsbPnpManagerInit,
    .Release = UsbPnpManagerRelease,
    .moduleName = "HDF_USB_PNP_MANAGER",
};

HDF_INIT(g_usbPnpManagerEntry);
