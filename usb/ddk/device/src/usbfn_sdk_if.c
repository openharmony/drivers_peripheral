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

#include "usbfn_cfg_mgr.h"
#include "usbfn_dev_mgr.h"
#include "usbfn_device.h"
#include "usbfn_interface.h"
#include "usbfn_io_mgr.h"
#include "usbfn_request.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG usbfn_sdk_if

static struct UsbDeviceFunctionsInfo g_functionsInfo[] = {
    {"f_generic.a",   1     },
    {"f_generic.e",   1 << 1},
    {"f_generic.mtp", 1 << 3},
    {"f_generic.ptp", 1 << 4},
    {NULL,            0     },
};

static int32_t IsDescriptorOk(struct UsbFnDeviceDesc *des)
{
    int32_t i, j;
    struct UsbFnStrings **strings = NULL;
    struct UsbFnFunction *functions = NULL;
    if (des == NULL) {
        HDF_LOGE("%{public}s: des null", __func__);
        goto ERR_DES;
    }
    if (des->deviceDesc == NULL || des->deviceStrings == NULL || des->configs == NULL) {
        HDF_LOGE("%{public}s: deviceDesc  deviceStrings configs null", __func__);
        goto ERR_DES;
    }

    strings = des->deviceStrings;
    if (strings[0] == NULL) {
        HDF_LOGE("%{public}s: strings null", __func__);
        goto ERR_DES;
    }

    for (i = 0; des->configs[i] != NULL; i++) {
        for (j = 0; des->configs[i]->functions[j] != NULL; j++) {
            functions = des->configs[i]->functions[j];
            if (strncmp(functions->funcName, FUNCTION_GENERIC, strlen(FUNCTION_GENERIC)) != 0) {
                continue;
            }
            if (functions->fsDescriptors == NULL) {
                HDF_LOGE("%{public}s: fsDescriptors null", __func__);
                goto ERR_DES;
            }
        }
    }
    if (i == 0 || j == 0) {
        HDF_LOGE("%{public}s: configs functions null", __func__);
        goto ERR_DES;
    }

    return 0;
ERR_DES:
    HDF_LOGE("%{public}s: DeviceDesc bad", __func__);
    return HDF_ERR_INVALID_PARAM;
}

static void DoChangeFunction(struct UsbFnFunction * const function, struct UsbFnDescriptorData * const descriptor)
{
    uint32_t i;
    struct UsbDeviceFunctionsInfo *funcInfo = g_functionsInfo;
    for (i = 0; funcInfo[i].functionName != NULL; i++) {
        if (strncmp(function->funcName, funcInfo[i].functionName, strlen(funcInfo[i].functionName)) == 0) {
            if ((descriptor->functionMask & funcInfo[i].numberMask) != 0) {
                function->enable = true;
                HDF_LOGI("%{public}s: enable function = %{public}s", __func__, funcInfo[i].functionName);
            } else {
                function->enable = false;
                HDF_LOGI("%{public}s: disable function = %{public}s", __func__, funcInfo[i].functionName);
            }
        }
    }
}

static void UsbFnChangeFunction(struct UsbFnDeviceDesc * const des, struct UsbFnDescriptorData * const descriptor)
{
    uint32_t i;
    uint32_t j;
    if (des == NULL || descriptor == NULL) {
        HDF_LOGE("%{public}s: param is null", __func__);
        return;
    }
    for (i = 0; des->configs[i] != NULL; i++) {
        for (j = 0; des->configs[i]->functions[j] != NULL; j++) {
            DoChangeFunction(des->configs[i]->functions[j], descriptor);
        }
    }
}

const struct UsbFnDevice *UsbFnCreateDevice(const char *udcName, struct UsbFnDescriptorData *descriptor)
{
    int32_t ret;
    const struct DeviceResourceNode *property = NULL;
    struct UsbFnDeviceDesc *des = NULL;

    if (udcName == NULL || descriptor == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return NULL;
    }
    if (UsbFnMgrDeviceGet(udcName) != NULL) {
        HDF_LOGE("%{public}s: udc %{public}s haved create", __func__, udcName);
        return NULL;
    }
    HDF_LOGD("%{public}s: type=%{public}d, fMask=%{public}d", __func__, descriptor->type, descriptor->functionMask);
    if (descriptor->type == USBFN_DESC_DATA_TYPE_PROP) {
        property = descriptor->property;
        HDF_LOGD("%{public}s: use descriptor in HCS", __func__);
        des = UsbFnCfgMgrGetInstanceFromHCS(property);
        if (des == NULL) {
            HDF_LOGE("%{public}s: get descriptors from HCS failed", __func__);
            return NULL;
        }
    } else {
        des = descriptor->descriptor;
    }
    UsbFnChangeFunction(des, descriptor);
    ret = IsDescriptorOk(des);
    if (ret) {
        return NULL;
    }

    return (struct UsbFnDevice *)UsbFnMgrDeviceCreate(udcName, des, property);
}

int32_t UsbFnRemoveDevice(struct UsbFnDevice *fnDevice)
{
    if (fnDevice == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnMgrDeviceRemove(fnDevice);
}

const struct UsbFnDevice *UsbFnGetDevice(const char *udcName)
{
    if (udcName == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return NULL;
    }
    return (struct UsbFnDevice *)UsbFnMgrDeviceGet((const char *)udcName);
}

int32_t UsbFnGetDeviceState(struct UsbFnDevice *fnDevice, UsbFnDeviceState *devState)
{
    if (fnDevice == NULL || devState == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnMgrDeviceGetState(fnDevice, devState);
}

const struct UsbFnInterface *UsbFnGetInterface(struct UsbFnDevice *fnDevice, uint8_t interfaceIndex)
{
    if (fnDevice == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return NULL;
    }
    return (struct UsbFnInterface *)UsbFnMgrDeviceGetInterface(fnDevice, interfaceIndex);
}

int32_t UsbFnStartRecvInterfaceEvent(
    struct UsbFnInterface *interface, uint32_t eventMask, UsbFnEventCallback callback, void *context)
{
    if (interface == NULL || eventMask == 0 || callback == NULL) {
        HDF_LOGE("%{public}s: INVALID_PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnMgrStartRecvEvent(interface, eventMask, callback, context);
}

int32_t UsbFnStopRecvInterfaceEvent(struct UsbFnInterface *interface)
{
    if (interface == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnStopRecvEvent(interface);
}

UsbFnInterfaceHandle UsbFnOpenInterface(struct UsbFnInterface *interface)
{
    if (interface == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return NULL;
    }
    return (UsbFnInterfaceHandle)UsbFnIoMgrInterfaceOpen(interface);
}

int32_t UsbFnCloseInterface(UsbFnInterfaceHandle handle)
{
    if (handle == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnIoMgrInterfaceClose((struct UsbHandleMgr *)handle);
}

int32_t UsbFnGetInterfacePipeInfo(struct UsbFnInterface *interface, uint8_t pipeId, struct UsbFnPipeInfo *info)
{
    if (info == NULL || interface == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnIoMgrInterfaceGetPipeInfo(interface, pipeId, info);
}

int32_t UsbFnRegistInterfaceProp(const struct UsbFnInterface *interface, const struct UsbFnRegistInfo *registInfo)
{
    if (registInfo == NULL || interface == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnCfgMgrRegisterProp(interface, registInfo);
}

int32_t UsbFnGetInterfaceProp(const struct UsbFnInterface *interface, const char *name, char *value)
{
    if (name == NULL || interface == NULL || value == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnCfgMgrGetProp(interface, name, value);
}

int32_t UsbFnSetInterfaceProp(const struct UsbFnInterface *interface, const char *name, const char *value)
{
    if (name == NULL || interface == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnCfgMgrSetProp(interface, name, value);
}

struct UsbFnRequest *UsbFnAllocRequest(UsbFnInterfaceHandle handle, uint8_t pipe, uint32_t len)
{
    struct UsbHandleMgr *handleMgr = handle;
    if (handle == NULL || len > MAX_BUFLEN || len == 0 || pipe >= handleMgr->numFd) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return NULL;
    }
    return UsbFnIoMgrRequestAlloc(handleMgr, pipe + 1, len);
}

struct UsbFnRequest *UsbFnAllocCtrlRequest(UsbFnInterfaceHandle handle, uint32_t len)
{
    struct UsbHandleMgr *handleMgr = handle;
    if (handle == NULL || len > MAX_BUFLEN || len == 0) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return NULL;
    }
    return UsbFnIoMgrRequestAlloc(handleMgr, 0, len);
}

int32_t UsbFnFreeRequest(struct UsbFnRequest *req)
{
    if (req == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnIoMgrRequestFree(req);
}

int32_t UsbFnGetRequestStatus(struct UsbFnRequest *req, UsbRequestStatus *status)
{
    if (req == NULL || status == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnIoMgrRequestGetStatus(req, status);
}

int32_t UsbFnSubmitRequestAsync(struct UsbFnRequest *req)
{
    if (req == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnIoMgrRequestSubmitAsync(req);
}

int32_t UsbFnCancelRequest(struct UsbFnRequest *req)
{
    if (req == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnIoMgrRequestCancel(req);
}

int32_t UsbFnSubmitRequestSync(struct UsbFnRequest *req, uint32_t timeout)
{
    if (req == NULL) {
        HDF_LOGE("%{public}s: INVALID PARAM", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbFnIoMgrRequestSubmitSync(req, timeout);
}
