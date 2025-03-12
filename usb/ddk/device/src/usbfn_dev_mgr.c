/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "usbfn_dev_mgr.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "osal_thread.h"
#include "osal_time.h"
#include "securec.h"
#include "usbfn_cfg_mgr.h"
#include "usbfn_io_mgr.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG    usbfn_dev_mgr
#define SLEEP_TIME_OUT 100
#define SLEEP_TIMES    20

static struct DListHead g_devEntry = {0};
static uint32_t g_intfCnt = 0;
static uint32_t g_epCnt = 1;
static uint32_t g_fnCntOld = 0;
static void GetInterfaceInfo(const struct UsbInterfaceDescriptor *intf, struct UsbFnDeviceMgr *devMgr, uint32_t fnCnt,
    const struct UsbFnConfiguration *config)
{
    if (g_fnCntOld != fnCnt) {
        g_fnCntOld = fnCnt;
        g_epCnt = 1;
    }
    struct UsbFnInterfaceInfo *info = NULL;
    if (intf->bDescriptorType == USB_DDK_DT_INTERFACE && intf->bNumEndpoints > 0) {
        if (g_intfCnt >= devMgr->fnDev.numInterfaces) {
            HDF_LOGE("%{public}s: GetInterfaceInfo failed", __func__);
            return;
        }
        info = &devMgr->interfaceMgr[g_intfCnt].interface.info;
        info->index = intf->bInterfaceNumber;
        info->interfaceClass = intf->bInterfaceClass;
        info->subclass = intf->bInterfaceSubClass;
        info->protocol = intf->bInterfaceProtocol;
        info->numPipes = intf->bNumEndpoints;
        info->configIndex = config->configurationValue;

        devMgr->interfaceMgr[g_intfCnt].interface.object = &devMgr->fnDev.object;
        devMgr->interfaceMgr[g_intfCnt].funcMgr = &devMgr->funcMgr[fnCnt];
        devMgr->interfaceMgr[g_intfCnt].startEpId = (uint8_t)g_epCnt;
        g_epCnt += intf->bNumEndpoints;
        g_intfCnt++;
    }
}

static void CreateInterface(struct UsbFnDeviceDesc *des, struct UsbFnDeviceMgr *devMgr)
{
    uint32_t fnCnt = 0;
    struct UsbInterfaceDescriptor *intf = NULL;
    g_intfCnt = 0;
    g_epCnt = 1;
    g_fnCntOld = 0;

    for (uint32_t i = 0; des->configs[i] != NULL; i++) {
        for (uint32_t j = 0; des->configs[i]->functions[j] != NULL; j++) {
            if (strncmp(des->configs[i]->functions[j]->funcName, FUNCTION_GENERIC, strlen(FUNCTION_GENERIC))) {
                continue;
            }
            if (des->configs[i]->functions[j]->enable == false) {
                continue;
            }
            DListHeadInit(&devMgr->funcMgr[fnCnt].reqEntry);
            devMgr->funcMgr[fnCnt].object = &devMgr->fnDev.object;
            int32_t ret = snprintf_s(devMgr->funcMgr[fnCnt].name, MAX_NAMELEN, MAX_NAMELEN - 1, "%s",
                des->configs[i]->functions[j]->funcName);
            if (ret < 0) {
                HDF_LOGE("%{public}s: snprintf_s failed", __func__);
                return;
            }

            for (uint32_t k = 0; des->configs[i]->functions[j]->fsDescriptors[k] != NULL; k++) {
                intf = (struct UsbInterfaceDescriptor *)des->configs[i]->functions[j]->fsDescriptors[k];
                GetInterfaceInfo(intf, devMgr, fnCnt, des->configs[i]);
            }
            fnCnt++;
        }
    }
}

#define MAX_LIST 32
static int32_t FindEmptyId(void)
{
    int32_t devCnt = 1;
    struct UsbObject *obj = NULL;
    struct UsbObject *temp = NULL;
    if (g_devEntry.next != 0 && !DListIsEmpty(&g_devEntry)) {
        int32_t i;
        for (i = 1; i < MAX_LIST; i++) {
            int32_t isUse = 0;
            DLIST_FOR_EACH_ENTRY_SAFE(obj, temp, &g_devEntry, struct UsbObject, entry) {
                if (obj->objectId == i) {
                    isUse = 1;
                    break;
                }
            }
            if (isUse == 0) {
                break;
            }
        }
        if (i == MAX_LIST) {
            HDF_LOGE("%{public}s:%{public}d too much device created", __func__, __LINE__);
            return -1;
        }
        devCnt = i;
    }
    return devCnt;
}

static int32_t CreatDev(const char *udcName, struct UsbFnDeviceDesc *des, struct UsbFnDeviceMgr *fnDevMgr)
{
    int32_t ret, devCnt;
    struct UsbFnAdapterOps *fnOps = UsbFnAdapterGetOps();
    devCnt = FindEmptyId();
    if (devCnt < 0) {
        return HDF_ERR_IO;
    }

    fnDevMgr->fnDev.object.objectId = devCnt;
    ret = sprintf_s(fnDevMgr->name, MAX_NAMELEN, "g%d", devCnt);
    if (ret < 0) {
        return HDF_ERR_IO;
    }
    ret = strcpy_s(fnDevMgr->udcName, MAX_NAMELEN, udcName);
    if (ret != EOK) {
        return HDF_ERR_IO;
    }
    ret = fnOps->createDevice(udcName, fnDevMgr->name, des);
    if (ret) {
        return HDF_ERR_IO;
    }
    return 0;
}

static uint32_t GetInterfaceNum(struct UsbDescriptorHeader **intf)
{
    uint32_t i;
    uint32_t num = 0;
    struct UsbInterfaceDescriptor *interface = NULL;
    for (i = 0; intf[i] != NULL; i++) {
        if (intf[i]->bDescriptorType == USB_DDK_DT_INTERFACE) {
            interface = (struct UsbInterfaceDescriptor *)intf[i];
            if (interface->bNumEndpoints > 0) {
                num++;
            }
        }
    }
    return num;
}

static int32_t AllocInterfaceAndFuncMgr(struct UsbFnDeviceMgr *fnDevMgr, struct UsbFnDeviceDesc *des)
{
    uint32_t i, j;
    for (i = 0; des->configs[i] != NULL; i++) {
        for (j = 0; des->configs[i]->functions[j] != NULL; j++) {
            if (strncmp(des->configs[i]->functions[j]->funcName, FUNCTION_GENERIC, strlen(FUNCTION_GENERIC))) {
                continue;
            }
            if (des->configs[i]->functions[j]->enable == false) {
                continue;
            }
            fnDevMgr->numFunc++;
            fnDevMgr->fnDev.numInterfaces += GetInterfaceNum(des->configs[i]->functions[j]->fsDescriptors);
        }
    }
    if (fnDevMgr->fnDev.numInterfaces == 0) {
        HDF_LOGE("%{public}s functions is null", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    fnDevMgr->interfaceMgr = UsbFnMemCalloc(fnDevMgr->fnDev.numInterfaces * sizeof(struct UsbFnInterfaceMgr));
    if (fnDevMgr->interfaceMgr == NULL) {
        HDF_LOGE("%{public}s UsbFnMemCalloc failed", __func__);
        return HDF_ERR_IO;
    }

    fnDevMgr->funcMgr = UsbFnMemCalloc(fnDevMgr->numFunc * sizeof(struct UsbFnFuncMgr));
    if (fnDevMgr->funcMgr == NULL) {
        HDF_LOGE("%{public}s UsbFnMemCalloc failed", __func__);
        UsbFnMemFree(fnDevMgr->interfaceMgr);
        return HDF_ERR_IO;
    }
    return 0;
}

static int32_t StartThreadIo(struct UsbFnDeviceMgr *fnDevMgr);
const struct UsbFnDeviceMgr *UsbFnMgrDeviceCreate(
    const char *udcName, struct UsbFnDeviceDesc *des, const struct DeviceResourceNode *node)
{
    int32_t ret;

    struct UsbFnDeviceMgr *fnDevMgr = NULL;
    if (udcName == NULL || des == NULL) {
        HDF_LOGE("%{public}s invalid param.", __func__);
        return NULL;
    }

    fnDevMgr = UsbFnMemCalloc(sizeof(struct UsbFnDeviceMgr));
    if (fnDevMgr == NULL) {
        HDF_LOGE("%{public}s UsbFnMemCalloc failed", __func__);
        return NULL;
    }

    ret = CreatDev(udcName, des, fnDevMgr);
    if (ret) {
        HDF_LOGE("%{public}s CreatDev failed", __func__);
        goto FREE_DEVMGR;
    }
    if (g_devEntry.next == 0) {
        DListHeadInit(&g_devEntry);
    }
    DListInsertTail(&fnDevMgr->fnDev.object.entry, &g_devEntry);
    fnDevMgr->node = node;
    fnDevMgr->des = des;

    ret = AllocInterfaceAndFuncMgr(fnDevMgr, des);
    if (ret == HDF_DEV_ERR_NO_DEVICE) {
        return fnDevMgr;
    } else if (ret != 0) {
        HDF_LOGE("%{public}s AllocInterfaceAndFuncMgr failed", __func__);
        goto FREE_DEVMGR;
    }

    CreateInterface(des, fnDevMgr);
    fnDevMgr->running = true;
    ret = StartThreadIo(fnDevMgr);
    if (ret) {
        HDF_LOGE("%{public}s: StartThreadIo failed", __func__);
        goto FREE_INTF_FUNC_MGR;
    }
    return fnDevMgr;

FREE_INTF_FUNC_MGR:
    UsbFnMemFree(fnDevMgr->interfaceMgr);
    UsbFnMemFree(fnDevMgr->funcMgr);
FREE_DEVMGR:
    UsbFnMemFree(fnDevMgr);
    return NULL;
}

int32_t UsbFnMgrDeviceRemove(struct UsbFnDevice *fnDevice)
{
    int32_t ret;
    int32_t i = 0;
    if (fnDevice == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbFnDeviceMgr *fnDevMgr = (struct UsbFnDeviceMgr *)fnDevice;
    struct UsbFnAdapterOps *fnOps = UsbFnAdapterGetOps();

    fnDevMgr->running = false;
    while (!fnDevMgr->running) {
        i++;
        OsalMSleep(SLEEP_TIME_OUT);
        if (i > SLEEP_TIMES) {
            HDF_LOGE("%{public}s: wait thread exit timeout", __func__);
            break;
        }
    }

    ret = OsalThreadDestroy(&fnDevMgr->thread);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadDestroy failed, ret = %{public}d", __func__, __LINE__, ret);
        return ret;
    }
    ret = fnOps->delDevice(fnDevMgr->name, fnDevMgr->udcName, fnDevMgr->des);
    if (ret) {
        HDF_LOGE("%{public}s:%{public}d UsbFnMgrDeviceRemove failed", __func__, __LINE__);
        return ret;
    }
    if (fnDevice->object.entry.prev != NULL && fnDevice->object.entry.next != NULL) {
        DListRemove(&fnDevice->object.entry);
    } else {
        HDF_LOGE("%{public}s: The node prev or next is NULL", __func__);
    }
    UsbFnCfgMgrUnRegisterAllProp();

    if (fnDevMgr->funcMgr != NULL) {
        UsbFnMemFree(fnDevMgr->funcMgr);
        fnDevMgr->funcMgr = NULL;
    }
    if (fnDevMgr->interfaceMgr != NULL) {
        UsbFnMemFree(fnDevMgr->interfaceMgr);
        fnDevMgr->interfaceMgr = NULL;
    }
    if (fnDevMgr->node) {
        UsbFnCfgMgrFreeUsbFnDeviceDesc(fnDevMgr->des);
        fnDevMgr->des = NULL;
    }
    UsbFnMemFree(fnDevMgr);
    fnDevMgr = NULL;
    return 0;
}

const struct UsbFnDeviceMgr *UsbFnMgrDeviceGet(const char *udcName)
{
    if (udcName == NULL) {
        HDF_LOGE("%{public}s invalid param.", __func__);
        return NULL;
    }
    if (g_devEntry.next == 0 || DListIsEmpty(&g_devEntry)) {
        HDF_LOGE("%{public}s no device created", __func__);
        return NULL;
    }

    struct UsbObject *obj = NULL;
    struct UsbObject *temp = NULL;
    DLIST_FOR_EACH_ENTRY_SAFE(obj, temp, &g_devEntry, struct UsbObject, entry) {
        struct UsbFnDeviceMgr *fnDevMgr = (struct UsbFnDeviceMgr *)obj;
        if (strcmp(udcName, fnDevMgr->udcName) == 0) {
            return fnDevMgr;
        }
    }
    return NULL;
}

int32_t UsbFnMgrDeviceGetState(struct UsbFnDevice *fnDevice, UsbFnDeviceState *devState)
{
    if (fnDevice == NULL || devState == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param.", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbFnDeviceMgr *fnDevMgr = (struct UsbFnDeviceMgr *)fnDevice;
    *devState = fnDevMgr->devState;
    return 0;
}

const struct UsbFnInterfaceMgr *UsbFnMgrDeviceGetInterface(struct UsbFnDevice *fnDevice, uint8_t interfaceIndex)
{
    if (fnDevice == NULL) {
        HDF_LOGE("%{public}s:%{public}d fnDevice is null", __func__, __LINE__);
        return NULL;
    }
    struct UsbFnDeviceMgr *fnDevMgr = (struct UsbFnDeviceMgr *)fnDevice;
    if (interfaceIndex >= fnDevMgr->fnDev.numInterfaces) {
        HDF_LOGE("%{public}s:%{public}d invalid param.", __func__, __LINE__);
        return NULL;
    }
    return &(fnDevMgr->interfaceMgr[interfaceIndex]);
}

static void CollectEventHandle(struct UsbFnEventAll *event, struct UsbFnDeviceMgr *devMgr)
{
    uint8_t i, j;
    struct UsbFnFuncMgr *funcMgr = NULL;
    struct UsbFnInterfaceMgr *intfMgr = NULL;
    struct UsbHandleMgr *handle = NULL;
    event->ep0Num = 0;
    event->epNum = 0;
    for (i = 0; i < devMgr->numFunc; i++) {
        funcMgr = devMgr->funcMgr + i;

        if (funcMgr->fd > 0 && funcMgr->callback != NULL) {
            event->ep0[event->ep0Num] = funcMgr->fd;
            event->ep0Event[event->ep0Num].type = USB_EP0_INVALID;
            event->ep0Num++;
        }
    }
    for (i = 0; i < devMgr->fnDev.numInterfaces; i++) {
        intfMgr = devMgr->interfaceMgr + i;
        if (intfMgr == NULL || intfMgr->isOpen == false || intfMgr->handle == NULL) {
            continue;
        }
        handle = intfMgr->handle;
        for (j = 0; j < handle->numFd; j++) {
            if (handle->fds[j] <= 0) {
                continue;
            }
            event->epx[event->epNum] = handle->fds[j];
            event->reqEvent[event->epNum] = handle->reqEvent[j];
            event->numEvent[event->epNum] = 0;
            event->epNum++;
        }
    }
}

static void HandleEp0IoEvent(const struct UsbFnFuncMgr *funcMgr, const struct UsbFnReqEvent *reqEvent)
{
    struct ReqList *reqList = NULL;
    struct ReqList *temp = NULL;

    DLIST_FOR_EACH_ENTRY_SAFE(reqList, temp, &funcMgr->reqEntry, struct ReqList, entry) {
        if (reqList->buf == reqEvent->buf) {
            HDF_LOGD("%{public}s: req.actual = %{public}d", __func__, reqList->req.actual);
            reqList->req.actual = reqEvent->actual;
            reqList->req.status = -reqEvent->status;
            if (reqList->req.complete) {
                reqList->req.complete(reqList->pipe, &reqList->req);
            } else {
                HDF_LOGE("no complete callback find");
            }
            break;
        }
    }
}

static void HandleEp0CtrlEvent(const struct UsbFnFuncMgr *funcMgr, struct UsbFnCtrlEvent *ctrlEvent)
{
    struct UsbFnDeviceMgr *devMgr = (struct UsbFnDeviceMgr *)funcMgr->object;
    struct UsbFnEvent fnEvnet;
    if (((funcMgr->eventMask) & (1 << ctrlEvent->type)) == 0) {
        return;
    }
    fnEvnet.setup = &ctrlEvent->u.setup;
    fnEvnet.type = ctrlEvent->type;
    fnEvnet.context = funcMgr->context;
    devMgr->devState = ctrlEvent->type;
    if (funcMgr->callback) {
        funcMgr->callback(&fnEvnet);
    } else {
        HDF_LOGE("%{public}s: no callback find event=%{public}d", __func__, fnEvnet.type);
    }
}

static void HandleEpsIoEvent(const struct UsbFnReqEvent *reqEvent, const struct UsbHandleMgr *handle)
{
    struct ReqList *reqList = NULL;
    struct ReqList *temp = NULL;
    DLIST_FOR_EACH_ENTRY_SAFE(reqList, temp, &handle->reqEntry, struct ReqList, entry) {
        if (reqList->buf == reqEvent->buf) {
            reqList->req.actual = reqEvent->actual;
            reqList->req.status = -reqEvent->status;
            if (reqList->req.complete) {
                reqList->req.complete(reqList->pipe, &reqList->req);
            } else {
                HDF_LOGE("no complete callback find");
            }
            break;
        }
    }
}

static struct UsbFnFuncMgr *GetFuncMgr(const struct UsbFnDeviceMgr *devMgr, int32_t ep0)
{
    uint8_t i;

    if (devMgr == NULL) {
        HDF_LOGE("%{public}s:%{public}d devMgr is null.", __func__, __LINE__);
        return NULL;
    }
    struct UsbFnFuncMgr *funcMgr = NULL;
    for (i = 0; i < devMgr->numFunc; i++) {
        funcMgr = devMgr->funcMgr + i;
        if (funcMgr->fd == ep0) {
            break;
        }
    }
    return funcMgr;
}

static struct UsbHandleMgr *GetHandleMgr(const struct UsbFnDeviceMgr *devMgr, int32_t epx)
{
    uint8_t i, j;
    struct UsbHandleMgr *handle = NULL;
    struct UsbFnInterfaceMgr *intfMgr = NULL;

    if (devMgr == NULL) {
        HDF_LOGE("%{public}s:%{public}d devMgr is null.", __func__, __LINE__);
        return NULL;
    }
    for (i = 0; i < devMgr->fnDev.numInterfaces; i++) {
        intfMgr = devMgr->interfaceMgr + i;
        if (!intfMgr->isOpen) {
            continue;
        }
        handle = intfMgr->handle;
        for (j = 0; j < handle->numFd; j++) {
            if (epx == handle->fds[j]) {
                return handle;
            }
        }
    }
    return handle;
}

static void HandleEp0Event(const struct UsbFnDeviceMgr *devMgr, struct UsbFnEventAll event)
{
    uint8_t i;
    struct UsbFnFuncMgr *funcMgr = NULL;
    for (i = 0; i < event.ep0Num; i++) {
        funcMgr = GetFuncMgr(devMgr, event.ep0[i]);
        if (funcMgr == NULL) {
            HDF_LOGE("%{public}s:%{public}d GetFuncMgr failed.", __func__, __LINE__);
            return;
        }
        if (event.ep0Event[i].type == USB_EP0_CTRL_EVENT) {
            HandleEp0CtrlEvent(funcMgr, &event.ep0Event[i].ctrlEvent);
        } else if (event.ep0Event[i].type == USB_EP0_IO_COMPLETED) {
            HandleEp0IoEvent(funcMgr, &event.ep0Event[i].reqEvent);
        }
    }
}

static int32_t UsbFnEventProcess(void *arg)
{
    struct UsbFnDeviceMgr *devMgr = (struct UsbFnDeviceMgr *)arg;
    struct UsbFnAdapterOps *fnOps = UsbFnAdapterGetOps();
    struct UsbFnEventAll event;
    struct UsbHandleMgr *handle = NULL;
    int32_t timeout = SLEEP_TIME_OUT;

    while (true) {
        if (devMgr == NULL || !devMgr->running) {
            break;
        }
        if (memset_s(&event, sizeof(event), 0, sizeof(event)) != EOK) {
            HDF_LOGE("%{public}s:%{public}d memset_s failed", __func__, __LINE__);
            return HDF_FAILURE;
        }

        CollectEventHandle(&event, devMgr);
        if (event.ep0Num + event.epNum == 0) {
            continue;
        }
        int32_t ret = fnOps->pollEvent(&event, timeout);
        if (ret != 0) {
            if (devMgr == NULL || !devMgr->running) {
                break;
            }
            OsalMSleep(1);
            continue;
        }
        HandleEp0Event(devMgr, event);
        for (uint8_t i = 0; i < event.epNum; i++) {
            handle = GetHandleMgr(devMgr, event.epx[i]);
            if (handle == NULL) {
                continue;
            }
            for (uint8_t j = 0; j < event.numEvent[i]; j++) {
                HandleEpsIoEvent(&event.reqEvent[i][j], handle);
            }
        }
    }
    if (devMgr) {
        devMgr->running = true;
    }
    HDF_LOGI("%{public}s, exit", __func__);
    return 0;
}

static int32_t StartThreadIo(struct UsbFnDeviceMgr *fnDevMgr)
{
    int32_t ret;
    struct OsalThreadParam threadCfg;
    ret = memset_s(&threadCfg, sizeof(threadCfg), 0, sizeof(threadCfg));
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memset_s failed", __func__, __LINE__);
        return ret;
    }
    threadCfg.name = "usbfn process";
    threadCfg.priority = OSAL_THREAD_PRI_LOW;
    threadCfg.stackSize = HDF_PROCESS_STACK_SIZE;

    ret = OsalThreadCreate(&fnDevMgr->thread, (OsalThreadEntry)UsbFnEventProcess, (void *)fnDevMgr);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadCreate failed, ret = %{public}d ", __func__, __LINE__, ret);
        return HDF_ERR_DEVICE_BUSY;
    }
    HDF_LOGD("%{public}s: Usb device OsalThreadCreate", __func__);
    ret = OsalThreadStart(&fnDevMgr->thread, &threadCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadStart failed, ret = %{public}d ", __func__, __LINE__, ret);
        return HDF_ERR_DEVICE_BUSY;
    }
    return 0;
}

int32_t UsbFnMgrStartRecvEvent(
    struct UsbFnInterface *interface, uint32_t eventMask, UsbFnEventCallback callback, void *context)
{
    struct UsbFnInterfaceMgr *interfaceMgr = (struct UsbFnInterfaceMgr *)interface;
    struct UsbFnFuncMgr *funcMgr = interfaceMgr->funcMgr;
    if (funcMgr->callback != NULL) {
        HDF_LOGE("%{public}s: callback has Register", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    funcMgr->context = context;
    funcMgr->eventMask = eventMask;
    funcMgr->callback = callback;
    if (funcMgr->fd <= 0) {
        int32_t ret = OpenEp0AndMapAddr(funcMgr);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: OpenEp0AndMapAddr failed, ret = %{public}d ", __func__, ret);
            return HDF_ERR_IO;
        }
    }
    return 0;
}

int32_t UsbFnStopRecvEvent(struct UsbFnInterface *interface)
{
    int32_t ret;
    struct UsbFnAdapterOps *fnOps = UsbFnAdapterGetOps();
    struct UsbFnInterfaceMgr *interfaceMgr = (struct UsbFnInterfaceMgr *)interface;
    struct UsbFnFuncMgr *funcMgr = interfaceMgr->funcMgr;
    ret = fnOps->queueDel(funcMgr->fd);
    if (ret) {
        HDF_LOGE("%{public}s:%{public}d queueDel failed, ret = %{public}d ", __func__, __LINE__, ret);
        return HDF_ERR_DEVICE_BUSY;
    }
    ret = fnOps->closePipe(funcMgr->fd);
    if (ret) {
        HDF_LOGE("%{public}s:%{public}d closePipe failed, ret = %{public}d ", __func__, __LINE__, ret);
        return HDF_ERR_DEVICE_BUSY;
    }
    funcMgr->fd = -1;
    funcMgr->callback = NULL;
    return 0;
}
