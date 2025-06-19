/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "usbd_dispatcher.h"
#include "hdf_slist.h"
#include "osal_mutex.h"
#include "usb_ddk.h"
#include "usb_impl.h"
#include "usb_interface_pool.h"
#include "v1_0/iusbd_subscriber.h"
#include "usbd_wrapper.h"
#include "usb_report_sys_event.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_2 {
int32_t UsbdDispatcher::UsbdAllocFifo(DataFifo *fifo, uint32_t size)
{
    if (fifo == nullptr) {
        HDF_LOGE("%{public}s:fifo is nullptr", __func__);
        return HDF_FAILURE;
    }
    if (!DataFifoIsInitialized(fifo)) {
        void *data = OsalMemAlloc(size);
        if (data == nullptr) {
            HDF_LOGE("%{public}s:OsalMemAlloc failed", __func__);
            return HDF_ERR_MALLOC_FAIL;
        }
        DataFifoInit(fifo, size, data);
    }
    return HDF_SUCCESS;
}

void UsbdDispatcher::UsbdFreeFifo(DataFifo *fifo)
{
    if (fifo == nullptr) {
        HDF_LOGE("%{public}s:fifo is nullptr", __func__);
        return;
    }

    OsalMemFree(fifo->data);
    fifo->data = nullptr;
    DataFifoInit(fifo, 0, nullptr);
}

void UsbdDispatcher::UsbdReadCallback(UsbRequest *req)
{
    if (req == nullptr) {
        HDF_LOGE("%{public}s:req is nullptr!", __func__);
        return;
    }

    UsbIfRequest *reqObj = reinterpret_cast<UsbIfRequest *>(req);
    UsbdRequestASync *dev = static_cast<UsbdRequestASync *>(req->compInfo.userData);
    if (dev == nullptr) {
        HDF_LOGE("%{public}s:invalid param dev is nullptr!", __func__);
        OsalSemPost(&reqObj->hostRequest->sem);
    }
}

void UsbdDispatcher::UsbdWriteCallback(UsbRequest *req)
{
    if (req == nullptr) {
        HDF_LOGE("%{public}s:invalid param req is nullptr!", __func__);
        return;
    }

    int32_t status = req->compInfo.status;
    HDF_LOGI("%{public}s:status is %{public}d!", __func__, status);
}

int32_t UsbdDispatcher::UsbControlSetUp(UsbControlParams *controlParams, UsbControlRequest *controlReq)
{
    if (controlParams == nullptr || controlReq == nullptr) {
        HDF_LOGE("%{public}s:controlParams or controlReq is nullptr", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    controlReq->target = controlParams->target;
    controlReq->reqType = controlParams->reqType;
    controlReq->directon = controlParams->directon;
    controlReq->request = controlParams->request;
    controlReq->value = controlParams->value;
    controlReq->index = controlParams->index;
    controlReq->buffer = controlParams->data;
    controlReq->length = static_cast<uint32_t>(controlParams->size);
    return HDF_SUCCESS;
}

UsbInterface *UsbdDispatcher::GetUsbInterfaceById(const HostDevice *dev, uint8_t interfaceIndex)
{
    if (dev == nullptr || dev->service == nullptr) {
        HDF_LOGE("%{public}s:idx:%{public}u service is nullptr", __func__, interfaceIndex);
        return nullptr;
    }

    UsbInterface *tmpIf = UsbClaimInterface(dev->service->session_, dev->busNum, dev->devAddr, interfaceIndex);
    if (tmpIf == nullptr) {
        HDF_LOGE("%{public}s: UsbClaimInterface failed", __func__);
    }
    return tmpIf;
}

int32_t UsbdDispatcher::GetInterfacePipe(
    const HostDevice *dev, UsbInterface *interface, uint8_t pipeAddr, UsbPipeInfo *pipe)
{
    UsbPipeInfo pipeTmp;
    if (memset_s(&pipeTmp, sizeof(pipeTmp), 0, sizeof(pipeTmp)) != EOK) {
        HDF_LOGE("%{public}s:memset_s failed ", __func__);
        return HDF_FAILURE;
    }

    if (dev == nullptr || interface == nullptr || pipe == nullptr) {
        HDF_LOGE("%{public}s:invalid params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    UsbInterfaceInfo *info = &interface->info;
    if (info == nullptr) {
        HDF_LOGE("%{public}s:invalid interface", __func__);
        return HDF_FAILURE;
    }

    UsbInterfaceHandle *interfaceHandle = UsbImpl::InterfaceIdToHandle(dev, info->interfaceIndex);
    if (interfaceHandle == nullptr) {
        HDF_LOGE("%{public}s:invalid interface handle", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = UsbGetPipeInfo(interfaceHandle, info->curAltSetting, pipeAddr, &pipeTmp);
    if (ret == HDF_SUCCESS && ((pipeTmp.pipeAddress | static_cast<uint8_t>(pipeTmp.pipeDirection)) == pipeAddr)) {
        if (pipe) {
            *pipe = pipeTmp;
        }
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t UsbdDispatcher::GetPipe(const HostDevice *dev, uint8_t interfaceId, uint8_t pipeId, UsbPipeInfo *pipe)
{
    if (dev == nullptr || pipe == nullptr) {
        HDF_LOGE("%{public}s:dev or pipe is nullptr, ifId:%{public}u epId:%{public}u", __func__, interfaceId, pipeId);
        return HDF_ERR_INVALID_PARAM;
    }

    if (interfaceId >= USB_MAX_INTERFACES) {
        HDF_LOGE("%{public}s:interfaceId invalid, ifId:%{public}u epId:%{public}u", __func__, interfaceId, pipeId);
        return HDF_ERR_INVALID_PARAM;
    }

    UsbInterface *interface = dev->iface[interfaceId];
    if (interface == nullptr) {
        HDF_LOGE("%{public}s:interface is nullptr ifId:%{public}u, epId:%{public}u", __func__, interfaceId, pipeId);
        return HDF_FAILURE;
    }

    int32_t ret = GetInterfacePipe(dev, interface, pipeId, pipe);
    return ret;
}

void UsbdDispatcher::UsbdFreeCtrlPipe(HostDevice *dev)
{
    if (dev == nullptr) {
        HDF_LOGE("%{public}s:params dev is nullptr", __func__);
        return;
    }

    OsalMemFree(dev->ctrPipe);
    dev->ctrPipe = nullptr;
}

int32_t UsbdDispatcher::UsbdGetCtrlPipe(HostDevice *dev)
{
    UsbPipeInfo *pipe = static_cast<UsbPipeInfo *>(OsalMemCalloc(sizeof(UsbPipeInfo)));
    if (pipe == nullptr) {
        HDF_LOGE("%{public}s:OsalMemCalloc failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    int32_t ret = UsbGetPipeInfo(dev->ctrDevHandle, dev->ctrIface->info.curAltSetting, 0, pipe);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:get pipe failed ret:%{public}d", __func__, ret);
        OsalMemFree(pipe);
        pipe = nullptr;
        return HDF_FAILURE;
    }

    dev->ctrPipe = pipe;
    return HDF_SUCCESS;
}

UsbdRequestSync *UsbdDispatcher::UsbdFindRequestSync(HostDevice *port, uint8_t interfaceId, uint8_t pipeAddr)
{
    if (port == nullptr) {
        HDF_LOGE("%{public}s:invalid param port is nullptr", __func__);
        return nullptr;
    }

    UsbdRequestSync *req = nullptr;
    HdfSListIterator it;
    bool flag = false;
    OsalMutexLock(&port->reqSyncLock);
    HdfSListIteratorInit(&it, &port->reqSyncList);
    while (HdfSListIteratorHasNext(&it)) {
        req = reinterpret_cast<UsbdRequestSync *>(HdfSListIteratorNext(&it));
        if (req == nullptr) {
            continue;
        }
        if (req->pipe.interfaceId == interfaceId && ((req->pipe.pipeAddress | req->pipe.pipeDirection) == pipeAddr)) {
            flag = true;
            break;
        }
    }
    OsalMutexUnlock(&port->reqSyncLock);

    if (flag) {
        return req;
    }
    return nullptr;
}

UsbdRequestSync *UsbdDispatcher::UsbdRequestSyncAlloc(void)
{
    UsbdRequestSync *req = static_cast<UsbdRequestSync *>(OsalMemCalloc(sizeof(UsbdRequestSync)));
    if (req == nullptr) {
        HDF_LOGE("%{public}s: OsalMemCalloc failed", __func__);
        return req;
    }

    req->request = nullptr;
    req->endPointAddr = 0;
    req->ifHandle = nullptr;
    OsalMutexInit(&req->lock);
    return req;
}

void UsbdDispatcher::UsbRequestParamsWSyncInit(UsbRequestParams *params, int32_t timeout, const UsbPipeInfo *pipe)
{
    if (params == nullptr || pipe == nullptr) {
        HDF_LOGE("%{public}s: params or pipe is nullptr", __func__);
        return;
    }

    params->interfaceId = pipe->interfaceId;
    params->pipeAddress = pipe->pipeDirection | pipe->pipeAddress;
    params->pipeId = pipe->pipeId;
    params->requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    params->timeout = static_cast<uint32_t>(timeout);
    params->dataReq.numIsoPackets = 0;
    params->dataReq.directon = static_cast<UsbRequestDirection>((pipe->pipeDirection >> USB_DIR_OFFSET) & 0x1);
    params->dataReq.length = pipe->maxPacketSize;
}

int32_t UsbdDispatcher::UsbdRequestSyncInit(
    HostDevice *port, UsbInterfaceHandle *ifHandle, UsbPipeInfo *pipe, UsbdRequestSync *requestSync)
{
    if (port == nullptr || requestSync == nullptr || ifHandle == nullptr || pipe == nullptr) {
        HDF_LOGE("%{public}s:invalid params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = memcpy_s(&requestSync->pipe, sizeof(UsbPipeInfo), pipe, sizeof(UsbPipeInfo));
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memcpy_s failed", __func__, ret);
        return ret;
    }

    requestSync->ifHandle = ifHandle;
    requestSync->request = UsbAllocRequest(requestSync->ifHandle, 0, requestSync->pipe.maxPacketSize);
    if (requestSync->request == nullptr) {
        HDF_LOGE("%{public}s:alloc request failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    UsbRequestParamsWSyncInit(&requestSync->params, USB_CTRL_SET_TIMEOUT, &requestSync->pipe);
    requestSync->params.userData = port;
    OsalMutexLock(&port->reqSyncLock);
    HdfSListAdd(&port->reqSyncList, &requestSync->node);
    OsalMutexUnlock(&port->reqSyncLock);
    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::UsbdRequestSyncInitwithLength(HostDevice *port, UsbInterfaceHandle *ifHandle,
    UsbPipeInfo *pipe, int32_t length, UsbdRequestSync *requestSync)
{
    if (port == nullptr || requestSync == nullptr || ifHandle == nullptr || pipe == nullptr) {
        HDF_LOGE("%{public}s:invalid params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = memcpy_s(&requestSync->pipe, sizeof(UsbPipeInfo), pipe, sizeof(UsbPipeInfo));
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memcpy_s failed", __func__, ret);
        return ret;
    }

    requestSync->ifHandle = ifHandle;
    requestSync->request = UsbAllocRequest(requestSync->ifHandle, 0, length);
    if (requestSync->request == nullptr) {
        HDF_LOGE("%{public}s:alloc request failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    UsbRequestParamsWSyncInit(&requestSync->params, USB_CTRL_SET_TIMEOUT, &requestSync->pipe);
    requestSync->params.userData = port;
    OsalMutexLock(&port->reqSyncLock);
    HdfSListAdd(&port->reqSyncList, &requestSync->node);
    OsalMutexUnlock(&port->reqSyncLock);
    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::UsbdRequestSyncRelease(UsbdRequestSync *requestSync)
{
    int32_t ret = HDF_SUCCESS;
    if (requestSync != nullptr) {
        OsalMutexLock(&requestSync->lock);
        if (requestSync->request != nullptr) {
            ret = UsbFreeRequest(requestSync->request);
            if (ret != HDF_SUCCESS) {
                HDF_LOGW("%{public}s:UsbFreeRequest failed", __func__);
            }
            requestSync->request = nullptr;
        }
        OsalMutexUnlock(&requestSync->lock);
        OsalMemFree(requestSync);
    }
    return ret;
}

void UsbdDispatcher::UsbRequestParamsInit(UsbRequestParams *params, int32_t timeout)
{
    if (params == nullptr) {
        HDF_LOGE("%{public}s:params is nullptr", __func__);
        return;
    }

    params->interfaceId = USB_CTRL_INTERFACE_ID;
    params->pipeAddress = 0;
    params->pipeId = 0;
    params->requestType = USB_REQUEST_PARAMS_CTRL_TYPE;
    params->timeout = static_cast<uint32_t>(timeout);
}

int32_t UsbdDispatcher::CtrlTranParamGetReqType(HdfSBuf *data, UsbControlParams *pCtrParams, uint32_t requestType)
{
    if (data == nullptr || pCtrParams == nullptr) {
        HDF_LOGE("%{public}s:param failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    uint8_t *buffer = nullptr;
    uint32_t length = 0;
    int32_t target = requestType & USB_RECIP_MASK;
    int32_t direction = (requestType >> DIRECTION_OFFSET_7) & ENDPOINT_DIRECTION_MASK;
    int32_t cmdType = (requestType >> CMD_OFFSET_5) & CMD_TYPE_MASK;
    if (direction == USB_REQUEST_DIR_TO_DEVICE) {
        if (!HdfSbufReadBuffer(data, (const void **)(&buffer), &length)) {
            HDF_LOGE("%{public}s:hdf sbuf Read failed", __func__);
            return HDF_FAILURE;
        }
    } else {
        length = MAX_CONTROL_BUFF_SIZE;
        buffer = static_cast<uint8_t *>(OsalMemCalloc(length));
        if (buffer == nullptr) {
            HDF_LOGE("%{public}s:OsalMemCalloc failed length = %{public}u", __func__, length);
            return HDF_ERR_MALLOC_FAIL;
        }
    }
    pCtrParams->target = static_cast<UsbRequestTargetType>(target);
    pCtrParams->directon = static_cast<UsbRequestDirection>(direction);
    pCtrParams->reqType = static_cast<UsbControlRequestType>(cmdType);
    pCtrParams->size = length;
    pCtrParams->data = buffer;
    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::CtrlTransferParamInit(HdfSBuf *data, UsbControlParams *pCtrParams, int32_t *timeout)
{
    if (data == nullptr || pCtrParams == nullptr) {
        HDF_LOGE("%{public}s:data or pCtrParams is nullptr", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t requestType;
    if (!HdfSbufReadInt32(data, &requestType)) {
        HDF_LOGE("%{public}s:failed to read the requestType from data", __func__);
        return HDF_ERR_IO;
    }

    int32_t requestCmd;
    if (!HdfSbufReadInt32(data, &requestCmd)) {
        HDF_LOGE("%{public}s:Failed to read the requestCmd from data", __func__);
        return HDF_ERR_IO;
    }

    int32_t value;
    if (!HdfSbufReadInt32(data, &value)) {
        HDF_LOGE("%{public}s:Failed to read the value from data", __func__);
        return HDF_ERR_IO;
    }

    int32_t index;
    if (!HdfSbufReadInt32(data, &index)) {
        HDF_LOGE("%{public}s:Failed to read the index from data", __func__);
        return HDF_ERR_IO;
    }

    if (!HdfSbufReadInt32(data, timeout)) {
        HDF_LOGE("%{public}s:Failed to read the timeout from data", __func__);
        return HDF_ERR_IO;
    }

    pCtrParams->request = static_cast<uint8_t>(requestCmd);
    pCtrParams->value = value;
    pCtrParams->index = index;
    int32_t ret = CtrlTranParamGetReqType(data, pCtrParams, requestType);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:CtrlTransferParamInit failed:%{public}d", __func__, ret);
        OsalMemFree(pCtrParams->data);
        pCtrParams->data = nullptr;
    }
    return ret;
}

void UsbdDispatcher::UsbdReleaseInterfaces(HostDevice *dev)
{
    if (dev == nullptr) {
        HDF_LOGE("%{public}s: %{public}d invalid param dev is nullptr", __func__, __LINE__);
        return;
    }

    for (int32_t i = 0; i < USB_MAX_INTERFACES; ++i) {
        if (dev->iface[i] != nullptr) {
            UsbReleaseInterface(dev->iface[i]);
            dev->iface[i] = nullptr;
        }
    }
    HDF_LOGI("%{public}s: %{public}d release iface success.", __func__, __LINE__);
    if (dev->ctrIface != nullptr) {
        UsbReleaseInterface(dev->ctrIface);
        dev->ctrIface = nullptr;
    }
}

void UsbdDispatcher::UsbdCloseInterfaces(HostDevice *dev)
{
    if (dev == nullptr) {
        HDF_LOGE("%{public}s: %{public}d invalid param dev is nullptr", __func__, __LINE__);
        return;
    }

    for (int32_t i = 0; i < USB_MAX_INTERFACES; ++i) {
        if (dev->devHandle[i] != nullptr) {
            UsbCloseInterface(dev->devHandle[i], false);
            dev->devHandle[i] = nullptr;
        }
    }
    if (dev->ctrDevHandle != nullptr) {
        UsbCloseInterface(dev->ctrDevHandle, false);
        dev->ctrDevHandle = nullptr;
    }
}

int32_t UsbdDispatcher::UsbdOpenInterfaces(HostDevice *dev)
{
    if (dev == nullptr) {
        HDF_LOGE("%{public}s: %{public}d invalid param dev is nullptr", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret =
        memset_s(dev->devHandle, sizeof(uint8_t) * USB_MAX_INTERFACES, 0, sizeof(uint8_t) * USB_MAX_INTERFACES);
    if (ret != EOK) {
        HDF_LOGE("%{public}s:memset_s failed ", __func__);
        return HDF_FAILURE;
    }
    dev->ctrDevHandle = UsbOpenInterface(dev->ctrIface);
    if (dev->ctrDevHandle == nullptr) {
        HDF_LOGE("%{public}s:ctrDevHandle UsbOpenInterface nullptr", __func__);
        UsbdCloseInterfaces(dev);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void UsbdDispatcher::RemoveDevFromService(UsbImpl *service, HostDevice *port)
{
    if (service == nullptr || port == nullptr) {
        HDF_LOGE("%{public}s: service or port is nullptr", __func__);
        return;
    }

    HdfSListIterator it;
    HostDevice *tempPort = nullptr;
    OsalMutexLock(&service->lock_);
    HdfSListIteratorInit(&it, &service->devList_);
    while (HdfSListIteratorHasNext(&it)) {
        tempPort = reinterpret_cast<HostDevice *>(HdfSListIteratorNext(&it));
        if (tempPort == nullptr) {
            continue;
        }
        if (tempPort->busNum == port->busNum && tempPort->devAddr == port->devAddr) {
            HdfSListIteratorRemove(&it);
            break;
        }
    }
    OsalMutexUnlock(&service->lock_);
}

int32_t UsbdDispatcher::UsbdClaimInterfaces(HostDevice *dev)
{
    if (dev == nullptr) {
        HDF_LOGE("%{public}s: %{public}d invalid param dev is nullptr", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (memset_s(dev->iface, sizeof(uint8_t) * USB_MAX_INTERFACES, 0, sizeof(uint8_t) * USB_MAX_INTERFACES) != EOK) {
        HDF_LOGE("%{public}s:memset_s failed", __func__);
        return HDF_FAILURE;
    }

    dev->ctrIface = GetUsbInterfaceById(const_cast<const HostDevice *>(dev), USB_CTRL_INTERFACE_ID);
    if (dev->ctrIface == nullptr) {
        HDF_LOGE("%{public}s:GetUsbInterfaceById nullptr", __func__);
        UsbdReleaseInterfaces(dev);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::ReturnGetPipes(int32_t ret, HostDevice *dev)
{
    UsbdCloseInterfaces(dev);
    UsbdReleaseInterfaces(dev);
    dev->service->session_ = nullptr;
    return ret;
}

int32_t UsbdDispatcher::ReturnOpenInterfaces(int32_t ret, HostDevice *dev)
{
    UsbdReleaseInterfaces(dev);
    dev->service->session_ = nullptr;
    return ret;
}

int32_t UsbdDispatcher::ReturnClainInterfaces(int32_t ret, HostDevice *dev)
{
    dev->service->session_ = nullptr;
    return ret;
}

int32_t UsbdDispatcher::UsbdInit(HostDevice *dev)
{
    if (dev == nullptr) {
        HDF_LOGE("%{public}s:invalid param dev", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (dev->initFlag) {
        HDF_LOGE("%{public}s:initFlag is true", __func__);
        return HDF_SUCCESS;
    }

    int32_t ret = UsbInitHostSdk(nullptr);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:UsbInitHostSdk failed", __func__);
        return HDF_FAILURE;
    }

    if (dev->service == nullptr) {
        HDF_LOGE("%{public}s:dev->service is nullptr", __func__);
        return HDF_FAILURE;
    }

    dev->service->session_ = nullptr;

    ret = UsbdClaimInterfaces(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:UsbdClaimInterfaces failed ret:%{public}d", __func__, ret);
        return ReturnClainInterfaces(ret, dev);
    }

    ret = UsbdOpenInterfaces(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:UsbdOpenInterfaces failed ret:%{public}d", __func__, ret);
        return ReturnOpenInterfaces(ret, dev);
    }

    ret = UsbdGetCtrlPipe(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:UsbdGetPipes failed ret:%{public}d", __func__, ret);
        return ReturnGetPipes(ret, dev);
    }
    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::UsbdRequestASyncRelease(UsbdRequestASync *request)
{
    if (request == nullptr) {
        HDF_LOGE("%{public}s:request is nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = HDF_SUCCESS;
    OsalMutexLock(&request->lock);
    UsbImpl::UsbdRequestASyncReleaseData(request);
    if (request->reqMsg.request != nullptr) {
        ret = UsbFreeRequest(request->reqMsg.request);
        request->reqMsg.request = nullptr;
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:UsbFreeRequest failed", __func__);
        }
    }
    OsalMutexUnlock(&request->lock);
    OsalMemFree(request);
    return ret;
}

int32_t UsbdDispatcher::UsbdBulkASyncReqRelease(UsbdBulkASyncReqList *list)
{
    for (int32_t i = 0; i < USBD_BULKASYNCREQ_NUM_MAX; ++i) {
        UsbFreeRequest(list->node[i].request);
        list->node[i].request = nullptr;
    }
    DListHeadInit(&list->eList);
    DListHeadInit(&list->uList);
    OsalMutexDestroy(&list->elock);
    OsalMutexDestroy(&list->ulock);
    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::UsbdBulkASyncListRelease(UsbdBulkASyncList *list)
{
    UsbdBulkASyncReqRelease(&list->rList);
    OsalMutexDestroy(&list->asmHandle.lock);
    OsalMemFree(list);
    return HDF_SUCCESS;
}

void UsbdDispatcher::UsbdRelease(HostDevice *dev)
{
    if (dev == nullptr) {
        HDF_LOGE("%{public}s: %{public}d invalid param dev is nullptr", __func__, __LINE__);
        return;
    }

    UsbdCloseInterfaces(dev);
    UsbdReleaseInterfaces(dev);
    UsbdFreeCtrlPipe(dev);
    HDF_LOGI("%{public}s: %{public}d interface,pipe free success", __func__, __LINE__);

    UsbImpl::UsbdRequestSyncReleaseList(dev);
    HDF_LOGI("%{public}s: %{public}d sync request release success", __func__, __LINE__);

    UsbImpl::UsbdRequestASyncReleaseList(dev);
    UsbImpl::UsbdBulkASyncListReleasePort(dev);

    if (dev->ctrlReq != nullptr) {
        UsbFreeRequest(dev->ctrlReq);
        dev->ctrlReq = nullptr;
    }
    UsbExitHostSdk(dev->service->session_);
    dev->service->session_ = nullptr;
    OsalMutexDestroy(&dev->writeLock);
    OsalMutexDestroy(&dev->readLock);
    OsalMutexDestroy(&dev->lock);
    OsalMutexDestroy(&dev->requestLock);
    OsalMutexDestroy(&dev->reqSyncLock);
    OsalMutexDestroy(&dev->reqASyncLock);
    dev->busNum = 0;
    dev->devAddr = 0;
    dev->initFlag = false;
}

int32_t UsbdDispatcher::UsbdMallocAndFill(uint8_t *&dataAddr, const std::vector<uint8_t> &data)
{
    uint32_t length = sizeof(uint8_t) * data.size();
    if (length == 0) {
        HDF_LOGI("%{public}s: data is empty", __func__);
        return HDF_SUCCESS;
    }

    dataAddr = static_cast<uint8_t *>(OsalMemCalloc(length));
    if (dataAddr == nullptr) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed", __func__);
        return HDF_FAILURE;
    }

    void *dataAddrCovert = static_cast<void *>(dataAddr);
    int32_t err = memcpy_s(dataAddrCovert, length, data.data(), length);
    if (err != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        OsalMemFree(dataAddr);
        dataAddr = nullptr;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::FillReqAyncParams(
    UsbdRequestASync *userData, UsbPipeInfo *pipe, UsbRequestParams *params, const uint8_t *buffer, uint32_t length)
{
    if (userData == nullptr || pipe == nullptr || params == nullptr) {
        HDF_LOGE("%{public}s:invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    bool bWrite = (pipe->pipeDirection == USB_PIPE_DIRECTION_OUT);
    params->interfaceId = pipe->interfaceId;
    params->pipeAddress = pipe->pipeDirection | pipe->pipeAddress;
    params->pipeId = pipe->pipeId;
    params->requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    params->timeout = USB_CTRL_SET_TIMEOUT;
    params->dataReq.numIsoPackets = 0;
    params->userData = static_cast<void *>(userData);
    params->dataReq.length = length;
    params->dataReq.directon = static_cast<UsbRequestDirection>((pipe->pipeDirection >> USB_PIPE_DIR_OFFSET) & 0x1);
    if (bWrite) {
        params->callback = UsbdWriteCallback;
        params->dataReq.buffer = const_cast<uint8_t *>(buffer);
    } else {
        params->callback = UsbdReadCallback;
        params->dataReq.length = length;
    }
    return HDF_SUCCESS;
}

UsbdRequestASync *UsbdDispatcher::UsbdRequestASyncAlloc(void)
{
    UsbdRequestASync *req = static_cast<UsbdRequestASync *>(OsalMemCalloc(sizeof(UsbdRequestASync)));
    if (req == nullptr) {
        HDF_LOGE("%{public}s: OsalMemCalloc failed", __func__);
        return req;
    }

    req->reqMsg.request = nullptr;
    req->endPointAddr = 0;
    req->ifHandle = nullptr;
    req->status = 0;
    OsalMutexInit(&req->lock);
    return req;
}

int32_t UsbdDispatcher::UsbdRequestASyncInit(
    HostDevice *port, UsbInterfaceHandle *ifHandle, UsbPipeInfo *pipe, UsbdRequestASync *request)
{
    if (port == nullptr || request == nullptr || ifHandle == nullptr || pipe == nullptr) {
        HDF_LOGE("%{public}s:invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = memcpy_s(&request->pipe, sizeof(UsbPipeInfo), pipe, sizeof(UsbPipeInfo));
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memcpy_s failed", __func__, ret);
        return ret;
    }

    request->ifHandle = ifHandle;
    request->reqMsg.request = UsbAllocRequest(request->ifHandle, 0, request->pipe.maxPacketSize);
    if (request->reqMsg.request == nullptr) {
        HDF_LOGE("%{public}s:alloc request failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    FillReqAyncParams(request, &request->pipe, &request->params, nullptr, 0);
    OsalMutexLock(&port->reqASyncLock);
    HdfSListAddTail(&port->reqASyncList, &request->node);
    OsalMutexUnlock(&port->reqASyncLock);
    return HDF_SUCCESS;
}

UsbdRequestASync *UsbdDispatcher::UsbdRequestASyncCreatAndInsert(
    HostDevice *port, uint8_t interfaceId, uint8_t pipeAddr)
{
    UsbPipeInfo pipe;
    if (memset_s(&pipe, sizeof(UsbPipeInfo), 0, sizeof(UsbPipeInfo)) != EOK) {
        HDF_LOGE("%{public}s:memset_s failed", __func__);
        return nullptr;
    }

    int32_t ret = GetPipe(port, interfaceId, pipeAddr, &pipe);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get pipe info failed interfaceId=%{public}d, pipeAddr=%{public}d", __func__, interfaceId,
            pipeAddr);
        return nullptr;
    }

    UsbInterfaceHandle *ifHandle = UsbImpl::InterfaceIdToHandle(port, interfaceId);
    if (ifHandle == nullptr) {
        HDF_LOGE("%{public}s:get interface handle failed", __func__);
        return nullptr;
    }

    UsbdRequestASync *req = UsbdRequestASyncAlloc();
    if (req == nullptr) {
        HDF_LOGE("%{public}s: UsbdRequestASyncAlloc failed", __func__);
        return req;
    }
    ret = UsbdRequestASyncInit(port, ifHandle, &pipe, req);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:UsbdRequestASyncInit failed:%{public}d", __func__, ret);
        UsbdRequestASyncRelease(req);
        req = nullptr;
        return req;
    }
    return req;
}

int32_t UsbdDispatcher::HostDeviceInit(HostDevice *port)
{
    if (port == nullptr) {
        HDF_LOGE("%{public}s:port is nullptr", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    port->busNum = 0;
    port->devAddr = 0;
    port->initFlag = false;
    port->interfaceCnt = 0;
    if (OsalMutexInit(&port->lock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:init lock failed!", __func__);
        return HDF_FAILURE;
    }

    if (OsalMutexInit(&port->requestLock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:init requestLock failed!", __func__);
        return HDF_FAILURE;
    }

    if (OsalMutexInit(&port->writeLock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:init writeLock failed!", __func__);
        return HDF_FAILURE;
    }

    if (OsalMutexInit(&port->readLock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:init readLock failed!", __func__);
        return HDF_FAILURE;
    }

    if (OsalMutexInit(&port->reqSyncLock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:init reqSyncLock failed!", __func__);
        return HDF_FAILURE;
    }

    if (OsalMutexInit(&port->reqASyncLock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:init reqASyncLock failed!", __func__);
        return HDF_FAILURE;
    }

    HdfSListInit(&port->requestQueue);
    HdfSListInit(&port->reqSyncList);
    HdfSListInit(&port->reqASyncList);
    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::HostDeviceCreate(HostDevice **port)
{
    if (port == nullptr) {
        HDF_LOGE("%{public}s:invalid param port is nullptr", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    HostDevice *tmp = static_cast<HostDevice *>(OsalMemCalloc(sizeof(HostDevice)));
    if (tmp == nullptr) {
        HDF_LOGE("%{public}s:OsalMemCalloc failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    int32_t ret = HostDeviceInit(tmp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:HostDeviceInit failed!", __func__);
        OsalMemFree(tmp);
        tmp = nullptr;
        return ret;
    }

    tmp->initFlag = false;
    *port = tmp;
    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::FunAttachDevice(HostDevice *port, HdfSBuf *data, HdfSBuf *reply)
{
    if (port == nullptr) {
        HDF_LOGE("%{public}s:mangf invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (port->initFlag) {
        HDF_LOGD("%{public}s:device is already on flag:%{public}d bus:%{public}d dev:%{public}d", __func__,
            port->initFlag, port->busNum, port->devAddr);
        return HDF_SUCCESS;
    }

    int32_t ret = HDF_SUCCESS;
    do {
        ret = UsbdInit(port);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:UsbInit failed ret:%{public}d", __func__, ret);
            RemoveDevFromService(port->service, port);
            UsbdRelease(port);
            OsalMemFree(port);
            return ret;
        }
        ret = UsbdAllocFifo(&port->readFifo, READ_BUF_SIZE);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:UsbAllocFifo failed ret:%{public}d", __func__, ret);
            ret = HDF_ERR_INVALID_PARAM;
            break;
        }
        if (ret == HDF_SUCCESS) {
            port->initFlag = true;
            HDF_LOGI("%{public}s:UsbOpen success", __func__);
        } else {
            HDF_LOGE("%{public}s:UsbOpen fail:%{public}d", __func__, ret);
        }
        return ret;
    } while (0);

    UsbdFreeFifo(&port->readFifo);
    UsbdRelease(port);
    RemoveDevFromService(port->service, port);
    OsalMemFree(port);
    return ret;
}

int32_t UsbdDispatcher::UsbdDeviceCreateAndAttach(const sptr<UsbImpl> &service, uint8_t busNum, uint8_t devAddr)
{
    HostDevice *port = service->FindDevFromService(busNum, devAddr);
    if (port != nullptr) {
        HDF_LOGI("%{public}s:device already add", __func__);
        return HDF_ERR_DEVICE_BUSY;
    }
    int32_t ret = HostDeviceCreate(&port);
    if (ret == HDF_SUCCESS) {
        port->busNum = busNum;
        port->devAddr = devAddr;
        port->service = service;
        OsalMutexLock(&service->lock_);
        HdfSListAdd(&service->devList_, &port->node);
        OsalMutexUnlock(&service->lock_);
        ret = FunAttachDevice(port, nullptr, nullptr);
        if (ret != HDF_SUCCESS) {
            HDF_LOGW("%{public}s:FunAttachDevice error ret:%{public}d", __func__, ret);
            UsbReportSysEvent::ReportUsbRecognitionFailSysEvent("UsbdDeviceCreateAndAttach", ret,
                "FunAttachDevice error");
        }
        port = nullptr;
    } else {
        HDF_LOGE("%{public}s:createdevice error ret:%{public}d", __func__, ret);
        UsbReportSysEvent::ReportUsbRecognitionFailSysEvent("UsbdDeviceCreateAndAttach", ret, "createdevice error");
    }
    return ret;
}

int32_t UsbdDispatcher::FunDetachDevice(HostDevice *port, HdfSBuf *data)
{
    if (port == nullptr) {
        HDF_LOGE("%{public}s:invalid param port", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    RemoveDevFromService(port->service, port);
    UsbdRelease(port);
    UsbdFreeFifo(&port->readFifo);
    OsalMemFree(port);
    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::UsbdDeviceDettach(UsbImpl *service, uint8_t busNum, uint8_t devAddr)
{
    if (service == nullptr) {
        HDF_LOGE("%{public}s:invalid param service!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    HostDevice *port = service->FindDevFromService(busNum, devAddr);
    if (port == nullptr) {
        HDF_LOGE("%{public}s:FindDevFromService failed", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    int32_t ret = FunDetachDevice(port, nullptr);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: %{public}d FunDetachDevice failed", __func__, ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

HostDevice *UsbdDispatcher::UsbdFindDevForBusNum(UsbImpl *service, uint8_t busNum)
{
    if (service == nullptr) {
        HDF_LOGE("%{public}s: service is nullptr", __func__);
        return nullptr;
    }

    uint8_t flag = false;
    HdfSListIterator it;
    HostDevice *tempPort = nullptr;
    OsalMutexLock(&service->lock_);
    HdfSListIteratorInit(&it, &service->devList_);
    while (HdfSListIteratorHasNext(&it)) {
        tempPort = reinterpret_cast<HostDevice *>(HdfSListIteratorNext(&it));
        if (!tempPort) {
            continue;
        }
        if (tempPort->busNum == busNum) {
            HdfSListIteratorRemove(&it);
            flag = true;
            break;
        }
    }
    OsalMutexUnlock(&service->lock_);
    if (flag) {
        return tempPort;
    }
    return nullptr;
}

int32_t UsbdDispatcher::UsbdRemoveBusDev(UsbImpl *service, uint8_t busNum, const sptr<IUsbdSubscriber> &subscriber)
{
    HostDevice *tempPort = nullptr;
    USBDeviceInfo info;
    int32_t ret = HDF_FAILURE;

    while (1) {
        tempPort = UsbdDispatcher::UsbdFindDevForBusNum(service, busNum);
        if (!tempPort) {
            break;
        }
        info = {ACT_DEVDOWN, tempPort->busNum, tempPort->devAddr};
        ret = subscriber->DeviceEvent(info);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s failed to notify subscriber, ret: %{public}d", __func__, ret);
            return ret;
        }
        UsbdRelease(tempPort);
        UsbdFreeFifo(&tempPort->readFifo);
        OsalMemFree(tempPort);
    }
    return ret;
}

int32_t UsbdDispatcher::UsbdBulkASyncReqInit(UsbdBulkASyncReqList *list, UsbdBulkASyncList *pList)
{
    int32_t ret = HDF_SUCCESS;
    int32_t i = 0;
    DListHeadInit(&list->eList);
    DListHeadInit(&list->uList);
    OsalMutexInit(&list->elock);
    OsalMutexInit(&list->ulock);
    for (i = 0; i < USBD_BULKASYNCREQ_NUM_MAX; ++i) {
        list->node[i].request = UsbAllocRequest(pList->ifHandle, 0, pList->pipe.maxPacketSize);
        if (!list->node[i].request) {
            HDF_LOGE("%{public}s:alloc request failed i:%{public}d", __func__, i);
            ret = HDF_ERR_MALLOC_FAIL;
            break;
        }
        list->node[i].list = list;
        list->node[i].id = i;
        DListInsertTail(&list->node[i].node, &list->eList);
        pList->params.userData = static_cast<void *>(&list->node[i]);
    }

    if (i != USBD_BULKASYNCREQ_NUM_MAX) {
        for (; i >= 0; --i) {
            UsbFreeRequest(list->node[i].request);
            list->node[i].request = nullptr;
        }
        DListHeadInit(&list->eList);
        DListHeadInit(&list->uList);
        OsalMutexDestroy(&list->elock);
        OsalMutexDestroy(&list->ulock);
    }
    list->pList = pList;
    return ret;
}

UsbdBulkASyncList *UsbdDispatcher::UsbdBulkASyncListAlloc(HostDevice *port, uint8_t ifId, uint8_t epId)
{
    UsbPipeInfo pipe;
    if (memset_s(&pipe, sizeof(UsbPipeInfo), 0, sizeof(UsbPipeInfo)) != EOK) {
        HDF_LOGE("%{public}s:memset_s failed", __func__);
        return nullptr;
    }

    int32_t ret = GetPipe(port, ifId, epId, &pipe);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:GetPipe failed, ret:%{public}d", __func__, ret);
        return nullptr;
    }

    UsbInterfaceHandle *ifHandle = UsbImpl::InterfaceIdToHandle(port, ifId);
    if (ifHandle == nullptr) {
        HDF_LOGE("%{public}s:get interface handle failed", __func__);
        return nullptr;
    }

    UsbdBulkASyncList *bulkAsyncList = reinterpret_cast<UsbdBulkASyncList *>(OsalMemCalloc(sizeof(UsbdBulkASyncList)));
    if (bulkAsyncList == nullptr) {
        HDF_LOGE("%{public}s:malloc failed!", __func__);
        return nullptr;
    }
    bulkAsyncList->ifId = ifId;
    bulkAsyncList->epId = epId;
    bulkAsyncList->instance = port;
    OsalMutexInit(&bulkAsyncList->asmHandle.lock);
    bulkAsyncList->pipe = pipe;
    bulkAsyncList->ifHandle = ifHandle;
    UsbdBulkASyncReqFillParams(&bulkAsyncList->pipe, &bulkAsyncList->params, nullptr);
    ret = UsbdBulkASyncReqInit(&bulkAsyncList->rList, bulkAsyncList);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbdBulkASyncReqInit failed ret:%{public}d", __func__, ret);
        UsbdBulkASyncListRelease(bulkAsyncList);
        bulkAsyncList = nullptr;
        return bulkAsyncList;
    }

    return bulkAsyncList;
}

int32_t UsbdDispatcher::UsbdBulkASyncReqNodeSetNoUse(UsbdBulkASyncReqNode *db)
{
    OsalMutexLock(&db->list->elock);
    db->use = USBD_REQNODE_NOUSE;
    DListInsertTail(&db->node, &db->list->eList);
    OsalMutexUnlock(&db->list->elock);
    return HDF_SUCCESS;
}

UsbdBulkASyncReqNode *UsbdDispatcher::UsbdBulkASyncReqGetENode(UsbdBulkASyncReqList *list)
{
    OsalMutexLock(&list->elock);
    if (DListIsEmpty(&list->eList)) {
        OsalMutexUnlock(&list->elock);
        HDF_LOGE("%{public}s:invalid param", __func__);
        return nullptr;
    }
    UsbdBulkASyncReqNode *ptr = DLIST_FIRST_ENTRY(&list->eList, UsbdBulkASyncReqNode, node);
    if (ptr != nullptr) {
        ptr->use = USBD_REQNODE_OTHER;
        if (ptr->node.prev != NULL && ptr->node.next != NULL) {
            DListRemove(&ptr->node);
        } else {
            HDF_LOGE("%{public}s: The node prev or next is NULL", __func__);
        }
    }
    OsalMutexUnlock(&list->elock);
    return ptr;
}

int32_t UsbdDispatcher::UsbdBulkReadRemoteCallback(
    const sptr<IUsbdBulkCallback> &service, int32_t status, UsbdBufferHandle *handle)
{
    if (service == nullptr || handle == nullptr) {
        HDF_LOGE("%{public}s:invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    OsalMutexLock(&handle->lock);
    uint8_t flag = handle->cbflg;
    handle->cbflg = 1;
    int32_t actLength = static_cast<int32_t>(handle->rcur);
    OsalMutexUnlock(&handle->lock);
    if (flag) {
        return HDF_SUCCESS;
    }
    int32_t ret = service->OnBulkReadCallback(status, actLength);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:OnBulkReadCallback failed, ret=%{public}d", __func__, ret);
    }
    return ret;
}

int32_t UsbdDispatcher::UsbdBulkWriteRemoteCallback(
    const sptr<IUsbdBulkCallback> &service, int32_t status, UsbdBufferHandle *handle)
{
    if (service == nullptr || handle == nullptr) {
        HDF_LOGE("%{public}s:invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    OsalMutexLock(&handle->lock);
    uint8_t flag = handle->cbflg;
    handle->cbflg = 1;
    int32_t actLength = static_cast<int32_t>(handle->cur);
    OsalMutexUnlock(&handle->lock);
    if (flag) {
        return HDF_SUCCESS;
    }

    int32_t ret = service->OnBulkWriteCallback(status, actLength);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:OnBulkWriteCallback failed, ret=%{public}d", __func__, ret);
    }
    return ret;
}

int32_t UsbdDispatcher::UsbdBulkASyncPutAsmData(UsbdBufferHandle *handle, uint8_t *buffer, uint32_t len)
{
    if (handle == nullptr || buffer == nullptr || len < 1) {
        HDF_LOGE("%{public}s:invalid param len:%{public}d", __func__, len);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = HDF_SUCCESS;
    OsalMutexLock(&handle->lock);
    do {
        if (handle->fd < 1) {
            HDF_LOGE("%{public}s:fd error, handle->fd:%{public}d", __func__, handle->fd);
            ret = HDF_ERR_BAD_FD;
            break;
        }
        uint32_t tlen = (handle->size > handle->rcur) ? (handle->size - handle->rcur) : 0;
        tlen = tlen < len ? tlen : len;
        if (tlen > 0) {
            ret = memcpy_s(handle->starAddr + handle->rcur, tlen, buffer, len);
            if (ret != EOK) {
                HDF_LOGE("%{public}s:%{public}d memcpy_s failed", __func__, ret);
                OsalMutexUnlock(&handle->lock);
                return ret;
            }

            handle->rcur += tlen;
        }
    } while (0);
    OsalMutexUnlock(&handle->lock);
    return ret;
}

int32_t UsbdDispatcher::UsbdBulkAsyncGetAsmData(
    UsbdBufferHandle *handle, UsbRequestParams *params, uint16_t maxPacketSize)
{
    if (handle == nullptr || params == nullptr || handle->size < 1 || maxPacketSize < 1) {
        HDF_LOGE("%{public}s:invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = HDF_ERR_INVALID_PARAM;
    OsalMutexLock(&handle->lock);
    if (handle->cur < handle->size) {
        params->dataReq.length =
            (handle->size - handle->cur) < maxPacketSize ? (handle->size - handle->cur) : maxPacketSize;
        params->dataReq.buffer = handle->starAddr + handle->cur;
        handle->cur += params->dataReq.length;
        ret = HDF_SUCCESS;
    } else {
        params->dataReq.length = 0;
        params->dataReq.buffer = nullptr;
        HDF_LOGE("%{public}s:invalid param", __func__);
        ret = HDF_DEV_ERR_NODATA;
    }
    OsalMutexUnlock(&handle->lock);
    return ret;
}

int32_t UsbdDispatcher::UsbdBulkAsyncGetAsmReqLen(UsbdBufferHandle *handle, uint32_t *reqLen, uint16_t maxPacketSize)
{
    if (handle == nullptr || reqLen == nullptr || handle->size < 1 || maxPacketSize < 1) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t tlen = 0;
    OsalMutexLock(&handle->lock);
    if (handle->cur < handle->size) {
        tlen = handle->size - handle->cur;
        tlen = tlen < maxPacketSize ? tlen : maxPacketSize;
        handle->cur += tlen;
    }
    OsalMutexUnlock(&handle->lock);
    *reqLen = tlen;
    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::UsbdBulkASyncReqWriteAutoSubmit(UsbRequest *request)
{
    UsbRequestParams params;
    UsbdBulkASyncReqNode *db = static_cast<UsbdBulkASyncReqNode *>(request->compInfo.userData);
    int32_t ret = memcpy_s(&params, sizeof(params), &db->list->pList->params, sizeof(params));
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memcpy_s failed", __func__, ret);
        return ret;
    }

    params.userData = static_cast<void *>(db);
    ret = UsbdBulkAsyncGetAsmData(&db->list->pList->asmHandle, &params, db->list->pList->pipe.maxPacketSize);
    if (ret != HDF_SUCCESS) {
        UsbdBulkASyncReqNodeSetNoUse(db);
        return ret;
    }
    db->request->compInfo.status = USB_REQUEST_COMPLETED;
    ret = UsbFillRequest(request, db->list->pList->ifHandle, &params);
    if (ret != HDF_SUCCESS) {
        UsbdBulkASyncReqNodeSetNoUse(db);
        HDF_LOGE("%{public}s:UsbFillRequest ret:%{public}d", __func__, ret);
        return ret;
    }
    ret = UsbSubmitRequestAsync(request);
    if (ret != HDF_SUCCESS) {
        UsbdBulkASyncReqNodeSetNoUse(db);
        HDF_LOGE("%{public}s:UsbSubmitRequestAsync ret:%{public}d", __func__, ret);
    }
    return ret;
}

int32_t UsbdDispatcher::UsbdBulkASyncReqReadAutoSubmit(UsbRequest *request)
{
    uint32_t readLen = 0;
    UsbdBulkASyncReqNode *db = static_cast<UsbdBulkASyncReqNode *>(request->compInfo.userData);
    int32_t ret =
        UsbdBulkASyncPutAsmData(&db->list->pList->asmHandle, request->compInfo.buffer, request->compInfo.actualLength);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbdBulkASyncPutAsmData error size:%{public}d ret:%{public}d", __func__,
            __LINE__, request->compInfo.actualLength, ret);
        UsbdBulkASyncReqNodeSetNoUse(db);
        return ret;
    }

    ret = UsbdBulkAsyncGetAsmReqLen(&db->list->pList->asmHandle, &readLen, db->list->pList->pipe.maxPacketSize);
    if (ret != HDF_SUCCESS || readLen < 1) {
        UsbdBulkASyncReqNodeSetNoUse(db);
        HDF_LOGE("%{public}s:invalid param", __func__);
        return HDF_DEV_ERR_NODATA;
    }
    db->request->compInfo.status = USB_REQUEST_COMPLETED;
    UsbHostRequest *hostRequest = reinterpret_cast<UsbIfRequest *>(request)->hostRequest;
    if (readLen != static_cast<uint32_t>(hostRequest->length)) {
        UsbRequestParams params;
        ret = memcpy_s(&params, sizeof(params), &db->list->pList->params, sizeof(params));
        if (ret != EOK) {
            HDF_LOGE("%{public}s: %{public}d memcpy_s failed", __func__, ret);
            return ret;
        }

        params.dataReq.length = readLen;
        params.userData = static_cast<void *>(db);
        ret = UsbFillRequest(request, db->list->pList->ifHandle, &params);
        if (ret != HDF_SUCCESS) {
            UsbdBulkASyncReqNodeSetNoUse(db);
            HDF_LOGE("%{public}s:UsbFillRequest ret:%{public}d ", __func__, ret);
            return ret;
        }
    }
    ret = UsbSubmitRequestAsync(request);
    if (ret != HDF_SUCCESS) {
        UsbdBulkASyncReqNodeSetNoUse(db);
        HDF_LOGE("%{public}s:UsbSubmitRequestAsync ret:%{public}d ", __func__, ret);
    }
    return ret;
}

void UsbdDispatcher::UsbdBulkASyncWriteCallbackAutoSubmit(UsbRequest *request)
{
    if (request == nullptr) {
        HDF_LOGE("%{public}s: %{public}d request is nullptr", __func__, __LINE__);
        return;
    }

    int32_t ret = HDF_SUCCESS;
    UsbdBulkASyncReqNode *node = static_cast<UsbdBulkASyncReqNode *>(request->compInfo.userData);
    int32_t status = request->compInfo.status;
    if (status != 0) {
        UsbdBulkASyncReqNodeSetNoUse(node);
        ret = UsbdBulkWriteRemoteCallback(node->list->pList->cb, status, &node->list->pList->asmHandle);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:%{public}d UsbdBulkWriteRemoteCallback failed, ret:%{public}d"
                "id:%{public}d status:%{public}d", __func__, __LINE__, ret, node->id, status);
        }
        return;
    }

    ret = UsbdBulkASyncReqWriteAutoSubmit(request);
    if (ret == HDF_DEV_ERR_NODATA) {
        int32_t count = DListGetCount(&node->list->eList);
        if (count >= USBD_BULKASYNCREQ_NUM_MAX) {
            ret = UsbdBulkWriteRemoteCallback(node->list->pList->cb, HDF_SUCCESS, &node->list->pList->asmHandle);
            if (ret != HDF_SUCCESS) {
                HDF_LOGE("%{public}s: %{public}d UsbdBulkWriteRemoteCallback failed", __func__, __LINE__);
            }
            return;
        }
    } else if (ret != HDF_SUCCESS) {
        ret = UsbdBulkWriteRemoteCallback(node->list->pList->cb, ret, &node->list->pList->asmHandle);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE(
                "%{public}s:%{public}d UsbdBulkWriteRemoteCallback failed ret:%{public}d id:%{public}d",
                __func__, __LINE__, ret, node->id);
        }
        return;
    }
}

void UsbdDispatcher::UsbdBulkASyncReadCallbackAutoSubmit(UsbRequest *request)
{
    if (request == nullptr) {
        HDF_LOGE("%{public}s: %{public}d request is nullptr", __func__, __LINE__);
        return;
    }

    int32_t ret = HDF_SUCCESS;
    UsbdBulkASyncReqNode *node = static_cast<UsbdBulkASyncReqNode *>(request->compInfo.userData);
    int32_t status = request->compInfo.status;
    if (status != 0) {
        UsbdBulkASyncReqNodeSetNoUse(node);
        ret = UsbdBulkReadRemoteCallback(node->list->pList->cb, status, &node->list->pList->asmHandle);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:%{public}d UsbdBulkReadRemoteCallback failed, ret:%{public}d"
                "id:%{public}d status:%{public}d", __func__, __LINE__, ret, node->id, status);
        }
        return;
    }

    ret = UsbdBulkASyncReqReadAutoSubmit(request);
    if (ret == HDF_DEV_ERR_NODATA) {
        int32_t count = DListGetCount(&node->list->eList);
        if (count >= USBD_BULKASYNCREQ_NUM_MAX) {
            ret = UsbdBulkReadRemoteCallback(node->list->pList->cb, HDF_SUCCESS, &node->list->pList->asmHandle);
            if (ret != HDF_SUCCESS) {
                HDF_LOGE("%{public}s: %{public}d UsbdBulkReadRemoteCallback failed", __func__, __LINE__);
            }
            return;
        }
    } else if (ret != HDF_SUCCESS) {
        ret = UsbdBulkReadRemoteCallback(node->list->pList->cb, ret, &node->list->pList->asmHandle);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE(
                "%{public}s:%{public}d UsbdBulkReadRemoteCallback failed ret:%{public}d id:%{public}d",
                __func__, __LINE__, ret, node->id);
        }
        return;
    }
}

int32_t UsbdDispatcher::UsbdBulkASyncReqFillParams(UsbPipeInfo *pipe, UsbRequestParams *params, uint8_t *buffer)
{
    params->interfaceId = pipe->interfaceId;
    params->pipeAddress = pipe->pipeDirection | pipe->pipeAddress;
    params->pipeId = pipe->pipeId;
    params->requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    params->timeout = USB_CTRL_SET_TIMEOUT;
    params->dataReq.numIsoPackets = 0;
    params->dataReq.directon = static_cast<UsbRequestDirection>((pipe->pipeDirection >> USB_PIPE_DIR_OFFSET) & 0x1);
    params->dataReq.length = pipe->maxPacketSize;

    if (pipe->pipeDirection == USB_PIPE_DIRECTION_OUT) {
        params->callback = UsbdBulkASyncWriteCallbackAutoSubmit;
        params->dataReq.buffer = buffer;
    } else {
        params->callback = UsbdBulkASyncReadCallbackAutoSubmit;
    }
    return HDF_SUCCESS;
}

int32_t UsbdDispatcher::UsbdBulkASyncReqWriteSubmit(UsbdBulkASyncReqNode *req)
{
    UsbRequestParams params;
    int32_t ret = memcpy_s(&params, sizeof(params), &req->list->pList->params, sizeof(params));
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memcpy_s failed", __func__, ret);
        return ret;
    }

    params.userData = static_cast<void *>(req);
    ret = UsbdBulkAsyncGetAsmData(&req->list->pList->asmHandle, &params, req->list->pList->pipe.maxPacketSize);
    if (ret != HDF_SUCCESS) {
        UsbdBulkASyncReqNodeSetNoUse(req);
        HDF_LOGE("%{public}s:UsbdBulkAsyncGetAsmData ret:%{public}d", __func__, ret);
        return ret;
    }
    req->request->compInfo.status = USB_REQUEST_COMPLETED;
    ret = UsbFillRequest(req->request, req->list->pList->ifHandle, &params);
    if (ret != HDF_SUCCESS) {
        UsbdBulkASyncReqNodeSetNoUse(req);
        HDF_LOGE("%{public}s:UsbFillRequest ret:%{public}d", __func__, ret);
        return ret;
    }
    ret = UsbSubmitRequestAsync(req->request);
    if (ret != HDF_SUCCESS) {
        UsbdBulkASyncReqNodeSetNoUse(req);
        HDF_LOGE("%{public}s:UsbSubmitRequestAsync ret:%{public}d", __func__, ret);
    }
    return ret;
}

int32_t UsbdDispatcher::UsbdBulkASyncReqReadSubmit(UsbdBulkASyncReqNode *db)
{
    uint32_t readLen = 0;
    int32_t ret = UsbdBulkAsyncGetAsmReqLen(&db->list->pList->asmHandle, &readLen, db->list->pList->pipe.maxPacketSize);
    if (ret != HDF_SUCCESS || readLen == 0) {
        UsbdBulkASyncReqNodeSetNoUse(db);
        HDF_LOGE("%{public}s:UsbdBulkAsyncGetAsmReqLen failed, readLen:%{public}u", __func__, readLen);
        return HDF_DEV_ERR_NODATA;
    }

    db->request->compInfo.status = USB_REQUEST_COMPLETED;
    UsbRequestParams params;
    ret = memcpy_s(&params, sizeof(params), &db->list->pList->params, sizeof(params));
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memcpy_s failed", __func__, ret);
        return ret;
    }

    params.dataReq.length = readLen;
    params.userData = static_cast<void *>(db);
    ret = UsbFillRequest(db->request, db->list->pList->ifHandle, &params);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:UsbFillRequest failed", __func__);
        UsbdBulkASyncReqNodeSetNoUse(db);
        return ret;
    }

    ret = UsbSubmitRequestAsync(db->request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:UsbSubmitRequestAsync failed", __func__);
        UsbdBulkASyncReqNodeSetNoUse(db);
    }
    return ret;
}
} // namespace V1_2
} // namespace Usb
} // namespace HDI
} // namespace OHOS
