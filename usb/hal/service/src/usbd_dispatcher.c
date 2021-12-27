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

#include "usbd_dispatcher.h"
#include <stdio.h>
#include <unistd.h>
#include "hdf_base.h"
#include "hdf_log.h"
#include "hdf_usb_pnp_manage.h"
#include "osal_mem.h"
#include "osal_sem.h"
#include "osal_time.h"
#include "securec.h"
#include "usb_interface_pool.h"
#include "usbd.h"
#include "usbd_function.h"
#include "usbd_port.h"
#include "usbd_publisher.h"

#define HDF_LOG_TAG usbd_dispatcher

#define MAX_BUFF_SIZE 16384
#define MAX_CONTROL_BUFF_SIZE 1024
#define READ_BUF_SIZE 8192

#define USB_CTRL_SET_TIMEOUT 5000
#define USB_PIPE_DIR_OFFSET 7
#define CHARFORMAT 8
#define USB_REUQEST_SLEEP_TIME 100
#define USB_MAX_DESCRIPTOR_SIZE 256

#define OPEN_SLEPP_TIME 1000
#define SUBMIT_SLEEP_TIME 500

#define POS_STEP 3

#define MULTIPLE 3
#define ADD_NUM_50 50
#define ERROR_0 0

#define HEX_NUM_1F 0x1F
#define HEX_NUM_1 0x1
#define HEX_NUM_3 0x3

static const int DEC_NUM_5 = 5;
static const int DEC_NUM_7 = 7;
static const int DEC_NUM_8 = 8;

static int32_t DispatchBindUsbSubscriber(struct UsbdService *service, struct HdfSBuf *data);
static int32_t DispatchUnbindUsbSubscriber(struct UsbdService *service);
static int32_t GetPipe(const struct HostDevice *dev, uint8_t interfaceId, uint8_t pipeId, struct UsbPipeInfo *pipe);
static int32_t UsbControlTransferEx(struct HostDevice *dev, struct UsbControlParams *pCtrParams, int32_t timeout);

int32_t HostDeviceCreate(struct HostDevice **port);
int32_t UsbdRealseDevices(struct UsbdService *service);
static struct HostDevice *FindDevFromService(struct UsbdService *service, uint8_t busNum, uint8_t devAddr);
static void RemoveDevFromService(struct UsbdService *service, struct HostDevice *port);

static int32_t UsbdInit(struct HostDevice *dev);
static void UsbdRelease(struct HostDevice *dev);

static bool UsbdHdfWriteBuf(struct HdfSBuf *data, uint8_t *buffer, uint32_t length)
{
    if ((!data) || ((length > 0) && (!buffer))) {
        return false;
    }
    if (length == 0) {
        return HdfSbufWriteUint32(data, length);
    }
    return HdfSbufWriteBuffer(data, (const void *)buffer, length);
}

static int32_t ParseDeviceBuf(struct HdfSBuf *data, uint8_t *busNum, uint8_t *devAddr)
{
    if (data == NULL || busNum == NULL || devAddr == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    HdfSbufReadUint8(data, busNum);
    HdfSbufReadUint8(data, devAddr);
    return HDF_SUCCESS;
}

static int32_t UsbdAllocFifo(struct DataFifo *fifo, uint32_t size)
{
    if (!DataFifoIsInitialized(fifo)) {
        void *data = OsalMemAlloc(size);
        if (data == NULL) {
            HDF_LOGE("%{public}s:%{public}d allocate failed", __func__, __LINE__);
            return HDF_ERR_MALLOC_FAIL;
        }
        DataFifoInit(fifo, size, data);
    }
    return HDF_SUCCESS;
}

static void UsbdFreeFifo(struct DataFifo *fifo)
{
    if (fifo == NULL) {
        HDF_LOGE("%{public}s:%{public}d fifo is NULL", __func__, __LINE__);
        return;
    }

    if (fifo->data != NULL) {
        OsalMemFree(fifo->data);
        fifo->data = NULL;
    }

    DataFifoInit(fifo, 0, NULL);
}

static struct RequestMsg *UsbdAllocRequestMsg(UsbInterfaceHandle *interfaceHandle, int32_t isoPackets, int32_t length)
{
    struct RequestMsg *reqMsg = NULL;
    reqMsg = (struct RequestMsg *)OsalMemAlloc(sizeof(struct RequestMsg));
    if (reqMsg == NULL) {
        HDF_LOGE("HDF_ERR_MALLOC_FAIL faild\n");
        return NULL;
    }
    memset_s(reqMsg, sizeof(*reqMsg), 0, sizeof(*reqMsg));
    reqMsg->request = UsbAllocRequest(interfaceHandle, 0, length);
    if (reqMsg->request == NULL) {
        HDF_LOGE("HDF_ERR_MALLOC_FAIL faild\n");
        OsalMemFree(reqMsg);
        return NULL;
    }
    reqMsg->clientData = NULL;
    reqMsg->clientLength = 0;
    return reqMsg;
}

static void UsbdFreeRequestMsg(struct RequestMsg *reqMsg)
{
    if (reqMsg == NULL) {
        return;
    }

    if (reqMsg->request != NULL) {
        UsbFreeRequest(reqMsg->request);
    }
    if (reqMsg->clientData) {
        OsalMemFree(reqMsg->clientData);
        reqMsg->clientData = NULL;
    }
    reqMsg->clientData = NULL;
    reqMsg->clientLength = 0;
    OsalMemFree(reqMsg);

    return;
}

static void UsbdReadCallback(struct UsbRequest *req)
{
    struct UsbIfRequest *reqObj = (struct UsbIfRequest *)req;
    HDF_LOGI("%{public}s:%{pulib}d entry", __func__, __LINE__);
    if (req == NULL) {
        HDF_LOGE("%{public}s:%{pulib}d req is NULL!", __func__, __LINE__);
        return;
    }
    int status = req->compInfo.status;
    uint32_t dataSize = req->compInfo.actualLength;
    struct HostDevice *dev = (struct HostDevice *)req->compInfo.userData;
    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{pulib}d dev is NULL!", __func__, __LINE__);
        OsalSemPost(&reqObj->hostRequest->sem);
        return;
    }

    switch (status) {
        case 0:
            HDF_LOGI("Bulk status: %{public}d+size:%{public}u\n", status, dataSize);
            if (dataSize > 0) {
                uint8_t *data = req->compInfo.buffer;
                OsalMutexLock(&dev->readLock);
                if (DataFifoIsFull(&dev->readFifo)) {
                    HDF_LOGW("%{public}s:%{public}d", __func__, __LINE__);
                    DataFifoSkip(&dev->readFifo, dataSize);
                }
                uint32_t readSize = DataFifoWrite(&dev->readFifo, data, dataSize);
                if (readSize != dataSize) {
                    HDF_LOGW("%{public}s: write less than expected ", __func__);
                }

                OsalMutexUnlock(&dev->readLock);
            }
            break;
        default:
            HDF_LOGW("%{public}s:%{public}d status=%{public}d", __func__, __LINE__, status);
            break;
    }
}

static void UsbdWriteCallback(struct UsbRequest *req)
{
    HDF_LOGI("%{public}s:%{pulib}d entry", __func__, __LINE__);
    if (req == NULL) {
        HDF_LOGE("%{public}s:%{pulib}d req is NULL!", __func__, __LINE__);
        return;
    }
    struct HostDevice *dev = (struct HostDevice *)req->compInfo.userData;
    if ((dev == NULL) || (dev == NULL)) {
        HDF_LOGE("%{public}s:%{pulib}d dev or dev->port is NULL!", __func__, __LINE__);
        return;
    }
    int status = req->compInfo.status;
    HDF_LOGE("%{public}s:%{pulib}d statue is %d!", __func__, __LINE__, status);
    switch (status) {
        case 0:
            break;
        case -ECONNRESET:
        case -ENOENT:
        case -ESHUTDOWN:
            break;
        default:
            break;
    }

    return;
}

static UsbInterfaceHandle *InterfaceIdToHandle(const struct HostDevice *dev, uint8_t id)
{
    UsbInterfaceHandle *devHandle = NULL;

    if (id == 0xFF) {
        devHandle = dev->ctrDevHandle;
    } else if (id < USB_MAX_INTERFACES) {
        return dev->devHandle[id];
    }
    return devHandle;
}

static int32_t UsbControlSetUp(struct UsbControlParams *controlParams, struct UsbControlRequest *controlReq)
{
    if (controlParams == NULL || controlReq == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }

    controlReq->target = controlParams->target;
    controlReq->reqType = controlParams->reqType;
    controlReq->directon = controlParams->directon;
    controlReq->request = controlParams->request;
    controlReq->value = CpuToLe16(controlParams->value);
    controlReq->index = CpuToLe16(controlParams->index);
    controlReq->buffer = controlParams->data;
    controlReq->length = CpuToLe16(controlParams->size);
    return HDF_SUCCESS;
}

static struct UsbInterface *GetUsbInterfaceById(const struct HostDevice *dev, uint8_t interfaceIndex)
{
    struct UsbInterface *tmpIf = NULL;

    if (!dev || (dev->service == NULL)) {
        HDF_LOGE("%{public}s:%{public}d idx:%{public}d service is null", __func__, __LINE__, interfaceIndex);
        return NULL;
    }
    tmpIf = (struct UsbInterface *)UsbClaimInterface(dev->service->session, dev->busNum, dev->devAddr, interfaceIndex);
    if (tmpIf == NULL) {
        HDF_LOGE("%{public}s:%{public}d failed busNum=%{public}d, devAddr=%{public}d, interface=%{public}d", __func__,
                 __LINE__, dev->busNum, dev->devAddr, interfaceIndex);
    }
    return tmpIf;
}

static int32_t GetInterfacePipe(const struct HostDevice *dev,
                                struct UsbInterface *interface,
                                uint8_t pipeAddr,
                                struct UsbPipeInfo *pipe)
{
    struct UsbInterfaceInfo *info = NULL;
    UsbInterfaceHandle *interfaceHandle = NULL;
    struct UsbPipeInfo pipeTmp;
    memset_s(&pipeTmp, sizeof(pipeTmp), 0, sizeof(pipeTmp));
    if (dev == NULL || interface == NULL || pipe == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid parmas", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    info = &interface->info;
    if (info == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid interface", __func__, __LINE__);
        return HDF_FAILURE;
    }

    interfaceHandle = InterfaceIdToHandle(dev, info->interfaceIndex);
    if (interfaceHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid interface handle", __func__, __LINE__);
        return HDF_FAILURE;
    }

    for (uint8_t i = 1; i <= info->pipeNum; ++i) {
        int32_t ret = UsbGetPipeInfo(interfaceHandle, info->curAltSetting, i, &pipeTmp);
        if ((ret == HDF_SUCCESS) && ((pipeTmp.pipeAddress | (uint8_t)pipeTmp.pipeDirection) == pipeAddr)) {
            if (pipe)
                *pipe = pipeTmp;
            return HDF_SUCCESS;
        }
    }
    return HDF_FAILURE;
}

static int32_t GetPipe(const struct HostDevice *dev, uint8_t interfaceId, uint8_t pipeId, struct UsbPipeInfo *pipe)
{
    struct UsbInterface *interface = NULL;

    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid parmas", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (interfaceId > USB_MAX_INTERFACES) {
        HDF_LOGE("%{public}s:%{public}d invalid parmas", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    interface = dev->iface[interfaceId];
    if (interface == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid interface", __func__, __LINE__);
        return HDF_FAILURE;
    }

    int32_t ret = GetInterfacePipe(dev, interface, pipeId, pipe);
    return ret;
}

static void UsbdFreeCtrlPipe(struct HostDevice *dev)
{
    if (dev == NULL) {
        return;
    }
    if (dev->ctrPipe) {
        OsalMemFree(dev->ctrPipe);
        dev->ctrPipe = NULL;
    }
}

static int32_t UsbdGetCtrlPipe(struct HostDevice *dev)
{
    int32_t ret;
    struct UsbPipeInfo *pipe = NULL;
    pipe = (struct UsbPipeInfo *)OsalMemAlloc(sizeof(struct UsbPipeInfo));
    if (pipe == NULL) {
        HDF_LOGE("%{public}s:%{public}d OsalMemAlloc failed", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }

    memset_s(pipe, sizeof(struct UsbPipeInfo), 0, sizeof(struct UsbPipeInfo));
    ret = UsbGetPipeInfo(dev->ctrDevHandle, dev->ctrIface->info.curAltSetting, 0, pipe);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d get pipe failed ret = %{public}d", __func__, __LINE__, ret);
        OsalMemFree(pipe);
        return HDF_FAILURE;
    }
    dev->ctrPipe = pipe;

    return HDF_SUCCESS;
}

static int32_t FunBulkReadSyncSubmit(struct UsbRequest *request,
                                     struct UsbRequestParams *parmas,
                                     UsbInterfaceHandle *interfaceHandle,
                                     struct HdfSBuf *reply)
{
    int32_t ret = UsbFillRequest(request, interfaceHandle, parmas);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s: UsbFillRequest faile, ret=%{public}d \n", __func__, ret);
        return ret;
    }

    ret = UsbSubmitRequestSync(request);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("UsbSubmitRequestSync faile, ret=%{public}d \n", ret);
        OsalMSleep(SUBMIT_SLEEP_TIME);
        return ret;
    }

    HDF_LOGI("%{public}s:%{public}d buffer:%{public}p-%{public}p-actualLength:%{public}d", __func__, __LINE__,
             request->compInfo.buffer, (uint8_t *)request->compInfo.buffer, request->compInfo.actualLength);
    struct UsbIfRequest *reqObj = (struct UsbIfRequest *)request;
    OsalMutexLock(&reqObj->hostRequest->lock);
    if (!UsbdHdfWriteBuf(reply, request->compInfo.buffer, request->compInfo.actualLength)) {
        HDF_LOGE("%{public}s: sbuf write buffer failed", __func__);
        ret = HDF_ERR_IO;
    }
    OsalMutexUnlock(&reqObj->hostRequest->lock);
    return ret;
}

static void UsbRequestParamsRSyncInit(struct UsbRequestParams *parmas, int32_t timeout, const struct UsbPipeInfo *pipe)
{
    if (parmas == NULL || pipe == NULL) {
        return;
    }
    parmas->pipeAddress = pipe->pipeDirection | pipe->pipeAddress;
    parmas->pipeId = pipe->pipeId;
    parmas->interfaceId = pipe->interfaceId;
    parmas->requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    parmas->timeout = timeout;
    parmas->dataReq.numIsoPackets = 0;
    parmas->dataReq.directon = (pipe->pipeDirection >> USB_DIR_OFFSET) & 0x1;
    parmas->dataReq.length = pipe->maxPacketSize;
    return;
}

static int32_t FunBulkReadSync(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint8_t interfaceId = 0;
    uint8_t pipeId = 0;
    int32_t timeout = 0;
    struct UsbPipeInfo pipe;
    struct UsbRequest *request = NULL;
    struct UsbRequestParams parmas;
    UsbInterfaceHandle *interfaceHandle = NULL;
    memset_s(&parmas, sizeof(parmas), 0, sizeof(parmas));
    memset_s(&pipe, sizeof(pipe), 0, sizeof(pipe));
    if ((port == NULL) || (data == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint8(data, &interfaceId)) {
        HDF_LOGE("%{public}s:%{public}d read interfaceId error", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (!HdfSbufReadUint8(data, &pipeId)) {
        HDF_LOGE("%{public}s:%{public}d read pipeId error", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (!HdfSbufReadInt32(data, &timeout)) {
        HDF_LOGE("%{public}s:%{public}d read timeout error", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    int32_t ret = GetPipe(port, interfaceId, pipeId, &pipe);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d get pipe info failed interfaceId=%{public}d, pipeId=%{public}d", __func__,
                 __LINE__, interfaceId, pipeId);
        return HDF_FAILURE;
    }
    interfaceHandle = InterfaceIdToHandle(port, pipe.interfaceId);
    if (!interfaceHandle) {
        HDF_LOGE("%{public}s:%{public}d InterfaceIdToHandle failed interfaceId=%{public}d, pipeId=%{public}d", __func__,
                 __LINE__, interfaceId, pipeId);
        return HDF_FAILURE;
    }
    request = UsbAllocRequest(interfaceHandle, 0, pipe.maxPacketSize);
    if (!request) {
        HDF_LOGE("%{public}s:%{public}d readReq request faild", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }
    HDF_LOGI("%{public}s:%{public}d request:%{public}p ", __func__, __LINE__, request);
    UsbRequestParamsRSyncInit(&parmas, timeout, &pipe);
    ret = FunBulkReadSyncSubmit(request, &parmas, interfaceHandle, reply);
    UsbFreeRequest(request);
    return ret;
}

static void UsbRequestParamsWSyncInit(struct UsbRequestParams *parmas, int32_t timeout, const struct UsbPipeInfo *pipe)
{
    if (parmas == NULL || pipe == NULL) {
        return;
    }
    parmas->interfaceId = pipe->interfaceId;
    parmas->pipeAddress = pipe->pipeDirection | pipe->pipeAddress;
    parmas->pipeId = pipe->pipeId;
    parmas->requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    parmas->timeout = timeout;
    parmas->dataReq.numIsoPackets = 0;
    return;
}

static int32_t FunBulkWriteSyncSyncSubmit(struct UsbRequest *request,
                                          UsbInterfaceHandle *interfaceHandle,
                                          struct UsbRequestParams *parmas)
{
    int32_t ret = UsbFillRequest(request, interfaceHandle, parmas);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s: UsbFillRequest faile, ret=%{public}d \n", __func__, ret);
        return ret;
    }
    HDF_LOGI("%{public}s:%{public}d debug \n", __func__, __LINE__);
    ret = UsbSubmitRequestSync(request);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("UsbSubmitRequestSync faile, ret=%{public}d \n", ret);
        ret = HDF_FAILURE;
        OsalMSleep(SUBMIT_SLEEP_TIME);
    }
    return ret;
}

static int32_t FunBulkWriteSyncGetParam(struct HdfSBuf *data, uint8_t *interfaceId, uint8_t *pipeId, int32_t *timeout)
{
    if (!HdfSbufReadUint8(data, interfaceId)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (!HdfSbufReadUint8(data, pipeId)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (!HdfSbufReadInt32(data, timeout)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    HDF_LOGI("%{public}s:%{public}d interfaceId %{public}d pipeId %{public}d timeout %{public}d", __func__, __LINE__,
             *interfaceId, *pipeId, *timeout);
    return HDF_SUCCESS;
}

static int32_t FunBulkWriteSync(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint8_t *buffer = NULL;
    uint8_t interfaceId = 0;
    uint8_t pipeId = 0;
    int32_t timeout = 0;
    uint32_t length = 0;
    UsbInterfaceHandle *interfaceHandle = NULL;
    struct UsbPipeInfo pipe;
    struct UsbRequest *request = NULL;
    struct UsbRequestParams parmas = {};
    memset_s(&parmas, sizeof(parmas), 0, sizeof(parmas));
    memset_s(&pipe, sizeof(pipe), 0, sizeof(pipe));
    HDF_LOGI("%{public}s:%{public}d UsbOpen", __func__, __LINE__);
    if ((port == NULL) || (data == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    uint32_t ret = FunBulkWriteSyncGetParam(data, &interfaceId, &pipeId, &timeout);
    if (ret != HDF_SUCCESS) {
        return HDF_ERR_IO;
    }
    if (!HdfSbufReadBuffer(data, (const void **)&buffer, &length)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    ret = GetPipe(port, interfaceId, pipeId, &pipe);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get pipe info failed interfaceId=%{public}d, pipeId=%{public}d", __func__, interfaceId,
                 pipeId);
        return HDF_FAILURE;
    }
    interfaceHandle = InterfaceIdToHandle(port, interfaceId);
    if (interfaceHandle == NULL) {
        HDF_LOGE("%{public}s: get interface handle faild \n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    request = UsbAllocRequest(interfaceHandle, 0, pipe.maxPacketSize);
    if (!request) {
        HDF_LOGE("%{public}s: alloc request faild\n", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    HDF_LOGI("%{public}s:%{public}d debug buffer:%{public}s, length:%{public}d, maxPacketSize:%{public}d \n", __func__,
             __LINE__, buffer, length, pipe.maxPacketSize);
    UsbRequestParamsWSyncInit(&parmas, timeout, &pipe);
    parmas.userData = port;
    parmas.dataReq.length = length;
    parmas.dataReq.buffer = buffer;
    ret = FunBulkWriteSyncSyncSubmit(request, interfaceHandle, &parmas);
    UsbFreeRequest(request);
    return ret;
}

static void UsbRequestParamsInit(struct UsbRequestParams *parmas, int32_t timeout)
{
    if (parmas == NULL) {
        return;
    }
    parmas->interfaceId = USB_CTRL_INTERFACE_ID;
    parmas->pipeAddress = 0;
    parmas->pipeId = 0;
    parmas->requestType = USB_REQUEST_PARAMS_CTRL_TYPE;
    parmas->timeout = timeout;
    return;
}

static int32_t UsbControlTransferEx(struct HostDevice *dev, struct UsbControlParams *pCtrParams, int32_t timeout)
{
    struct UsbRequest *request = NULL;
    struct UsbControlParams controlParams = {};
    struct UsbRequestParams parmas = {};

    memset_s(&controlParams, sizeof(controlParams), 0, sizeof(controlParams));
    memset_s(&parmas, sizeof(parmas), 0, sizeof(parmas));

    if (dev == NULL || pCtrParams->data == NULL) {
        HDF_LOGE("%{public}s:%{public}d null pointer faild", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    request = UsbAllocRequest(dev->ctrDevHandle, 0, MAX_CONTROL_BUFF_SIZE);
    if (!request) {
        HDF_LOGE("%{public}s:%{public}d UsbAllocRequest alloc request faild\n", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }

    controlParams = *pCtrParams;
    UsbRequestParamsInit(&parmas, timeout);

    int ret = UsbControlSetUp(&controlParams, &parmas.ctrlReq);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbControlSetUp, ret=%{public}d ", __func__, __LINE__, ret);
        return ret;
    }
    ret = UsbFillRequest(request, dev->ctrDevHandle, &parmas);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d UsbFillRequest faile, ret=%{public}d ", __func__, __LINE__, ret);
        UsbFreeRequest(request);
        return ret;
    }

    ret = UsbSubmitRequestSync(request);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d UsbSubmitRequestSync  faile, ret=%{public}d ", __func__, __LINE__, ret);
        OsalMSleep(SUBMIT_SLEEP_TIME);
        UsbFreeRequest(request);
        return ret;
    }

    *pCtrParams = controlParams;
    if (USB_REQUEST_DIR_FROM_DEVICE == controlParams.directon) {
        HDF_LOGI("%{public}s: debug length=%{public}d, actualLength=%{public}d rlen:=%{public}d", __func__,
                 request->compInfo.length, request->compInfo.actualLength, pCtrParams->size);
        memcpy_s(pCtrParams->data, pCtrParams->size, request->compInfo.buffer, request->compInfo.actualLength);
        if (pCtrParams->size > request->compInfo.actualLength)
            pCtrParams->size = request->compInfo.actualLength;
        controlParams = *pCtrParams;
    }

    UsbFreeRequest(request);
    return ret;
}

static int32_t CtrlTranParamGetReqType(struct HdfSBuf *data, struct UsbControlParams *pCtrParams, int32_t requestType)
{
    if (data == NULL || pCtrParams == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    uint8_t *buffer = NULL;
    uint32_t length = 0;

    int32_t target = requestType & HEX_NUM_1F;
    int32_t direction = (requestType >> DEC_NUM_7) & HEX_NUM_1;
    int32_t cmdType = (requestType >> DEC_NUM_5) & HEX_NUM_3;
    HDF_LOGI(
        "%{public}s:%{public}d requestType:%{public}d direction:%{public}d target:%{public}d cmdType::%{public}d\n",
        __func__, __LINE__, requestType, direction, target, cmdType);
    if (direction == USB_REQUEST_DIR_TO_DEVICE) {
        if (!HdfSbufReadBuffer(data, (const void **)&buffer, &length)) {
            HDF_LOGE("%{public}s:%{public}d hdf sbuf Read failed", __func__, __LINE__);
            return HDF_FAILURE;
        }
        HDF_LOGI("%{public}s:%{public}d HdfSbufReadBuffer length = %{public}d", __func__, __LINE__, length);
    } else {
        length = MAX_CONTROL_BUFF_SIZE;
        buffer = (uint8_t *)OsalMemAlloc(length);
        if (buffer == NULL) {
            HDF_LOGE("%{public}s:%{public}d OsalMemAlloc faild length = %{public}d", __func__, __LINE__, length);
            return HDF_ERR_MALLOC_FAIL;
        }
        memset_s(buffer, length, 0, length);
        HDF_LOGI("%{public}s:%{public}d OsalMemAlloc length = %{public}d", __func__, __LINE__, length);
    }
    pCtrParams->target = target;
    pCtrParams->directon = direction;
    pCtrParams->reqType = cmdType;
    pCtrParams->size = length;
    pCtrParams->data = buffer;

    return HDF_SUCCESS;
}

static int32_t CtrlTransferParamInit(struct HdfSBuf *data, struct UsbControlParams *pCtrParams, int32_t *timeout)
{
    if (data == NULL || pCtrParams == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t requestCmd = 0;
    int32_t requestType = 0;
    int32_t value = 0;
    int32_t index = 0;

    if (!HdfSbufReadInt32(data, &requestType)) {
        HDF_LOGE("%{public}s:%{public}d read param fail", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (!HdfSbufReadInt32(data, &requestCmd)) {
        HDF_LOGE("%{public}s:%{public}d read param fail", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (!HdfSbufReadInt32(data, &value)) {
        HDF_LOGE("%{public}s:%{public}d read param fail", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (!HdfSbufReadInt32(data, &index)) {
        HDF_LOGE("%{public}s:%{public}d read param fail", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (!HdfSbufReadInt32(data, timeout)) {
        HDF_LOGE("%{public}s:%{public}d read param fail", __func__, __LINE__);
        return HDF_ERR_IO;
    }

    HDF_LOGI("%{public}s:%{public}d requestType:%{public}d requestCmd:%{public}d value::%{public}d\n", __func__,
             __LINE__, requestType, requestCmd, value);

    pCtrParams->request = (uint8_t)requestCmd;
    pCtrParams->value = value;
    pCtrParams->index = index;

    int ret = CtrlTranParamGetReqType(data, pCtrParams, requestType);
    return ret;
}

static int32_t FunControlTransfer(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t timeout = 0;

    HDF_LOGI("%{public}s:%{public}d FunControlTransfer entry", __func__, __LINE__);
    if ((port == NULL) || (data == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (port->ctrDevHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d interface handle is null \n", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbControlParams controlParams = {};
    memset_s(&controlParams, sizeof(controlParams), 0, sizeof(controlParams));
    int ret = CtrlTransferParamInit(data, &controlParams, &timeout);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d CtrlTransferParamInit fail ret:%{public}d\n", __func__, __LINE__, ret);
        return ret;
    }
    ret = UsbControlTransferEx(port, &controlParams, timeout);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbControlTransfer faild ret:%{public}d\n", __func__, __LINE__, ret);
    }
    HDF_LOGI("%{public}s:%{public}d UsbControlTransfer ok length = %{public}d", __func__, __LINE__, controlParams.size);
    if (controlParams.directon == USB_REQUEST_DIR_FROM_DEVICE) {
        if ((HDF_SUCCESS == ret) && (!UsbdHdfWriteBuf(reply, (uint8_t *)controlParams.data, controlParams.size))) {
            HDF_LOGE("%{public}s:%{public}d sbuf write buffer failed", __func__, __LINE__);
        }
        if (controlParams.data)
            OsalMemFree(controlParams.data);
    }
    return ret;
}

static int32_t UsbdReleaseInterface(struct HostDevice *dev, uint8_t interfaceId)
{
    HDF_LOGI("%{public}s:%{public}d interfaceId:%{public}d dev:%{public}s", __func__, __LINE__, interfaceId,
             dev ? "OK" : "NULL");
    if (interfaceId >= USB_MAX_INTERFACES) {
        HDF_LOGE("%{public}s:%{public}d interfaceId:%{public}d fail", __func__, __LINE__, interfaceId);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!dev) {
        HDF_LOGE("%{public}s:%{public}d dev is null", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (dev->devHandle[interfaceId] != NULL) {
        int32_t ret = UsbCloseInterface(dev->devHandle[interfaceId]);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: UsbCloseInterface failed id = %{public}d ret:%{public}d", __func__, interfaceId, ret);
            return ret;
        }
        dev->devHandle[interfaceId] = NULL;
    }

    if (dev->iface[interfaceId] != NULL) {
        int32_t ret = UsbReleaseInterface(dev->iface[interfaceId]);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: UsbReleaseInterface failed id = %{public}d ret:%{public}d", __func__, interfaceId,
                     ret);
            return ret;
        }
        dev->iface[interfaceId] = NULL;
    }

    return HDF_SUCCESS;
}

static void UsbdReleaseInterfaces(struct HostDevice *dev)
{
    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d: invalid parma", __func__, __LINE__);
        return;
    }

    for (int i = 0; i < USB_MAX_INTERFACES; ++i) {
        if (dev->iface[i]) {
            UsbReleaseInterface(dev->iface[i]);
            dev->iface[i] = NULL;
        }
    }
    if (dev->ctrIface) {
        UsbReleaseInterface(dev->ctrIface);
        dev->ctrIface = NULL;
    }
}

static int32_t UsbdClaimInterface(struct HostDevice *dev, uint8_t interfaceId)
{
    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d: invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (interfaceId >= USB_MAX_INTERFACES) {
        return HDF_ERR_INVALID_PARAM;
    }

    if (dev->iface[interfaceId] == NULL) {
        dev->iface[interfaceId] = GetUsbInterfaceById((const struct HostDevice *)dev, interfaceId);
        if (dev->iface[interfaceId] == NULL) {
            HDF_LOGE(
                "%{public}s:%{public}d UsbClaimInterface failed id = %{public}d, busNum=%{public}d, devAddr=%{public}d",
                __func__, __LINE__, interfaceId, (int32_t)dev->busNum, (int32_t)dev->devAddr);
            return HDF_FAILURE;
        }
    }

    if (dev->devHandle[interfaceId] == NULL) {
        dev->devHandle[interfaceId] = UsbOpenInterface(dev->iface[interfaceId]);
        if (dev->devHandle[interfaceId] == NULL) {
            HDF_LOGE("%{public}s:%{public}d UsbOpenInterface failed id = %{public}d", __func__, __LINE__, interfaceId);
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

static int32_t UsbdClaimInterfaces(struct HostDevice *dev)
{
    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d: invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    memset_s(dev->iface, sizeof(uint8_t) * USB_MAX_INTERFACES, 0, sizeof(uint8_t) * USB_MAX_INTERFACES);

    dev->ctrIface = GetUsbInterfaceById((const struct HostDevice *)dev, USB_CTRL_INTERFACE_ID);
    if (dev->ctrIface == NULL) {
        HDF_LOGE("%{public}s:%{public}d GetUsbInterfaceById null", __func__, __LINE__);
        UsbdReleaseInterfaces(dev);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void UsbdCloseInterfaces(struct HostDevice *dev)
{
    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d: invalid parma", __func__, __LINE__);
        return;
    }

    for (int i = 0; i < USB_MAX_INTERFACES; ++i) {
        if (dev->devHandle[i]) {
            UsbCloseInterface(dev->devHandle[i]);
            dev->devHandle[i] = NULL;
        }
    }
    if (dev->ctrDevHandle) {
        UsbCloseInterface(dev->ctrDevHandle);
        dev->ctrDevHandle = NULL;
    }
}

static int32_t FunClaimInterface(struct HostDevice *port, struct HdfSBuf *data)
{
    if ((port == NULL) || (data == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    uint8_t interfaceId;
    if (!HdfSbufReadUint8(data, &interfaceId)) {
        HDF_LOGE("%{public}s:%{public}d sbuf read interfaceNum failed", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UsbdClaimInterface(port, interfaceId);
}

static int32_t FunReleaseInterface(struct HostDevice *port, struct HdfSBuf *data)
{
    if ((port == NULL) || (data == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    uint8_t interfaceId;
    if (!HdfSbufReadUint8(data, &interfaceId)) {
        HDF_LOGE("%{public}s:%{public}d sbuf read interfaceNum failed", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s:%{public}d interfaceId:%{public}d", __func__, __LINE__, interfaceId);
    return UsbdReleaseInterface(port, interfaceId);
}

static int32_t UsbdOpenInterfaces(struct HostDevice *dev)
{
    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d: invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    memset_s(dev->devHandle, sizeof(uint8_t) * USB_MAX_INTERFACES, 0, sizeof(uint8_t) * USB_MAX_INTERFACES);

    HDF_LOGI("%{public}s:%{public}d UsbOpenInterface start", __func__, __LINE__);
    dev->ctrDevHandle = UsbOpenInterface(dev->ctrIface);
    HDF_LOGI("%{public}s:%{public}d UsbOpenInterface end", __func__, __LINE__);
    if (dev->ctrDevHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d ctrDevHandle UsbOpenInterface null", __func__, __LINE__);
        UsbdCloseInterfaces(dev);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void MakeUsbControlParams(struct UsbControlParams *controlParams,
                          uint8_t *buffer,
                          uint32_t *length,
                          uint16_t value,
                          uint16_t index)
{
    controlParams->request = USB_DDK_REQ_GET_DESCRIPTOR;
    controlParams->target = USB_REQUEST_TARGET_DEVICE;
    controlParams->reqType = USB_REQUEST_TYPE_STANDARD;
    controlParams->directon = USB_REQUEST_DIR_FROM_DEVICE;
    controlParams->value = value;
    controlParams->index = index;
    controlParams->data = buffer;
    controlParams->size = *length;
}

static int32_t FunGetDeviceDescriptor(struct HostDevice *port, struct HdfSBuf *reply)
{
    if ((port == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t length = USB_MAX_DESCRIPTOR_SIZE;
    uint8_t *buffer = (uint8_t *)OsalMemAlloc(length);
    if (!buffer) {
        HDF_LOGE("%{public}s:%{public}d malloc fail ", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }
    memset_s(buffer, length, 0, length);
    struct UsbControlParams controlParams = {};
    MakeUsbControlParams(&controlParams, buffer, &length, (int32_t)USB_DDK_DT_DEVICE << DEC_NUM_8, 0);
    int32_t ret = UsbControlTransferEx(port, &controlParams, USB_CTRL_SET_TIMEOUT);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d failed ret:%{public}d", __func__, __LINE__, ret);
        if (buffer)
            OsalMemFree(buffer);
        return ret;
    }
    if (!UsbdHdfWriteBuf(reply, buffer, controlParams.size)) {
        HDF_LOGE("%{public}s:%{public}d WriteBuffer fail ", __func__, __LINE__);
        ret = HDF_ERR_IO;
    }
    if (buffer)
        OsalMemFree(buffer);
    return ret;
}

static int32_t FunGetConfigDescriptor(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint8_t *buffer = NULL;
    uint8_t configId = 0;

    if ((port == NULL) || (reply == NULL) || (data == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint8(data, &configId)) {
        HDF_LOGE("%{public}s:%{public}d failed", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    uint32_t length = USB_MAX_DESCRIPTOR_SIZE;
    buffer = (uint8_t *)OsalMemAlloc(length);
    if (!buffer) {
        HDF_LOGE("%{public}s:%{public}d malloc fail ", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }
    memset_s(buffer, length, 0, length);
    struct UsbControlParams controlParams = {};
    MakeUsbControlParams(&controlParams, buffer, &length, ((int32_t)USB_DDK_DT_CONFIG << DEC_NUM_8) + configId, 0);
    int32_t ret = UsbControlTransferEx(port, &controlParams, USB_CTRL_SET_TIMEOUT);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d failed", __func__, __LINE__);
        if (buffer)
            OsalMemFree(buffer);
        return ret;
    }
    if (!UsbdHdfWriteBuf(reply, buffer, controlParams.size)) {
        HDF_LOGE("%{public}s:%{public}d WriteBuffer fail ", __func__, __LINE__);
        ret = HDF_ERR_IO;
    }

    if (buffer)
        OsalMemFree(buffer);
    return ret;
}

static int32_t FunGetStringDescriptor(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint8_t *buffer = NULL;
    uint8_t stringId = 0;

    if ((port == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint8(data, &stringId)) {
        HDF_LOGE("%{public}s:%{public}d failed", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    uint32_t length = USB_MAX_DESCRIPTOR_SIZE;
    buffer = (uint8_t *)OsalMemAlloc(length);
    if (!buffer) {
        HDF_LOGE("%{public}s:%{public}d malloc fail ", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }
    memset_s(buffer, length, 0, length);
    struct UsbControlParams controlParams = {};
    MakeUsbControlParams(&controlParams, buffer, &length, ((int32_t)USB_DDK_DT_STRING << DEC_NUM_8) + stringId, 0);
    int32_t ret = UsbControlTransferEx(port, &controlParams, USB_CTRL_SET_TIMEOUT);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d failed", __func__, __LINE__);
        if (buffer)
            OsalMemFree(buffer);
        return ret;
    }
    if (!UsbdHdfWriteBuf(reply, buffer, controlParams.size)) {
        HDF_LOGE("%{public}s:%{public}d WriteBuffer fail ", __func__, __LINE__);
        ret = HDF_ERR_IO;
    }
    if (buffer)
        OsalMemFree(buffer);
    return ret;
}

void MakeGetActiveUsbControlParams(struct UsbControlParams *controlParams,
                                   uint8_t *buffer,
                                   uint32_t *length,
                                   uint16_t value,
                                   uint16_t index)
{
    controlParams->request = USB_DDK_REQ_GET_CONFIGURATION;
    controlParams->target = USB_REQUEST_TARGET_DEVICE;
    controlParams->reqType = USB_REQUEST_TYPE_STANDARD;
    controlParams->directon = USB_REQUEST_DIR_FROM_DEVICE;
    controlParams->value = value;
    controlParams->index = index;
    controlParams->data = buffer;
    controlParams->size = *length;
}

static int32_t FunGetActiveConfig(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint8_t configId = 0;
    uint32_t length = 1;

    HDF_LOGI("%{public}s: FunControlTransfer entry", __func__);
    if ((port == NULL) || (data == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbControlParams controlParams = {};
    MakeGetActiveUsbControlParams(&controlParams, &configId, &length, 0, 0);
    int32_t ret = UsbControlTransferEx(port, &controlParams, USB_CTRL_SET_TIMEOUT);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d failed", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (!HdfSbufWriteUint8(reply, configId)) {
        HDF_LOGE("%{public}s:%{public}d WriteBuffer fail ", __func__, __LINE__);
        ret = HDF_ERR_IO;
    }
    return ret;
}

static int32_t ReOpenDevice(struct HostDevice *port)
{
    int32_t ret = HDF_FAILURE;
    if (!port) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return ret;
    }
    uint8_t busNum = port->busNum;
    uint8_t devAddr = port->devAddr;
    UsbdRelease(port);
    port->busNum = busNum;
    port->devAddr = devAddr;
    ret = UsbdInit(port);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbInit failed ret:%{public}d", __func__, __LINE__, ret);
        UsbdRelease(port);
        RemoveDevFromService(port->service, port);
        OsalMemFree(port);
        return ret;
    }
    DataFifoReset(&port->readFifo);
    OsalMSleep(OPEN_SLEPP_TIME);
    return HDF_SUCCESS;
}

void MakeSetActiveUsbControlParams(struct UsbControlParams *controlParams,
                                   uint8_t *buffer,
                                   uint32_t *length,
                                   uint16_t value,
                                   uint16_t index)
{
    controlParams->request = USB_DDK_REQ_SET_CONFIGURATION;
    controlParams->target = USB_REQUEST_TARGET_DEVICE;
    controlParams->reqType = USB_REQUEST_TYPE_STANDARD;
    controlParams->directon = USB_REQUEST_DIR_FROM_DEVICE;
    controlParams->value = value;
    controlParams->index = index;
    controlParams->data = buffer;
    controlParams->size = *length;
}

static int32_t FunSetActiveConfig(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint8_t configId = 0;
    uint8_t configIdOld = 0;
    uint8_t configIdNew = 0;
    uint32_t length = 1;
    if ((port == NULL) || (data == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint8(data, &configId)) {
        HDF_LOGE("%{public}s:%{public}d failed", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbControlParams controlParams = {};
    MakeGetActiveUsbControlParams(&controlParams, &configIdOld, &length, 0, 0);
    int32_t ret = UsbControlTransferEx(port, &controlParams, USB_CTRL_SET_TIMEOUT);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d getConfiguration failed ret:%{public}d", __func__, __LINE__, ret);
        return HDF_ERR_INVALID_PARAM;
    }
    if (configId == configIdOld) {
        HDF_LOGI("%{public}s:%{public}d setConfiguration success configId:%{public}d old:%{public}d", __func__,
                 __LINE__, configId, configIdOld);
        return HDF_SUCCESS;
    }
    length = 0;
    MakeSetActiveUsbControlParams(&controlParams, &configId, &length, (int32_t)0 + configId, 0);
    ret = UsbControlTransferEx(port, &controlParams, USB_CTRL_SET_TIMEOUT);
    HDF_LOGI("%{public}s:%{public}d ret:%{public}d configId:%{public}d id2:%{public}d length:%{public}d", __func__,
             __LINE__, ret, configId, configIdOld, length);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d setConfiguration failed ret:%{public}d", __func__, __LINE__, ret);
        return HDF_ERR_IO;
    }
    length = 1;
    MakeGetActiveUsbControlParams(&controlParams, &configIdNew, &length, 0, 0);
    ret = UsbControlTransferEx(port, &controlParams, USB_CTRL_SET_TIMEOUT);
    HDF_LOGI("%{public}s:%{public}d ret:%{public}d config:%{public}d leng:%{public}d", __func__, __LINE__, ret,
             configIdNew, length);
    if ((HDF_SUCCESS != ret) || (configId != configIdNew)) {
        HDF_LOGE("%{public}s:%{public}d getConfiguration failed ret:%{public}d", __func__, __LINE__, ret);
        return HDF_ERR_IO;
    }
    if (configId != 0) {
        ret = ReOpenDevice(port);
        HDF_LOGE("%{public}s:%{public}d ReOpenDevice failed ret:%{public}d", __func__, __LINE__, ret);
    }
    return ret;
}

static int32_t FunSetInterface(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint8_t interfaceId = 0;
    uint8_t altIndex = 0;
    uint32_t length = 0;
    UsbInterfaceHandle *interfaceHandle = NULL;

    HDF_LOGI("%{public}s:%{public}d FunControlTransfer entry", __func__, __LINE__);
    if ((port == NULL) || (data == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint8(data, &interfaceId)) {
        HDF_LOGE("%{public}s:%{public}d failed", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint8(data, &altIndex)) {
        HDF_LOGE("%{public}s:%{public}d failed", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    interfaceHandle = InterfaceIdToHandle(port, interfaceId);
    if (interfaceHandle == NULL) {
        HDF_LOGE(
            "%{public}s:%{public}d InterfaceIdToHandle failed bus:%{public}d devAddr:%{public}d interfaceId:%{public}d",
            __func__, __LINE__, port->busNum, port->devAddr, interfaceId);
        return HDF_FAILURE;
    }

    int32_t ret = UsbSelectInterfaceSetting(interfaceHandle, altIndex, &port->iface[interfaceId]);
    HDF_LOGI("%{public}s:%{public}d ret:%{public}d ifId:%{public}d altIdx:%{public}d length:%{public}d", __func__,
             __LINE__, ret, interfaceId, altIndex, length);
    return ret;
}

static int32_t FunBulkReadGetParam(struct HdfSBuf *data, uint8_t *interfaceId, uint8_t *pipeId, int32_t *timeout)
{
    if (!HdfSbufReadUint8(data, interfaceId)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint8(data, pipeId)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadInt32(data, timeout)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

static void UsbRequestParamsBRInit(struct UsbRequestParams *parmas,
                                   const struct HostDevice *port,
                                   int32_t timeout,
                                   const struct UsbPipeInfo *pipe)
{
    if (parmas == NULL || pipe == NULL || port == NULL) {
        return;
    }
    parmas->userData = (void *)port;
    parmas->pipeAddress = pipe->pipeDirection | pipe->pipeAddress;
    parmas->pipeId = pipe->pipeId;
    parmas->interfaceId = pipe->interfaceId;
    parmas->callback = UsbdReadCallback;
    parmas->requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    parmas->timeout = timeout;
    parmas->dataReq.numIsoPackets = 0;
    parmas->dataReq.directon = (pipe->pipeDirection >> USB_PIPE_DIR_OFFSET) & 0x1;
    parmas->dataReq.length = pipe->maxPacketSize;

    return;
}

static int32_t FunBulkReadUsbSubmit(struct HostDevice *port, struct RequestMsg *reqMsg)
{
    OsalMutexLock(&port->requestLock);
    struct UsbIfRequest *ifReq = (struct UsbIfRequest *)reqMsg->request;
    struct UsbHostRequest *hostReq = (struct UsbHostRequest *)ifReq->hostRequest;
    OsalSemInit(&hostReq->sem, 0);
    int32_t ret = UsbSubmitRequestAsync(reqMsg->request);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("UsbSubmitRequestAsync faile, ret=%{public}d \n", ret);
        ret = HDF_FAILURE;
        OsalMutexUnlock(&port->requestLock);
        OsalMSleep(SUBMIT_SLEEP_TIME);
        UsbdFreeRequestMsg(reqMsg);
        return ret;
    }
    HdfSListAdd(&port->requestQueue, &reqMsg->node);
    OsalMutexUnlock(&port->requestLock);
    return ret;
}

static int32_t FunBulkRead(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint8_t interfaceId = 0;
    uint8_t pipeId = 0;
    int32_t timeout = 0;
    struct UsbPipeInfo pipe;
    struct RequestMsg *reqMsg = NULL;
    struct UsbRequestParams parmas;
    UsbInterfaceHandle *interfaceHandle = NULL;
    memset_s(&pipe, sizeof(pipe), 0, sizeof(pipe));
    memset_s(&parmas, sizeof(parmas), 0, sizeof(parmas));
    if ((port == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = FunBulkReadGetParam(data, &interfaceId, &pipeId, &timeout);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    ret = GetPipe(port, interfaceId, pipeId, &pipe);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get pipe info failed", __func__);
        return HDF_FAILURE;
    }
    interfaceHandle = InterfaceIdToHandle(port, pipe.interfaceId);
    if (interfaceHandle == NULL) {
        HDF_LOGE(
            "%{public}s:%{public}d InterfaceIdToHandle failed bus:%{public}d devAddr:%{public}d interfaceId:%{public}d",
            __func__, __LINE__, port->busNum, port->devAddr, pipe.interfaceId);
        return HDF_FAILURE;
    }
    reqMsg = UsbdAllocRequestMsg(interfaceHandle, 0, pipe.maxPacketSize);
    if (reqMsg == NULL) {
        return HDF_ERR_MALLOC_FAIL;
    }
    UsbRequestParamsBRInit(&parmas, port, timeout, &pipe);
    ret = UsbFillRequest(reqMsg->request, interfaceHandle, &parmas);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s: UsbFillRequest faile, ret=%{public}d \n", __func__, ret);
        UsbdFreeRequestMsg(reqMsg);
        return ret;
    }
    ret = FunBulkReadUsbSubmit(port, reqMsg);
    if (ret != HDF_SUCCESS) {
        UsbdFreeRequestMsg(reqMsg);
    }
    return ret;
}

static int32_t FunBulkWriteGetParam(struct HdfSBuf *data, uint8_t *interfaceId, uint8_t *pipeId, int32_t *timeout)
{
    if (!HdfSbufReadUint8(data, interfaceId)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint8(data, pipeId)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadInt32(data, timeout)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

static void UsbRequestParamsBWInit(struct UsbRequestParams *parmas,
                                   const struct HostDevice *port,
                                   int32_t timeout,
                                   const struct UsbPipeInfo *pipe)
{
    if (parmas == NULL || pipe == NULL || port == NULL) {
        return;
    }
    parmas->userData = (void *)port;
    parmas->pipeAddress = pipe->pipeDirection | pipe->pipeAddress;
    parmas->pipeId = pipe->pipeId;
    parmas->interfaceId = pipe->interfaceId;
    parmas->callback = UsbdWriteCallback;
    parmas->requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    parmas->timeout = timeout;
    parmas->dataReq.numIsoPackets = 0;
    parmas->dataReq.directon = (pipe->pipeDirection >> USB_PIPE_DIR_OFFSET) & 0x1;

    return;
}

static int32_t FunBulkWriteUsbSubmit(struct HostDevice *port, struct RequestMsg *reqMsg)
{
    OsalMutexLock(&port->requestLock);
    struct UsbIfRequest *ifReq = (struct UsbIfRequest *)reqMsg->request;
    struct UsbHostRequest *hostReq = (struct UsbHostRequest *)ifReq->hostRequest;
    OsalSemInit(&hostReq->sem, 0);
    int32_t ret = UsbSubmitRequestAsync(reqMsg->request);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d UsbSubmitRequestAsync faile, ret=%{public}d \n", __func__, __LINE__, ret);
        OsalMutexUnlock(&port->requestLock);
        OsalMSleep(SUBMIT_SLEEP_TIME);
        return HDF_FAILURE;
    }
    HdfSListAdd(&port->requestQueue, &reqMsg->node);
    OsalMutexUnlock(&port->requestLock);
    return ret;
}

static int32_t FunBulkWrite(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint8_t interfaceId = 0;
    uint8_t pipeId = 0;
    int32_t timeout = 0;
    uint32_t length = 0;
    uint8_t *buffer = NULL;
    struct UsbPipeInfo pipe;
    struct RequestMsg *reqMsg = NULL;
    struct UsbRequestParams parmas;
    UsbInterfaceHandle *interfaceHandle = NULL;
    memset_s(&pipe, sizeof(pipe), 0, sizeof(pipe));
    memset_s(&parmas, sizeof(parmas), 0, sizeof(parmas));
    if ((port == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = FunBulkWriteGetParam(data, &interfaceId, &pipeId, &timeout);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    if (!HdfSbufReadBuffer(data, (const void **)&buffer, &length)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetPipe(port, interfaceId, pipeId, &pipe);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get pipe info failed", __func__);
        return HDF_FAILURE;
    }
    interfaceHandle = InterfaceIdToHandle(port, pipe.interfaceId);
    if (interfaceHandle == NULL) {
        return HDF_FAILURE;
    }
    reqMsg = UsbdAllocRequestMsg(interfaceHandle, 0, pipe.maxPacketSize);
    if (reqMsg == NULL) {
        return HDF_ERR_MALLOC_FAIL;
    }
    UsbRequestParamsBWInit(&parmas, port, timeout, &pipe);
    parmas.dataReq.length = length;
    parmas.dataReq.buffer = buffer;
    ret = UsbFillRequest(reqMsg->request, interfaceHandle, &parmas);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s: UsbFillRequest faile, ret=%{public}d \n", __func__, ret);
        UsbdFreeRequestMsg(reqMsg);
        return ret;
    }
    ret = FunBulkWriteUsbSubmit(port, reqMsg);
    UsbdFreeRequestMsg(reqMsg);
    return ret;
}

static int32_t FunRequestQueueGetPipeHandle(struct HostDevice *port,
                                            struct HdfSBuf *data,
                                            struct UsbPipeInfo *pipe,
                                            UsbInterfaceHandle **interfaceHandle)
{
    uint8_t interfaceId = 0;
    uint8_t pipeId = 0;
    if (!HdfSbufReadUint8(data, &interfaceId)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint8(data, &pipeId)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = GetPipe(port, interfaceId, pipeId, pipe);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE(
            "%{public}s:%{public}d get pipe info failed, interfaceId=%{public}d,pipeId=%{public}d pipeAddr:%{public}d",
            __func__, __LINE__, interfaceId, pipeId, pipe->pipeAddress);
        ret = HDF_FAILURE;
    }
    *interfaceHandle = InterfaceIdToHandle(port, pipe->interfaceId);
    if (*interfaceHandle == NULL) {
        HDF_LOGE(
            "%{public}s:%{public}d get handle failed, interfaceId=%{public}d,pipeId=%{public}d pipeAddr:%{public}d",
            __func__, __LINE__, interfaceId, pipeId, pipe->pipeAddress);
        ret = HDF_FAILURE;
    }
    return ret;
}

static bool UsbdHdfReadBufAndMalloc(struct HdfSBuf *data, uint8_t **ptr, uint32_t *length)
{
    if ((!data) && (!length) && (!ptr)) {
        HDF_LOGE("%{public}s:%{public}d param failed", __func__, __LINE__);
        return false;
    }
    if (!HdfSbufReadUint32(data, length)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return false;
    }
    if (*length > 0) {
        const uint8_t *tclientData = HdfSbufReadUnpadBuffer(data, *length);
        if (tclientData == NULL) {
            HDF_LOGE("%{public}s:%{public}d read failed length:%{public}d", __func__, __LINE__, *length);
            return false;
        }
        *ptr = (uint8_t *)OsalMemAlloc(*length);
        if (!(*ptr)) {
            HDF_LOGE("%{public}s:%{public}d OsalMemAlloc fail size:%{public}d", __func__, __LINE__, *length);
            return HDF_ERR_MALLOC_FAIL;
        }
        errno_t ret = memcpy_s(*ptr, *length, tclientData, *length);
        if (ret != EOK) {
            HDF_LOGE("%{public}s:%{public}d memcpy_s fail size:%{public}d", __func__, __LINE__, *length);
            return HDF_ERR_MALLOC_FAIL;
        }
    } else {
        *ptr = NULL;
    }
    return true;
}

static int32_t FunRequestQueueRetError(int32_t ret, uint8_t *clientData, uint8_t *buffer)
{
    if (clientData) {
        OsalMemFree(clientData);
    }
    if (buffer) {
        OsalMemFree(buffer);
    }
    return ret;
}

static int32_t FillReqAyncParams(struct HostDevice *userData,
                                 struct UsbPipeInfo *pipe,
                                 struct UsbRequestParams *parmas,
                                 uint8_t *buffer,
                                 int length)
{
    int32_t ret = HDF_SUCCESS;
    bool bWrite = false;
    if ((!userData) || (!pipe) || (!parmas)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    bWrite = (pipe->pipeDirection == USB_PIPE_DIRECTION_OUT);
    parmas->interfaceId = pipe->interfaceId;
    parmas->pipeAddress = pipe->pipeDirection | pipe->pipeAddress;
    parmas->pipeId = pipe->pipeId;
    parmas->requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    parmas->timeout = USB_CTRL_SET_TIMEOUT;
    parmas->dataReq.numIsoPackets = 0;
    parmas->userData = (void *)userData;
    parmas->dataReq.length = length;
    HDF_LOGI(
        "%{public}s:%{public}d interfaceId=%{public}d,pipeId=%{public}d bwrite:%{public}d pipDriect:%{public}d "
        "pipeAddr:%{public}d Addr:%{public}d",
        __func__, __LINE__, pipe->interfaceId, pipe->pipeId, bWrite, pipe->pipeDirection, pipe->pipeAddress,
        parmas->pipeAddress);
    if (bWrite) {
        parmas->callback = UsbdWriteCallback;
        parmas->dataReq.buffer = buffer;
    } else {
        parmas->callback = UsbdReadCallback;
        parmas->dataReq.directon = (pipe->pipeDirection >> USB_PIPE_DIR_OFFSET) & 0x1;
        parmas->dataReq.length = length;
    }
    return ret;
}

static int32_t RequestQueueFillRequest(struct RequestMsg **reqMsg,
                                       UsbInterfaceHandle *interfaceHandle,
                                       struct UsbRequestParams *parmas)
{
    int32_t ret = UsbFillRequest((*reqMsg)->request, interfaceHandle, parmas);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d UsbFillRequest faile, ret=%{public}d \n", __func__, __LINE__, ret);
        UsbdFreeRequestMsg(*reqMsg);
        *reqMsg = NULL;
    }
    return ret;
}

static int32_t MallocReqest(struct RequestMsg **reqMsg,
                            UsbInterfaceHandle *interfaceHandle,
                            struct UsbPipeInfo *pipe,
                            uint8_t *clientData,
                            uint32_t clientLength)
{
    int32_t ret = HDF_SUCCESS;
    *reqMsg = UsbdAllocRequestMsg(interfaceHandle, 0, pipe->maxPacketSize);
    if ((*reqMsg) == NULL) {
        HDF_LOGE("%{public}s:%{public}d malloc reqMsg error", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }
    (*reqMsg)->clientData = (void *)clientData;
    (*reqMsg)->clientLength = clientLength;
    (*reqMsg)->request->compInfo.status = -1;
    return ret;
}

static int32_t ReqAyncSubmit(struct HostDevice *port, struct RequestMsg *reqMsg)
{
    if ((port == NULL) || (reqMsg == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    OsalMutexLock(&port->requestLock);
    OsalSemInit(&((struct UsbIfRequest *)reqMsg->request)->hostRequest->sem, 0);
    int32_t ret = UsbSubmitRequestAsync(reqMsg->request);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d UsbSubmitRequestAsync faile, ret=%{public}d \n", __func__, __LINE__, ret);
        ret = HDF_FAILURE;
        OsalMutexUnlock(&port->requestLock);
        OsalMSleep(SUBMIT_SLEEP_TIME);
        return ret;
    }
    HdfSListAddTail(&port->requestQueue, &reqMsg->node);
    OsalMutexUnlock(&port->requestLock);
    return ret;
}

static int32_t ReturnGotoRQError1(int32_t ret, uint8_t *clientData, uint8_t *buffer)
{
    if (clientData) {
        OsalMemFree(clientData);
    }
    if (buffer) {
        OsalMemFree(buffer);
    }
    return ret;
}

static int32_t ReturnGotoRQError2(int32_t ret, uint8_t *clientData, uint8_t *buffer, struct RequestMsg *reqMsg)
{
    UsbdFreeRequestMsg(reqMsg);
    if (clientData) {
        OsalMemFree(clientData);
    }
    if (buffer) {
        OsalMemFree(buffer);
    }
    return ret;
}

static int32_t FunRequestQueue(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct UsbPipeInfo pipe;
    struct RequestMsg *reqMsg = NULL;
    struct UsbRequestParams parmas;
    UsbInterfaceHandle *interfaceHandle = NULL;
    uint8_t *clientData = NULL;
    uint8_t *buffer = NULL;
    uint32_t clientLength = 0;
    uint32_t length = 0;
    bool bWrite = false;
    memset_s(&pipe, sizeof(pipe), 0, sizeof(pipe));
    memset_s(&parmas, sizeof(parmas), 0, sizeof(parmas));
    if ((port == NULL) || (reply == NULL) || (data == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = FunRequestQueueGetPipeHandle(port, data, &pipe, &interfaceHandle);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    if (!UsbdHdfReadBufAndMalloc(data, &clientData, &clientLength) ||
        !UsbdHdfReadBufAndMalloc(data, &buffer, &length)) {
        return FunRequestQueueRetError(ret, clientData, buffer);
    }
    ret = FillReqAyncParams(port, &pipe, &parmas, buffer, length);
    if (HDF_SUCCESS != ret)
        return ReturnGotoRQError1(ret, clientData, buffer);
    bWrite = (pipe.pipeDirection == USB_PIPE_DIRECTION_OUT);
    parmas.dataReq.length = bWrite ? length : MAX_CONTROL_BUFF_SIZE;
    ret = MallocReqest(&reqMsg, interfaceHandle, &pipe, clientData, clientLength);
    if (HDF_SUCCESS != ret)
        return ReturnGotoRQError2(ret, clientData, buffer, reqMsg);
    ret = RequestQueueFillRequest(&reqMsg, interfaceHandle, &parmas);
    if (HDF_SUCCESS != ret)
        return ReturnGotoRQError2(ret, clientData, buffer, reqMsg);
    ret = ReqAyncSubmit(port, reqMsg);
    if (HDF_SUCCESS != ret)
        return ReturnGotoRQError2(ret, clientData, buffer, reqMsg);
    if (buffer) {
        OsalMemFree(buffer);
        buffer = NULL;
    }
    return HDF_SUCCESS;
}

static int32_t GetRequestMsgFromQueue(struct HostDevice *port, struct RequestMsg **reqMsg)
{
    int32_t ret = HDF_SUCCESS;
    struct HdfSListNode *requestNode = NULL;
    int32_t requestCount = 0;
    if (port == NULL) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    OsalMutexLock(&port->requestLock);
    if (!HdfSListIsEmpty(&port->requestQueue)) {
        requestNode = HdfSListPop(&port->requestQueue);
        requestCount = HdfSListCount(&port->requestQueue);
    }
    OsalMutexUnlock(&port->requestLock);
    if (requestNode == NULL) {
        HDF_LOGE("%{public}s:%{public}d request node is null", __func__, __LINE__);
        return HDF_FAILURE;
    }
    *reqMsg = HDF_SLIST_CONTAINER_OF(struct HdfSListNode, requestNode, struct RequestMsg, node);
    if (*reqMsg == NULL) {
        HDF_LOGE("%{public}s:%{public}d request msg is null", __func__, __LINE__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s:%{public}d get request %{public}p ok, count=%{public}d status:%{public}d", __func__, __LINE__,
             (*reqMsg), requestCount, (*reqMsg)->request->compInfo.status);
    return ret;
}

static int32_t GetRequestMsgData(struct HostDevice *port,
                                 struct RequestMsg *reqMsg,
                                 int32_t timeout,
                                 uint8_t **buffer,
                                 uint32_t *length)
{
    int32_t ret = HDF_SUCCESS;
    if (reqMsg == NULL) {
        HDF_LOGE("%{public}s: invalid parma  request %{public}p", __func__, reqMsg);
        return HDF_ERR_INVALID_PARAM;
    }
    if ((int32_t)(reqMsg->request->compInfo.status) == -1) {
        HDF_LOGI("%{public}s:%{public}d  request waitting... timeout:%{public}d", __func__, __LINE__, timeout);
        ret = OsalSemWait(&((struct UsbIfRequest *)reqMsg->request)->hostRequest->sem, timeout);
        HDF_LOGI("%{public}s:%{public}d wait over ret:%{public}d timeout:%{public}d status:%{public}d", __func__,
                 __LINE__, ret, timeout, reqMsg->request->compInfo.status);
        ret = (int32_t)(reqMsg->request->compInfo.status);
        if ((ret == USB_REQUEST_COMPLETED) || (USB_REQUEST_COMPLETED_SHORT == ret)) {
            ret = HDF_SUCCESS;
        }
        if (HDF_SUCCESS != ret) {
            HDF_LOGE("%{public}s:%{public}d  request wait failed ret = %{public}d", __func__, __LINE__, ret);
            return ret;
        }
    }

    OsalMutexLock(&port->readLock);
    *length = DataFifoLen(&port->readFifo);
    HDF_LOGI("%{public}s:%{public}d len:%{public}d clientlen:%{public}d", __func__, __LINE__, *length,
             reqMsg->clientLength);
    if (*length > 0) {
        *buffer = (uint8_t *)OsalMemCalloc(*length + 1);
        if (*buffer == NULL) {
            HDF_LOGE("%{public}s:%{public}d OsalMemCalloc error", __func__, __LINE__);
            ret = HDF_ERR_MALLOC_FAIL;
            *length = 0;
            OsalMutexUnlock(&port->readLock);
            return ret;
        }
        memset_s(*buffer, *length + 1, 0, *length + 1);
        *length = DataFifoRead(&port->readFifo, *buffer, *length);
        HDF_LOGI("%{public}s:%{public}d len:%{public}d", __func__, __LINE__, *length);
    }

    OsalMutexUnlock(&port->readLock);
    return ret;
}

static int32_t ReturnRWError(int32_t ret, struct RequestMsg *reqMsg)
{
    if (reqMsg) {
        UsbdFreeRequestMsg(reqMsg);
    }
    return ret;
}

static int32_t ReturnRWError1(int32_t ret, uint8_t *buffer, struct RequestMsg *reqMsg)
{
    if (buffer) {
        OsalMemFree(buffer);
    }
    if (reqMsg) {
        UsbdFreeRequestMsg(reqMsg);
    }
    return ret;
}

static int32_t FunRequestWait(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct RequestMsg *reqMsg = NULL;
    uint8_t *buffer = NULL;
    uint32_t length = 0;
    int32_t timeout = 0;
    if ((port == NULL) || (data == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadInt32(data, &timeout)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s:%{public}d request wait entry ok timeout = %{public}d", __func__, __LINE__, timeout);
    int32_t ret = GetRequestMsgFromQueue(port, &reqMsg);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d GetRequestMsgFromQueue error:%{public}d", __func__, __LINE__, ret);
        return ReturnRWError(ret, reqMsg);
    }
    ret = GetRequestMsgData(port, reqMsg, timeout, &buffer, &length);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s:%{public}d GetRequestMsgData error:%{public}d", __func__, __LINE__, ret);
        return ReturnRWError1(ret, buffer, reqMsg);
    }
    if ((!reqMsg->clientData) && (reqMsg->clientLength > 0)) {
        ret = HDF_ERR_IO;
        HDF_LOGE("%{public}s:%{public}d failed len:%{public}d", __func__, __LINE__, reqMsg->clientLength);
        return ReturnRWError1(ret, buffer, reqMsg);
    }
    if (!UsbdHdfWriteBuf(reply, reqMsg->clientData, reqMsg->clientLength)) {
        ret = HDF_ERR_IO;
        HDF_LOGE("%{public}s:%{public}d  HdfSbufWriteBuffer failed", __func__, __LINE__);
        return ReturnRWError1(ret, buffer, reqMsg);
    }
    if (!UsbdHdfWriteBuf(reply, buffer, length)) {
        ret = HDF_ERR_IO;
        HDF_LOGE("%{public}s:%{public}d  HdfSbufWriteBuffer failed", __func__, __LINE__);
    }
    if (buffer) {
        OsalMemFree(buffer);
        buffer = NULL;
    }
    if (reqMsg) {
        UsbdFreeRequestMsg(reqMsg);
    }
    return ret;
}

static int32_t FunRequestCancel(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct RequestMsg *reqMsg = NULL;
    struct HdfSListNode *requestNode = NULL;
    uint8_t interfaceId = 0;
    uint8_t endpointId = 0;

    if ((port == NULL) || (data == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint8(data, &interfaceId)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint8(data, &endpointId)) {
        HDF_LOGE("%{public}s: invalid parma", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    OsalMutexLock(&port->requestLock);
    if (!HdfSListIsEmpty(&port->requestQueue)) {
        requestNode = HdfSListPop(&port->requestQueue);
    }
    OsalMutexUnlock(&port->requestLock);
    if (requestNode == NULL) {
        HDF_LOGE("%{public}s:%{public}d request node is null", __func__, __LINE__);
        return HDF_SUCCESS;
    }
    reqMsg = HDF_SLIST_CONTAINER_OF(struct HdfSListNode, requestNode, struct RequestMsg, node);
    if (reqMsg == NULL) {
        HDF_LOGE("%{public}s:%{public}d request msg is null", __func__, __LINE__);
        return HDF_FAILURE;
    }
    int32_t ret = UsbCancelRequest(reqMsg->request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d request cancel failed = %{public}d", __func__, __LINE__, ret);
    }
    OsalMSleep(SUBMIT_SLEEP_TIME);
    UsbdFreeRequestMsg(reqMsg);
    return ret;
}

static int32_t ReturnGetPipes(int32_t ret, struct HostDevice *dev)
{
    UsbdCloseInterfaces(dev);
    UsbdReleaseInterfaces(dev);
    UsbExitHostSdk(dev->service->session);
    dev->service->session = NULL;
    return ret;
}

static int32_t ReturnOpenInterfaces(int32_t ret, struct HostDevice *dev)
{
    UsbdReleaseInterfaces(dev);
    UsbExitHostSdk(dev->service->session);
    dev->service->session = NULL;
    return ret;
}

static int32_t ReturnClainInterfaces(int32_t ret, struct HostDevice *dev)
{
    UsbExitHostSdk(dev->service->session);
    dev->service->session = NULL;
    return ret;
}

static int32_t UsbdInit(struct HostDevice *dev)
{
    struct UsbSession *session = NULL;
    HDF_LOGI("%{public}s:%{public}d UsbdInit", __func__, __LINE__);
    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d: invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (dev->initFlag == true) {
        HDF_LOGE("%{public}s:%{public}d: initFlag is true", __func__, __LINE__);
        return HDF_SUCCESS;
    }
    int32_t ret = UsbInitHostSdk(NULL);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbInitHostSdk faild", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (dev->service)
        dev->service->session = session;
    ret = UsbdClaimInterfaces(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbdClaimInterfaces faild ret:%{public}d", __func__, __LINE__, ret);
        return ReturnClainInterfaces(ret, dev);
    }
    ret = UsbdOpenInterfaces(dev);
    HDF_LOGI("%{public}s:%{public}d UsbdOpenInterfaces end ret:%{public}d", __func__, __LINE__, ret);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbdOpenInterfaces faild ret:%{public}d", __func__, __LINE__, ret);
        return ReturnOpenInterfaces(ret, dev);
    }
    ret = UsbdGetCtrlPipe(dev);
    HDF_LOGI("%{public}s:%{public}d UsbdGetCtrlPipe end ret:%{public}d", __func__, __LINE__, ret);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbdGetPipes failed ret:%{public}d", __func__, __LINE__, ret);
        return ReturnGetPipes(ret, dev);
    }

    return HDF_SUCCESS;
}

static void UsbdRelease(struct HostDevice *dev)
{
    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d: invalid parma", __func__, __LINE__);
        return;
    }

    if (dev->initFlag == false) {
        HDF_LOGE("%{public}s:%{public}d: initFlag is false", __func__, __LINE__);
        return;
    }

    UsbdFreeCtrlPipe(dev);
    UsbdCloseInterfaces(dev);
    UsbdReleaseInterfaces(dev);
    UsbExitHostSdk(dev->service->session);
    HDF_LOGI("%{public}s:%{public}d UsbExitHostSdk session:%{public}s ", __func__, __LINE__,
             dev->service->session ? "OK" : "NULL");
    dev->service->session = NULL;
    OsalMutexDestroy(&dev->writeLock);
    OsalMutexDestroy(&dev->readLock);
    OsalMutexDestroy(&dev->lock);
    OsalMutexDestroy(&dev->requestLock);
    dev->busNum = 0;
    dev->devAddr = 0;
    dev->initFlag = false;
}

static int32_t ReturnOpenDevErrFifo(int32_t ret, struct HostDevice *port)
{
    UsbdFreeFifo(&port->readFifo);
    UsbdRelease(port);
    RemoveDevFromService(port->service, port);
    OsalMemFree(port);
    return ret;
}

static int32_t ReturnOpenDevErrInit(int32_t ret, struct HostDevice *port)
{
    UsbdRelease(port);
    RemoveDevFromService(port->service, port);
    OsalMemFree(port);
    return ret;
}

static int32_t FunOpenDevice(struct HostDevice *port, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int ret;
    HDF_LOGI("%{public}s:%{public}d UsbOpen", __func__, __LINE__);
    if ((port == NULL) || (data == NULL) || (reply == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (port->initFlag) {
        HDF_LOGE("%{public}s:%{public}d device is already on flag:%{public}d bus:%{public}d dev:%{public}d", __func__,
                 __LINE__, port->initFlag, port->busNum, port->devAddr);
        return HDF_SUCCESS;
    }
    ret = UsbdInit(port);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbInit failed ret:%{public}d", __func__, __LINE__, ret);
        return ReturnOpenDevErrInit(ret, port);
    }
    ret = UsbdAllocFifo(&port->readFifo, READ_BUF_SIZE);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbAllocFifo failed ret:%{public}d", __func__, __LINE__, ret);
        ret = HDF_ERR_INVALID_PARAM;
        return ReturnOpenDevErrFifo(ret, port);
    }
    port->initFlag = true;
    HDF_LOGI("%{public}s:%{public}d UsbOpen success", __func__, __LINE__);
    OsalMSleep(OPEN_SLEPP_TIME);
    return HDF_SUCCESS;
}

static int32_t FunCloseDevice(struct HostDevice *port, struct HdfSBuf *data)
{
    if (port == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid parma", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!port->initFlag) {
        HDF_LOGE("%{public}s:%{public}d device already close", __func__, __LINE__);
        return HDF_SUCCESS;
    }
    UsbdFreeFifo(&port->readFifo);
    UsbdRelease(port);
    RemoveDevFromService(port->service, port);
    OsalMemFree(port);
    return HDF_SUCCESS;
}

static int32_t FunSetRole(struct HdfSBuf *data, struct HdfSBuf *reply, struct UsbdService *service)
{
    int32_t portId = 0;
    int32_t powerRole = 0;
    int32_t dataRole = 0;
    if (!HdfSbufReadInt32(data, &portId)) {
        HDF_LOGE("%{public}s:%{public}d Read data faild", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (!HdfSbufReadInt32(data, &powerRole)) {
        HDF_LOGE("%{public}s:%{public}d Read data faild", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (!HdfSbufReadInt32(data, &dataRole)) {
        HDF_LOGE("%{public}s:%{public}d Read data faild", __func__, __LINE__);
        return HDF_ERR_IO;
    }

    HDF_LOGI("%{public}s:%{public}d FunSetRole %{public}d %{public}d %{public}d", __func__, __LINE__, portId, powerRole,
             dataRole);
    int32_t ret = SetPort(portId, powerRole, dataRole, service);
    if (ret) {
        HDF_LOGE("%{public}s:%{public}d FunSetRole fasle", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (reply)
        HdfSbufWriteInt32(reply, ret);
    return HDF_SUCCESS;
}

static int32_t FunQueryPort(struct HdfSBuf *data, struct HdfSBuf *reply, struct UsbdService *service)
{
    int32_t portId = 0;
    int32_t powerRole = 0;
    int32_t dataRole = 0;
    int32_t mode = 0;
    int32_t ret = QueryPort(&portId, &powerRole, &dataRole, &mode, service);
    if (ret) {
        HDF_LOGE("%{public}s:%{public}d FunQueryPort fasle", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    if (reply) {
        HdfSbufWriteInt32(reply, portId);
        HdfSbufWriteInt32(reply, powerRole);
        HdfSbufWriteInt32(reply, dataRole);
        HdfSbufWriteInt32(reply, mode);
    }
    return HDF_SUCCESS;
}

static int32_t FunGetCurrentFunctions(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t funcs = UsbdGetFunction();
    HDF_LOGI("%{public}s:%{public}d FunSetCurrentFunctions funcs: %{public}d", __func__, __LINE__, funcs);
    if (reply)
        HdfSbufWriteInt32(reply, funcs);
    return HDF_SUCCESS;
}

static int32_t FunSetCurrentFunctions(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t funcs = 0;
    HdfSbufReadInt32(data, &funcs);
    HDF_LOGI("%{public}s:%{public}d FunSetCurrentFunctions funcs: %{public}d", __func__, __LINE__, funcs);
    int ret = UsbdSetFunction(funcs);
    if (ret) {
        return HDF_ERR_IO;
    }
    return HDF_SUCCESS;
}

static int32_t DispatchBindUsbSubscriber(struct UsbdService *service, struct HdfSBuf *data)
{
    struct UsbdSubscriber *subscriber = NULL;
    HDF_LOGI("%{public}s:%{public}d entry", __func__, __LINE__);
    if (service == NULL || data == NULL) {
        HDF_LOGE("%{public}s:%{public}d param is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct HdfRemoteService *remoteService = HdfSBufReadRemoteService(data);
    if (remoteService == NULL) {
        HDF_LOGE("%{public}s: remoteService is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    subscriber = (struct UsbdSubscriber *)OsalMemCalloc(sizeof(struct UsbdSubscriber));
    if (subscriber == NULL) {
        HDF_LOGE("%{public}s: calloc subscriber error", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    memset_s(subscriber, sizeof(struct UsbdSubscriber), 0, sizeof(struct UsbdSubscriber));
    subscriber->remoteService = remoteService;
    return BindUsbSubscriber(service, subscriber);
}

static int32_t DispatchUnbindUsbSubscriber(struct UsbdService *service)
{
    if (service == NULL) {
        HDF_LOGE("%{public}s:%{public}d param is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return UnbindUsbSubscriber(service);
}

static int32_t DispatchCheckParam(struct HdfDeviceIoClient *client)
{
    if (client == NULL) {
        HDF_LOGE("%{public}s:%{public}d client is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (client->device == NULL) {
        HDF_LOGE("%{public}s:%{public}d client->device is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (client->device->service == NULL) {
        HDF_LOGE("%{public}s:%{public}d client->device->service is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_OBJECT;
    }
    return HDF_SUCCESS;
}

static bool FilterCmd(int cmd)
{
    HDF_LOGI("%{public}s:%{public}d usbd dispatch FilterCmd cmd = %{public}d", __func__, __LINE__, cmd);
    if (cmd != CMD_FUN_GET_CURRENT_FUNCTIONS && cmd != CMD_FUN_SET_CURRENT_FUNCTIONS && cmd != CMD_SET_ROLE &&
        cmd != CMD_QUERY_PORT && CMD_BIND_USB_SUBSCRIBER != cmd && CMD_UNBIND_USB_SUBSCRIBER != cmd) {
        return true;
    }
    return false;
}

int32_t DispatchSwitchHost(int cmd,
                           struct UsbdService *service,
                           struct HostDevice *port,
                           struct HdfSBuf *data,
                           struct HdfSBuf *reply)
{
    switch (cmd) {
        case CMD_FUN_OPEN_DEVICE:
            return FunOpenDevice(port, data, reply);
        case CMD_FUN_CLOSE_DEVICE:
            return FunCloseDevice(port, data);
        case CMD_FUN_SEND_BULK_READ_ASYNC:
            return FunBulkRead(port, data, reply);
        case CMD_FUN_SEND_BULK_WRITE_ASYNC:
            return FunBulkWrite(port, data, reply);
        case CMD_FUN_SEND_BULK_READ_SYNC:
        case CMD_FUN_SEND_INTERRUPT_READ_SYNC:
        case CMD_FUN_SEND_ISO_READ_SYNC:
            return FunBulkReadSync(port, data, reply);
        case CMD_FUN_SEND_BULK_WRITE_SYNC:
        case CMD_FUN_SEND_INTERRUPT_WRITE_SYNC:
        case CMD_FUN_SEND_ISO_WRITE_SYNC:
            return FunBulkWriteSync(port, data, reply);
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
    return HDF_SUCCESS;
}

int32_t DispatchSwitchDevice(int cmd,
                             struct UsbdService *service,
                             struct HostDevice *port,
                             struct HdfSBuf *data,
                             struct HdfSBuf *reply)
{
    switch (cmd) {
        case CMD_SET_ROLE:
            return FunSetRole(data, reply, service);
        case CMD_QUERY_PORT:
            return FunQueryPort(data, reply, service);
        case CMD_FUN_GET_CURRENT_FUNCTIONS:
            return FunGetCurrentFunctions(data, reply);
        case CMD_FUN_SET_CURRENT_FUNCTIONS:
            return FunSetCurrentFunctions(data, reply);
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
    return HDF_SUCCESS;
}

int32_t DispatchSwitch(int cmd,
                       struct UsbdService *service,
                       struct HostDevice *port,
                       struct HdfSBuf *data,
                       struct HdfSBuf *reply)
{
    if (cmd == CMD_FUN_OPEN_DEVICE || cmd == CMD_FUN_CLOSE_DEVICE || cmd == CMD_FUN_SEND_BULK_READ_ASYNC ||
        cmd == CMD_FUN_SEND_BULK_WRITE_ASYNC || cmd == CMD_FUN_SEND_BULK_READ_SYNC ||
        cmd == CMD_FUN_SEND_INTERRUPT_READ_SYNC || cmd == CMD_FUN_SEND_ISO_READ_SYNC ||
        cmd == CMD_FUN_SEND_BULK_WRITE_SYNC || cmd == CMD_FUN_SEND_INTERRUPT_WRITE_SYNC ||
        cmd == CMD_FUN_SEND_ISO_WRITE_SYNC) {
        return DispatchSwitchHost(cmd, service, port, data, reply);
    }
    if (cmd == CMD_SET_ROLE || cmd == CMD_QUERY_PORT || cmd == CMD_FUN_GET_CURRENT_FUNCTIONS ||
        cmd == CMD_FUN_SET_CURRENT_FUNCTIONS) {
        return DispatchSwitchDevice(cmd, service, port, data, reply);
    }

    switch (cmd) {
        case CMD_BIND_USB_SUBSCRIBER:
            return DispatchBindUsbSubscriber(service, data);
        case CMD_UNBIND_USB_SUBSCRIBER:
            return DispatchUnbindUsbSubscriber(service);
        case CMD_FUN_SEND_CTRL_REQUEST_SYNC:
            return FunControlTransfer(port, data, reply);
        case CMD_FUN_GET_DEVICE_DESCRIPTOR:
            return FunGetDeviceDescriptor(port, reply);
        case CMD_FUN_GET_CONFIG_DESCRIPTOR:
            return FunGetConfigDescriptor(port, data, reply);
        case CMD_FUN_GET_STRING_DESCRIPTOR:
            return FunGetStringDescriptor(port, data, reply);
        case CMD_FUN_REQUEST_QUEUE:
            return FunRequestQueue(port, data, reply);
        case CMD_FUN_REQUEST_WAIT:
            return FunRequestWait(port, data, reply);
        case CMD_FUN_REQUEST_CANCEL:
            return FunRequestCancel(port, data, reply);
        case CMD_FUN_CLAIM_INTERFACE:
            return FunClaimInterface(port, data);
        case CMD_FUN_RELEASE_INTERFACE:
            return FunReleaseInterface(port, data);
        case CMD_FUN_SET_CONFIG:
            return FunSetActiveConfig(port, data, reply);
        case CMD_FUN_GET_CONFIG:
            return FunGetActiveConfig(port, data, reply);
        case CMD_FUN_SET_INTERFACE:
            return FunSetInterface(port, data, reply);
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
    return HDF_SUCCESS;
}

int32_t DispatchCmdOpenDevice(struct HostDevice **port, uint8_t busNum, uint8_t devAddr, struct UsbdService *service)
{
    int32_t ret = HDF_ERR_INVALID_PARAM;
    if (!(*port)) {
        ret = HostDeviceCreate(port);
        HDF_LOGI(
            "%{public}s:%{public}d OpenDevice ret:%{public}d busNum:%{public}d devAddr:%{public}d "
            "port:%{public}p",
            __func__, __LINE__, ret, busNum, devAddr, *port);
        if ((HDF_SUCCESS == ret) && (*port)) {
            (*port)->service = service;
            (*port)->busNum = busNum;
            (*port)->devAddr = devAddr;
            OsalMutexLock(&service->lock);
            HdfSListAdd(&service->devList, &(*port)->node);
            OsalMutexUnlock(&service->lock);
        }
    }
    return ret;
}

int32_t UsbdServiceDispatch(struct HdfDeviceIoClient *client, int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct UsbdService *service = NULL;
    struct HostDevice *port = NULL;
    if (DispatchCheckParam(client) != HDF_SUCCESS) {
        return HDF_ERR_INVALID_OBJECT;
    }
    HDF_LOGI("%{public}s:%{public}d usbd dispatch cmd = %{public}d", __func__, __LINE__, cmd);
    service = (struct UsbdService *)client->device->service;
    if (FilterCmd(cmd)) {
        uint8_t busNum = 0;
        uint8_t devAddr = 0;
        int32_t ret = ParseDeviceBuf(data, &busNum, &devAddr);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:%{public}d cmd = %{public}d parse error:%{public}d", __func__, __LINE__, cmd, ret);
            return ret;
        }
        port = FindDevFromService(service, busNum, devAddr);
        switch (cmd) {
            case CMD_FUN_OPEN_DEVICE:
                ret = DispatchCmdOpenDevice(&port, busNum, devAddr, service);
                if (ret != HDF_SUCCESS) {
                    HDF_LOGE("%{public}s:%{public}d DispatchCmdOpenDevice fail", __func__, __LINE__);
                    return ret;
                }
                break;
            default:
                if (!port) {
                    HDF_LOGE("%{public}s:%{public}d cmd = %{public}d busNum:%{public}d devAddr:%{public}d no device",
                             __func__, __LINE__, cmd, busNum, devAddr);
                    return HDF_DEV_ERR_NO_DEVICE;
                }
                break;
        }
    }
    HDF_LOGI("%{public}s:%{public}d cmd = %{public}d port:%{public}p", __func__, __LINE__, cmd, port);
    return DispatchSwitch(cmd, service, port, data, reply);
}

static int32_t HostDeviceInit(struct HostDevice *port)
{
    if (!port) {
        HDF_LOGE("%{public}s:%{public}d param failed", __func__, __LINE__);
        return HDF_ERR_INVALID_OBJECT;
    }
    port->busNum = 0;
    port->devAddr = 0;
    port->initFlag = false;
    port->interfaceCnt = 0;

    if (OsalMutexInit(&port->lock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d init lock fail!", __func__, __LINE__);
        return HDF_FAILURE;
    }
    if (OsalMutexInit(&port->requestLock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d init lock fail!", __func__, __LINE__);
        return HDF_FAILURE;
    }
    if (OsalMutexInit(&port->writeLock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d init lock fail!", __func__, __LINE__);
        return HDF_FAILURE;
    }
    if (OsalMutexInit(&port->readLock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d init lock fail!", __func__, __LINE__);
        return HDF_FAILURE;
    }
    HdfSListInit(&port->requestQueue);
    return HDF_SUCCESS;
}

int32_t HostDeviceCreate(struct HostDevice **port)
{
    struct HostDevice *tmp = NULL;
    if (!port) {
        return HDF_FAILURE;
    }
    tmp = (struct HostDevice *)OsalMemCalloc(sizeof(struct HostDevice));
    if (!tmp) {
        HDF_LOGE("%{public}s:%{public}d Alloc usb host device failed", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }
    memset_s(tmp, sizeof(struct HostDevice), 0, sizeof(struct HostDevice));

    int32_t ret = HostDeviceInit(tmp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d HostDeviceInit fail!", __func__, __LINE__);
        OsalMemFree(tmp);
        return ret;
    }

    tmp->initFlag = false;
    *port = tmp;
    return HDF_SUCCESS;
}

int32_t UsbdRealseDevices(struct UsbdService *service)
{
    if (!service) {
        return HDF_ERR_INVALID_PARAM;
    }
    OsalMutexLock(&service->lock);
    while (!HdfSListIsEmpty(&service->devList)) {
        struct HostDevice *port = (struct HostDevice *)HdfSListPop(&service->devList);
        if (port) {
            UsbdRelease(port);
            OsalMemFree(port);
        }
    }
    OsalMutexUnlock(&service->lock);
    return HDF_SUCCESS;
}

static struct HostDevice *FindDevFromService(struct UsbdService *service, uint8_t busNum, uint8_t devAddr)
{
    struct HdfSListIterator it;
    struct HostDevice *port = NULL;
    bool flag = false;
    if (!service) {
        return NULL;
    }

    OsalMutexLock(&service->lock);
    HdfSListIteratorInit(&it, &service->devList);
    while (HdfSListIteratorHasNext(&it)) {
        port = (struct HostDevice *)HdfSListIteratorNext(&it);
        if (!port) {
            continue;
        }
        if ((port->busNum == busNum) && (port->devAddr == devAddr)) {
            flag = true;
            break;
        }
    }
    OsalMutexUnlock(&service->lock);
    if (!flag) {
        return NULL;
    }
    return port;
}

static void RemoveDevFromService(struct UsbdService *service, struct HostDevice *port)
{
    struct HdfSListIterator it;
    struct HostDevice *tport = NULL;
    if (!service || !port) {
        return;
    }

    OsalMutexLock(&service->lock);
    HdfSListIteratorInit(&it, &service->devList);
    while (HdfSListIteratorHasNext(&it)) {
        tport = (struct HostDevice *)HdfSListIteratorNext(&it);
        if (!tport) {
            continue;
        }
        if ((tport->busNum == port->busNum) && (tport->devAddr == port->devAddr)) {
            HdfSListIteratorRemove(&it);
            break;
        }
    }
    OsalMutexUnlock(&service->lock);

    return;
}
