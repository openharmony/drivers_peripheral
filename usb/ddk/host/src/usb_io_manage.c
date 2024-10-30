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

#include "usb_io_manage.h"
#include "usb_raw_api_library.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG USB_IO_MANAGE

static const int MAX_ERROR_TIMES = 20;

static bool IoCancelRequest(struct UsbInterfacePool *interfacePool, const struct UsbHostRequest *hostRequest)
{
    struct UsbIfRequest *requestObj = NULL;

    if (hostRequest == NULL) {
        HDF_LOGE("%{public}s:%{public}d hostRequest is NULL", __func__, __LINE__);
        return true;
    }

    requestObj = (struct UsbIfRequest *)hostRequest->privateObj;
    if (requestObj == NULL) {
        HDF_LOGE("%{public}s:%{public}d get request error", __func__, __LINE__);
        return true;
    }

    if (interfacePool->ioProcessStopStatus != USB_POOL_PROCESS_RUNNING) {
        UsbCancelRequest(&requestObj->request);
    }

    return (requestObj->request.compInfo.status == USB_REQUEST_CANCELLED);
}

static int32_t IoSendProcess(const void *interfacePoolArg)
{
    if (interfacePoolArg == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbInterfacePool *interfacePool = (struct UsbInterfacePool *)interfacePoolArg;
    struct UsbHostRequest *submitRequest = NULL;
    int32_t ret;
    int32_t i;
    int32_t errorTimes = 0;

    while (errorTimes < MAX_ERROR_TIMES) {
        submitRequest = NULL;
        /* Get a request from curretn submit queue */
        ret = UsbIoGetRequest(&interfacePool->submitRequestQueue, &submitRequest);

        if (interfacePool->ioProcessStopStatus != USB_POOL_PROCESS_RUNNING) {
            if (submitRequest != NULL) {
                submitRequest->status = USB_REQUEST_ERROR;
                UsbIoSetRequestCompletionInfo(submitRequest);
            }
            break;
        }

        if (ret != HDF_SUCCESS || submitRequest == NULL) {
            ++errorTimes;
            HDF_LOGE("%{public}s:%{public}d ret=%{public}d errtimes=%{public}d", __func__, __LINE__, ret, errorTimes);
            continue;
        }
        errorTimes = 0;

        if (IoCancelRequest(interfacePool, submitRequest)) {
            continue;
        }

        for (i = 0; i < USB_IO_SUBMIT_RETRY_TIME_CNT; i++) {
            ret = RawSubmitRequest(submitRequest);
            if (ret != HDF_SUCCESS) {
                continue;
            }
            /* Submit success */
            OsalSemPost(&interfacePool->ioSem);
            break;
        }

        if (i >= USB_IO_SUBMIT_RETRY_TIME_CNT) {
            HDF_LOGE("%{public}s:%{public}d submit request failed", __func__, __LINE__);
            submitRequest->status = USB_REQUEST_ERROR;
            UsbIoSetRequestCompletionInfo(submitRequest);
            continue;
        }
    }
    HDF_LOGE("%{public}s, stop. errorTimes=%{public}d", __func__, errorTimes);
    return 0;
}

static int32_t IoAsyncReceiveProcess(const void *interfacePoolArg)
{
    if (interfacePoolArg == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbInterfacePool *interfacePool = (struct UsbInterfacePool *)interfacePoolArg;
    if (RawRegisterSignal() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d RawRegisterSignal error", __func__, __LINE__);
    }

    HDF_LOGD("%{public}s, enter recv thread", __func__);
    while (true) {
        if (!interfacePool->ioProcessTid) {
            interfacePool->ioProcessTid = RawGetTid();
        }

        if (interfacePool->device == NULL) {
            HDF_LOGE("%{public}s:%{public}d interfacePool->device is NULL!", __func__, __LINE__);
            OsalMSleep(USB_IO_SLEEP_MS_TIME);
            continue;
        }

        if (interfacePool->device->devHandle == NULL) {
            HDF_LOGE("%{public}s:%{public}d interfacePool->device->devHandle is NULL!", __func__, __LINE__);
            OsalMSleep(USB_IO_SLEEP_MS_TIME);
            continue;
        }

        int32_t ret = OsalSemWait(&interfacePool->ioSem, HDF_WAIT_FOREVER);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("sem wait failed: %{public}d", ret);
        }

        if (interfacePool->ioProcessStopStatus != USB_POOL_PROCESS_RUNNING ||
            interfacePool->ioRecvProcessStopStatus != USB_POOL_PROCESS_RUNNING) {
            break;
        }

        ret = RawHandleRequest(interfacePool->device->devHandle);
        if (ret == HDF_DEV_ERR_NO_DEVICE) {
            HDF_LOGE("%{public}s dev is not found ret: %{public}d", __func__, ret);
        }
        if (ret < 0) {
            HDF_LOGE("%{public}s RawHandleRequest failed ret: %{public}d", __func__, ret);
            OsalMSleep(USB_IO_SLEEP_MS_TIME);
            continue;
        }
    }
    HDF_LOGE("%{public}s, recv thread end. ", __func__);
    OsalMutexLock(&interfacePool->ioStopLock);
    interfacePool->ioProcessStopStatus = USB_POOL_PROCESS_STOPED;
    interfacePool->ioRecvProcessStopStatus = USB_POOL_PROCESS_STOPED;
    OsalSemPost(&interfacePool->submitRequestQueue.sem);
    OsalMutexUnlock(&interfacePool->ioStopLock);

    return HDF_SUCCESS;
}

HDF_STATUS UsbIoCreateQueue(const struct UsbInterfacePool *interfacePool)
{
    if (interfacePool == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    DListHeadInit((struct DListHead *)&interfacePool->submitRequestQueue.entry);
    OsalMutexInit((struct OsalMutex *)&interfacePool->submitRequestQueue.mutex);
    OsalSemInit((struct OsalSem *)&interfacePool->submitRequestQueue.sem, 0);

    return HDF_SUCCESS;
}

HDF_STATUS UsbIoDestroyQueue(const struct UsbInterfacePool *interfacePool)
{
    if (interfacePool == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!DListIsEmpty(&interfacePool->submitRequestQueue.entry)) {
        HDF_LOGE("%{public}s:%{public}d submitRequestQueue is not empty", __func__, __LINE__);
        return HDF_FAILURE;
    }

    OsalMutexDestroy((struct OsalMutex *)&interfacePool->submitRequestQueue.mutex);
    OsalSemDestroy((struct OsalSem *)&interfacePool->submitRequestQueue.sem);

    return HDF_SUCCESS;
}

int32_t UsbIoSendRequest(const struct UsbMessageQueue *msgQueue, const struct UsbHostRequest *request)
{
    if ((msgQueue == NULL) || (request == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parameter", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    OsalMutexLock((struct OsalMutex *)&msgQueue->mutex);
    DListInsertTail((struct DListHead *)&request->list, (struct DListHead *)&msgQueue->entry);
    OsalMutexUnlock((struct OsalMutex *)&msgQueue->mutex);

    OsalSemPost((struct OsalSem *)&msgQueue->sem);

    return HDF_SUCCESS;
}

HDF_STATUS UsbIoGetRequest(const struct UsbMessageQueue *msgQueue, struct UsbHostRequest **request)
{
    HDF_STATUS ret;
    struct UsbHostRequest *reqEntry = NULL;

    if ((msgQueue == NULL) || (request == NULL)) {
        ret = HDF_ERR_INVALID_OBJECT;
        HDF_LOGE("%{public}s:%{public}d invalid parameter", __func__, __LINE__);
        return ret;
    }

    ret = OsalSemWait((struct OsalSem *)&msgQueue->sem, HDF_WAIT_FOREVER);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalSemWait failed, ret=%{public}d", __func__, __LINE__, ret);
        goto ERROR;
    }
    if (DListIsEmpty(&msgQueue->entry)) {
        ret = HDF_SUCCESS;
        goto ERROR;
    }

    OsalMutexLock((struct OsalMutex *)&msgQueue->mutex);
    if (msgQueue->entry.next == NULL || msgQueue->entry.next->prev == NULL || msgQueue->entry.prev == NULL || msgQueue->entry.prev->next == NULL) {
        ret = HDF_ERR_INVALID_OBJECT;
        OsalMutexUnlock((struct OsalMutex *)&msgQueue->mutex);
        goto ERROR;
    }
    reqEntry = DLIST_FIRST_ENTRY(&msgQueue->entry, struct UsbHostRequest, list);
    if (reqEntry == NULL || reqEntry->list.prev == NULL || reqEntry->list.next == NULL ||
        reqEntry->list.prev->next != &reqEntry->list || reqEntry->list.next->prev != &reqEntry->list) {
        ret = HDF_ERR_INVALID_OBJECT;
        HDF_LOGE("%{public}s:%{public}d list node is invalid", __func__, __LINE__);
        OsalMutexUnlock((struct OsalMutex *)&msgQueue->mutex);
        goto ERROR;
    }
    DListRemove(&reqEntry->list);
    *request = (struct UsbHostRequest *)reqEntry;
    OsalMutexUnlock((struct OsalMutex *)&msgQueue->mutex);

    return HDF_SUCCESS;

ERROR:
    *request = NULL;
    return ret;
}

HDF_STATUS UsbIoStart(struct UsbInterfacePool *interfacePool)
{
    struct OsalThreadParam threadCfg;
    if (interfacePool == NULL) {
        HDF_LOGE("%{public}s:%{public}d", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    OsalMutexLock(&interfacePool->ioStopLock);
    interfacePool->ioProcessStopStatus = USB_POOL_PROCESS_RUNNING;
    interfacePool->ioRecvProcessStopStatus = USB_POOL_PROCESS_RUNNING;
    OsalSemInit(&interfacePool->ioSem, 0);
    OsalMutexUnlock(&interfacePool->ioStopLock);

    /* create IoSendProcess thread */
    HDF_STATUS ret = memset_s(&threadCfg, sizeof(threadCfg), 0, sizeof(threadCfg));
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memset_s failed", __func__, __LINE__);
        return ret;
    }
    threadCfg.name = "usb io send process";
    threadCfg.priority = OSAL_THREAD_PRI_DEFAULT;
    threadCfg.stackSize = USB_IO_SEND_PROCESS_STACK_SIZE;

    ret = OsalThreadCreate(&interfacePool->ioSendProcess, (OsalThreadEntry)IoSendProcess, (void *)interfacePool);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadCreate failed, ret=%{public}d ", __func__, __LINE__, ret);
        return ret;
    }

    ret = OsalThreadStart(&interfacePool->ioSendProcess, &threadCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadStart failed, ret=%{public}d ", __func__, __LINE__, ret);
        goto ERR_DESTROY_SEND;
    }

    /* create IoAsyncReceiveProcess thread */
    (void)memset_s(&threadCfg, sizeof(threadCfg), 0, sizeof(threadCfg));
    threadCfg.name = "usb io async receive process";
    threadCfg.priority = OSAL_THREAD_PRI_DEFAULT;
    threadCfg.stackSize = USB_IO_RECEIVE_PROCESS_STACK_SIZE;

    ret = OsalThreadCreate(&interfacePool->ioAsyncReceiveProcess, (void *)IoAsyncReceiveProcess, (void *)interfacePool);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadCreate failed, ret=%{public}d ", __func__, __LINE__, ret);
        goto ERR_DESTROY_SEND;
    }

    ret = OsalThreadStart(&interfacePool->ioAsyncReceiveProcess, &threadCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadStart failed, ret=%{public}d ", __func__, __LINE__, ret);
        goto ERR_DESTROY_RECV;
    }

    return HDF_SUCCESS;

ERR_DESTROY_SEND:
    OsalThreadDestroy(&interfacePool->ioAsyncReceiveProcess);
ERR_DESTROY_RECV:
    OsalThreadDestroy(&interfacePool->ioSendProcess);

    return ret;
}

HDF_STATUS UsbIoRecvProcessStop(struct UsbInterfacePool *interfacePool)
{
    if ((interfacePool == NULL) || (interfacePool->device == NULL) || (interfacePool->device->devHandle == NULL)) {
        HDF_LOGE("%{public}s:%{public}d param is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if ((interfacePool->ioRecvProcessStopStatus != USB_POOL_PROCESS_STOPED)) {
        OsalMutexLock(&interfacePool->ioStopLock);
        interfacePool->ioRecvProcessStopStatus = USB_POOL_PROCESS_STOP;
        OsalSemPost(&interfacePool->submitRequestQueue.sem);
        OsalMutexUnlock(&interfacePool->ioStopLock);
    }
    return HDF_SUCCESS;
}

HDF_STATUS UsbIoStop(struct UsbInterfacePool *interfacePool)
{
    if ((interfacePool == NULL) || (interfacePool->device == NULL) || (interfacePool->device->devHandle == NULL)) {
        HDF_LOGE("%{public}s:%{public}d param is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if ((interfacePool->ioProcessStopStatus != USB_POOL_PROCESS_STOPED)) {
        OsalMutexLock(&interfacePool->ioStopLock);
        interfacePool->ioProcessStopStatus = USB_POOL_PROCESS_STOP;
        OsalSemPost(&interfacePool->ioSem);
        OsalSemPost(&interfacePool->submitRequestQueue.sem);
        OsalMutexUnlock(&interfacePool->ioStopLock);

        if (RawKillSignal(interfacePool->device->devHandle, interfacePool->ioProcessTid) != HDF_SUCCESS) {
            HDF_LOGE(
                "%{public}s:%{public}d RawKillSignal ioProcessTid=%{public}d failed",
                __func__, __LINE__, interfacePool->ioProcessTid);
        }
    }
    int32_t i = 0;
    while (interfacePool->ioProcessStopStatus != USB_POOL_PROCESS_STOPED) {
        i++;
        OsalMSleep(USB_IO_SLEEP_MS_TIME);
        if (i > USB_IO_STOP_WAIT_MAX_TIME) {
            HDF_LOGD("%{public}s:%{public}d", __func__, __LINE__);
            break;
        }
    }

    HDF_STATUS ret = OsalThreadDestroy(&interfacePool->ioSendProcess);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadDestroy failed, ret=%{public}d ", __func__, __LINE__, ret);
        return ret;
    }
    ret = OsalThreadDestroy(&interfacePool->ioAsyncReceiveProcess);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadDestroy failed, ret=%{public}d ", __func__, __LINE__, ret);
    } else {
        OsalSemDestroy(&interfacePool->ioSem);
    }
    return ret;
}

void UsbIoSetRequestCompletionInfo(const void *requestArg)
{
    if (requestArg == NULL) {
        HDF_LOGE("%{public}s:%{public}d parameter error. ", __func__, __LINE__);
        return;
    }

    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)requestArg;
    struct UsbIfRequest *requestObj = (struct UsbIfRequest *)hostRequest->privateObj;
    if (requestObj == NULL) {
        HDF_LOGE("%{public}s:%{public}d get request error. ", __func__, __LINE__);
        return;
    }
    requestObj->request.compInfo.buffer = hostRequest->buffer;
    requestObj->request.compInfo.length = hostRequest->length;
    requestObj->request.compInfo.actualLength = (uint32_t)hostRequest->actualLength;
    requestObj->request.compInfo.status = hostRequest->status;
    requestObj->request.compInfo.userData = hostRequest->userData;
    if ((hostRequest->requestType & USB_DDK_ENDPOINT_XFERTYPE_MASK) == USB_DDK_ENDPOINT_XFER_CONTROL) {
        requestObj->request.compInfo.buffer = requestObj->request.compInfo.buffer + USB_RAW_CONTROL_SETUP_SIZE;
    }

    /* Fill in the request completion information. */
    /* Call user callback function. */
    if (hostRequest->userCallback) {
        hostRequest->userCallback(&requestObj->request);
    }

    if (requestObj->isSyncReq) {
        OsalSemPost(&hostRequest->sem);
    }
}
