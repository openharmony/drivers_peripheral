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

#include "usb_io_manage.h"
#include "osal_time.h"
#include "usb_raw_api_library.h"

#define HDF_LOG_TAG USB_IO_MANAGE

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

static int IoSendProcess(void *interfacePoolArg)
{
    if (interfacePoolArg == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbInterfacePool *interfacePool = (struct UsbInterfacePool *)interfacePoolArg;
    struct UsbHostRequest *submitRequest = NULL;
    int ret;
    int i;

    while (true) {
        if (interfacePool == NULL) {
            HDF_LOGE("%{public}s:%{public}d interfacePool is NULL", __func__, __LINE__);
            OsalMSleep(USB_IO_SLEEP_MS_TIME);
            continue;
        }

        /* Get a request from curretn submit queue */
        ret = UsbIoGetRequest(&interfacePool->submitRequestQueue, &submitRequest);

        if (interfacePool->ioProcessStopStatus != USB_POOL_PROCESS_RUNNING) {
            break;
        }

        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:%{public}d UsbIoGetRequest faile, ret=%{public}d ",
                __func__, __LINE__, ret);
            continue;
        }

        if (submitRequest == NULL) {
            continue;
        }

        if (IoCancelRequest(interfacePool, submitRequest) == true) {
            continue;
        }

        /* The Submit request operation is retried up to
         * USB_IO_SUBMIT_RETRY_TIME_CNT times. */
        for (i = 0; i < USB_IO_SUBMIT_RETRY_TIME_CNT; i++) {
            ret = RawSubmitRequest(submitRequest);
            if (ret != HDF_SUCCESS) {
                HDF_LOGE("%{public}s:%{public}d RawSubmitRequest failed, i=%{public}d, ret=%{public}d",
                    __func__, __LINE__, i, ret);
                continue;
            }
            /* Submit success */
            break;
        }

        if (i >= USB_IO_SUBMIT_RETRY_TIME_CNT) {
            HDF_LOGE("%{public}s:%{public}d submit request failes", __func__, __LINE__);
            /* If submit request fails, the corresponding status is set and
             * the callback function is called */
            submitRequest->status = USB_REQUEST_ERROR;
            UsbIoSetRequestCompletionInfo(submitRequest);
            continue;
        }
    }

    return 0;
}

static int IoAsyncReceiveProcess(void *interfacePoolArg)
{
    if (interfacePoolArg == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbInterfacePool *interfacePool = (struct UsbInterfacePool *)interfacePoolArg;
    int ret;

    if (RawRegisterSignal() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d RawRegisterSignal error", __func__, __LINE__);
    }
    interfacePool->ioProcessTid = RawGetTid();

    while (true) {
        if (interfacePool == NULL) {
            HDF_LOGE("%{public}s:%{public}d interfacePool is NULL", __func__, __LINE__);
            OsalMSleep(USB_IO_SLEEP_MS_TIME);
            return HDF_FAILURE;
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


        ret = RawHandleRequest(interfacePool->device->devHandle, NULL);
        if ((ret < 0) || (interfacePool->ioProcessStopStatus != USB_POOL_PROCESS_RUNNING)) {
            HDF_LOGE("%{public}s:%{public}d RawHandleRequest faile, stopStatus=%{public}d ret=%{public}d ",
                __func__, __LINE__, interfacePool->ioProcessStopStatus, ret);
            break;
        }
    }

    OsalMutexLock(&interfacePool->ioStopLock);
    interfacePool->ioProcessStopStatus = USB_POOL_PROCESS_STOPED;
    OsalMutexUnlock(&interfacePool->ioStopLock);

    return HDF_SUCCESS;
}

HDF_STATUS UsbIoCreateQueue(struct UsbInterfacePool *interfacePool)
{
    if (interfacePool == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    DListHeadInit(&interfacePool->submitRequestQueue.entry);
    OsalMutexInit(&interfacePool->submitRequestQueue.mutex);
    OsalSemInit(&interfacePool->submitRequestQueue.sem, 0);

    return HDF_SUCCESS;
}

HDF_STATUS UsbIoDestroyQueue(struct UsbInterfacePool *interfacePool)
{
    if (interfacePool == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!DListIsEmpty(&interfacePool->submitRequestQueue.entry)) {
        HDF_LOGE("%{public}s:%{public}d submitRequestQueue is not empty", __func__, __LINE__);
        return HDF_FAILURE;
    }

    OsalMutexDestroy(&interfacePool->submitRequestQueue.mutex);
    OsalSemDestroy(&interfacePool->submitRequestQueue.sem);

    return HDF_SUCCESS;
}

int32_t UsbIoSendRequest(struct UsbMessageQueue *msgQueue, struct UsbHostRequest *request)
{

    if ((msgQueue == NULL) || (request == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parameter", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    OsalMutexLock(&msgQueue->mutex);
    DListInsertTail(&request->list, &msgQueue->entry);
    OsalMutexUnlock(&msgQueue->mutex);

    OsalSemPost(&msgQueue->sem);

    return HDF_SUCCESS;
}

HDF_STATUS UsbIoGetRequest(struct UsbMessageQueue *msgQueue, struct UsbHostRequest **request)
{
    HDF_STATUS ret;
    struct UsbHostRequest *reqEntry = NULL;

    if ((msgQueue == NULL) || (request == NULL)) {
        ret = HDF_ERR_INVALID_OBJECT;
        HDF_LOGE("%{public}s:%{public}d invalid parameter", __func__, __LINE__);
        goto error;
    }

    ret = OsalSemWait(&msgQueue->sem, HDF_WAIT_FOREVER);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalSemWait faile, ret=%{public}d\n",
            __func__, __LINE__, ret);
        goto error;
    }
    if (DListIsEmpty(&msgQueue->entry))
    {
        ret = HDF_SUCCESS;
        goto error;
    }

    OsalMutexLock(&msgQueue->mutex);
    if (msgQueue->entry.next == NULL) {
        ret = HDF_ERR_INVALID_OBJECT;
        OsalMutexUnlock(&msgQueue->mutex);
        goto error;
    }
    reqEntry = DLIST_FIRST_ENTRY(&msgQueue->entry, struct UsbHostRequest, list);
    if (reqEntry == NULL) {
        ret = HDF_ERR_INVALID_OBJECT;
        OsalMutexUnlock(&msgQueue->mutex);
        goto error;
    }
    DListRemove(&reqEntry->list);
    *request = (struct UsbHostRequest *)reqEntry;
    OsalMutexUnlock(&msgQueue->mutex);

    return HDF_SUCCESS;

error:
    *request = NULL;
    return ret;
}

HDF_STATUS UsbIoStart(struct UsbInterfacePool *interfacePool)
{
    HDF_STATUS ret;
    struct OsalThreadParam threadCfg;

    if (interfacePool == NULL) {
        HDF_LOGE("%{public}s:%{public}d", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    OsalMutexLock(&interfacePool->ioStopLock);
    interfacePool->ioProcessStopStatus = USB_POOL_PROCESS_RUNNING;
    OsalMutexUnlock(&interfacePool->ioStopLock);

    /* creat IoSendProcess thread */
    (void)memset_s(&threadCfg, sizeof(threadCfg), 0, sizeof(threadCfg));
    threadCfg.name = "usb io send process";
    threadCfg.priority = OSAL_THREAD_PRI_DEFAULT;
    threadCfg.stackSize = USB_IO_SEND_PROCESS_STACK_SIZE;

    ret = OsalThreadCreate(&interfacePool->ioSendProcess, (OsalThreadEntry)IoSendProcess, (void *)interfacePool);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadCreate faile, ret=%{public}d ",
            __func__, __LINE__, ret);
        return ret;
    }

    ret = OsalThreadStart(&interfacePool->ioSendProcess, &threadCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadStart faile, ret=%{public}d ",
            __func__, __LINE__, ret);
        goto ERR_DESTROY_SEND;
    }

    /* creat IoAsyncReceiveProcess thread */
    (void)memset_s(&threadCfg, sizeof(threadCfg), 0, sizeof(threadCfg));
    threadCfg.name = "usb io async receive process";
    threadCfg.priority = OSAL_THREAD_PRI_DEFAULT;
    threadCfg.stackSize = USB_IO_RECEIVE_PROCESS_STACK_SIZE;

    ret = OsalThreadCreate(&interfacePool->ioAsyncReceiveProcess, \
        (OsalThreadEntry)IoAsyncReceiveProcess, (void *)interfacePool);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadCreate faile, ret=%{public}d ",
            __func__, __LINE__, ret);
        goto ERR_DESTROY_SEND;
    }

    ret = OsalThreadStart(&interfacePool->ioAsyncReceiveProcess, &threadCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadStart faile, ret=%{public}d ",
            __func__, __LINE__, ret);
        goto ERR_DESTROY_RECV;
    }

    return HDF_SUCCESS;

ERR_DESTROY_SEND:
    OsalThreadDestroy(&interfacePool->ioAsyncReceiveProcess);
ERR_DESTROY_RECV:
    OsalThreadDestroy(&interfacePool->ioSendProcess);

    return ret;
}

HDF_STATUS UsbIoStop(struct UsbInterfacePool *interfacePool)
{
    HDF_STATUS ret;
    int32_t i = 0;

    if (interfacePool == NULL) {
        HDF_LOGE("%{public}s:%{public}d", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if ((interfacePool->ioProcessStopStatus != USB_POOL_PROCESS_STOPED)) {
        HDF_LOGD("%{public}s:%{public}d not stoped", __func__, __LINE__);
        OsalMutexLock(&interfacePool->ioStopLock);
        interfacePool->ioProcessStopStatus = USB_POOL_PROCESS_STOP;
        OsalSemPost(&interfacePool->submitRequestQueue.sem);
        OsalMutexUnlock(&interfacePool->ioStopLock);

        if (RawKillSignal(interfacePool->device->devHandle, interfacePool->ioProcessTid) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:%{public}d RawKillSignal ioProcessTid=%{public}d failed",
                __func__, __LINE__, interfacePool->ioProcessTid);
        }
    } else {
        HDF_LOGD("%{public}s:%{public}d stoped", __func__, __LINE__);
    }

    while (interfacePool->ioProcessStopStatus != USB_POOL_PROCESS_STOPED) {
        i++;
        OsalMSleep(USB_IO_SLEEP_MS_TIME);
        if (i > USB_IO_STOP_WAIT_MAX_TIME) {
            HDF_LOGD("%{public}s:%{public}d", __func__, __LINE__);
            break;
        }
    }

    ret = OsalThreadDestroy(&interfacePool->ioSendProcess);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadDestroy faile, ret=%{public}d ", \
            __func__, __LINE__, ret);
        return ret;
    }

    ret = OsalThreadDestroy(&interfacePool->ioAsyncReceiveProcess);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadDestroy faile, ret=%{public}d ",
            __func__, __LINE__, ret);
    }

    OsalMutexDestroy(&interfacePool->ioStopLock);

    return ret;
}

void UsbIoSetRequestCompletionInfo(void *requestArg)
{
    if (requestArg == NULL) {
        HDF_LOGE("%{public}s:%{public}d parameter error. ", __func__, __LINE__);
        return;
    }

    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)requestArg;
    struct UsbIfRequest *requestObj = NULL;

    if (hostRequest == NULL) {
        HDF_LOGE("%{public}s:%{public}d hostRequest is NULL ", __func__, __LINE__);
        return;
    }

    requestObj = (struct UsbIfRequest *)hostRequest->privateObj;
    if (requestObj == NULL) {
        HDF_LOGE("%{public}s:%{public}d get request error. ", __func__, __LINE__);
        return;
    }
    requestObj->request.compInfo.buffer = hostRequest->buffer;
    requestObj->request.compInfo.length = hostRequest->length;
    requestObj->request.compInfo.actualLength = hostRequest->actualLength;
    requestObj->request.compInfo.status = hostRequest->status;
    requestObj->request.compInfo.userData = hostRequest->userData;
    if ((hostRequest->requestType & USB_DDK_ENDPOINT_XFERTYPE_MASK) == USB_DDK_ENDPOINT_XFER_CONTROL) {
        requestObj->request.compInfo.buffer = requestObj->request.compInfo.buffer + USB_RAW_CONTROL_SETUP_SIZE;
    }

    if (requestObj->isSyncReq) {
        OsalSemPost(&requestObj->sem);
    }

    /* Fill in the request completion information. */
    /* Call user callback function. */
    if (hostRequest->userCallback) {
        hostRequest->userCallback(&requestObj->request);
    }
}
