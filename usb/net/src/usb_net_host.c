/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <fcntl.h>

#include "hdf_usb_pnp_manage.h"
#include "cdc_ether.h"
#include "usb_net_host.h"

#define HDF_LOG_TAG             usb_net_host
#define USB_NET_SERVICE_NAME    "hdf_usb_net_service"
#define MAX_QUEUE_MEMORY        (60 * 1518)
#define PRINT_LINE_MAX          32
#define USBNET_QLEN_TIME        5
#define USBNET_QLEN_DEFAULT     4

uint32_t g_sendToUrbTimes = 0;
uint32_t g_sendToUrbSuccessTimes = 0;
uint32_t g_sendToUrbReadTimes = 0;

static int printf_char_buffer(char *buff, int size, bool isPrint)
{
    if (isPrint) {
        int i = 0;
        HDF_LOGI("===-harch-=== printf_char_buffer begin\n");
        for (i = 0; i < size; i++) {
            HDF_LOGI("%{public}02x ", buff[i]);
            if ((i + 1) % PRINT_LINE_MAX == 0) {
                HDF_LOGI("");
            }
        }
        HDF_LOGI("===-harch-=== printf_char_buffer end\n");
    }
    return 0;
}

void UsbnetWriteLog(char *buff, int size, int tag)
{
    HARCH_INFO_PRINT("begin");
    if (tag) {
        struct timeval time;
        gettimeofday(&time, NULL);

        char str[1024] = {0};
        snprintf_s(str, sizeof(str), sizeof(str) - 1, "/data/log/%d%06d_%04d.txt",
            time.tv_sec, time.tv_usec, size);

        FILE *fp = fopen(str, "a+");
        if (!fp) {
            HDF_LOGE("%{public}s: fopen failed", __func__);
            return;
        }
        (void)fwrite(buff, size, 1, fp);
        (void)fclose(fp);
    }
    HARCH_INFO_PRINT("end");
}

// net process
static int32_t UsbnetHostSendBufToNet(struct HdfIoService *serv,  uint32_t id,
    const void *buf,  uint32_t length,  int32_t *replyData)
{
    HARCH_INFO_PRINT("begin");
    int32_t ret = 0;
    struct HdfSBuf *data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("fail to obtain sbuf data");
        return HDF_FAILURE;
    }

    struct HdfSBuf *reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        HDF_LOGE("fail to obtain sbuf reply");
        ret = HDF_DEV_ERR_NO_MEMORY;
        goto out;
    }

    if (!HdfSbufWriteBuffer(data, buf, length)) {
        HDF_LOGE("fail to write sbuf");
        ret = HDF_FAILURE;
        goto out;
    }

    ret = serv->dispatcher->Dispatch(&serv->object, id,  data,  reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("fail to send service call");
        goto out;
    }

    if (!HdfSbufReadInt32(reply, replyData)) {
        HDF_LOGE("fail to get service call reply");
        ret = HDF_ERR_INVALID_OBJECT;
        goto out;
    }

    HARCH_INFO_PRINT("Get reply is: %{public}d", *replyData);
out:
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

static void  UsbnetHostTXComplete(const void *requestArg)
{
    g_sendToUrbSuccessTimes++;
    HARCH_INFO_PRINT("begin success times = %{public}d", g_sendToUrbSuccessTimes);
    struct UsbRawRequest *req = (struct UsbRawRequest *)requestArg;
    if (req == NULL) {
        HDF_LOGE("%{public}s:%{public}d req is null!", __func__, __LINE__);
        return;
    }

    struct UsbHostWb *wb = (struct UsbHostWb *)req->userData;
    if (wb == NULL) {
        HDF_LOGE("%{public}s:%{public}d userData(wb) is null!", __func__, __LINE__);
        return;
    }

    if (req->status != USB_REQUEST_COMPLETED) {
        HDF_LOGE("%{public}s: write req failed, status = %{public}d", __func__, req->status);
    }

    wb->use = 0;
    HARCH_INFO_PRINT("%{public}s:%{public}d", __func__, __LINE__);
    return;
}


static int32_t UsbnetHostStartWb(struct UsbnetHost *usbNet,  struct UsbHostWb *wb)
{
    HARCH_INFO_PRINT("begin");
    struct UsbRawFillRequestData reqData;
    int32_t ret;

    if ((usbNet == NULL)     ||
        (wb == NULL)         ||
        (usbNet->dataOutEp == NULL) ||
        (usbNet->devHandle == NULL) ||
        (wb->request == NULL)) {
        HDF_LOGE("%{public}s:%{public}d", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    HARCH_INFO_PRINT();
    usbNet->transmitting++;

    reqData.endPoint = usbNet->dataOutEp->addr;
    reqData.numIsoPackets = 0;
    reqData.callback = UsbnetHostTXComplete;
    reqData.userData = (void *)wb;
    reqData.timeout = USB_CTRL_SET_TIMEOUT;
    reqData.buffer = wb->buf;
    reqData.length = wb->len;

    HARCH_INFO_PRINT();
    ret = UsbRawFillBulkRequest(wb->request, usbNet->devHandle, &reqData);
    if (ret) {
        HDF_LOGE("%{public}s: FillInterruptRequest failed, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    HARCH_INFO_PRINT();
    ret = UsbRawSubmitRequest(wb->request);
    if (ret) {
        HDF_LOGE("UsbRawSubmitRequest failed, ret = %{public}d", ret);
        wb->use = 0;
        usbNet->transmitting--;
        return HDF_FAILURE;
    }
    HARCH_INFO_PRINT();
    return HDF_SUCCESS;
}

static int32_t UsbHostWbIsAvail(const struct UsbnetHost *usbNet)
{
    int32_t i;
    int32_t n = USBNET_NW;

    OsalMutexLock((struct OsalMutex *)&usbNet->writeLock);
    for (i = 0; i < USBNET_NW; i++) {
        n -= usbNet->wb[i].use;
    }
    OsalMutexUnlock((struct OsalMutex *)&usbNet->writeLock);
    HARCH_INFO_PRINT("g_sendToUrbTimes = %{public}d, curWbUse = %{public}d", g_sendToUrbTimes, n);
    return n;
}

static int32_t UsbHostWbAlloc(const struct UsbnetHost *usbNet)
{
    struct UsbHostWb *wb = NULL;
    int32_t i;

    for (i = 0; i < USBNET_NW; i++) {
        wb = (struct UsbHostWb *)&usbNet->wb[i];
        if (!wb->use) {
            wb->use = 1;
            wb->len = 0;
            return i;
        }
    }
    return -1;
}

static int32_t UsbnetHostSnedbufToUrb(struct UsbnetHost *usbNet,  struct HdfSBuf *data)
{
    int32_t wbn;
    int32_t size;
    unsigned char *buf = NULL;
    uint32_t bufSize   = 0;

    g_sendToUrbTimes++;
    if (usbNet == NULL) {
        HDF_LOGE("%{public}s: usbNet is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (UsbHostWbIsAvail(usbNet)) {
        wbn = UsbHostWbAlloc(usbNet);
        if (wbn < 0 || wbn >= USBNET_NW) {
            HDF_LOGE("%{public}s: UsbHostWbAlloc failed", __func__);
            return HDF_FAILURE;
        }
    } else {
        HDF_LOGE("%{public}s: no write buf", __func__);
        return HDF_SUCCESS;
    }

    struct UsbHostWb *wb = &usbNet->wb[wbn];
    if (wb == NULL) {
        return HDF_FAILURE;
    }

    int flag = HdfSbufReadBuffer(data, (const void **)(&(buf)), &bufSize);
    if ((!flag) || buf == NULL) {
        HDF_LOGE("%{public}s: fail to read infoTable in event data, flag = %{public}d", __func__, flag);
        return HDF_ERR_INVALID_PARAM;
    }
    size = bufSize;
    HARCH_INFO_PRINT("buf size = %{public}d, usbNet->dataOutEp->maxPacketSize = %{public}d",
        bufSize, usbNet->dataOutEp->maxPacketSize);

    printf_char_buffer((char *)buf, CPU_TO_LE32(bufSize), false);
    UsbnetWriteLog((char *)buf, CPU_TO_LE32(bufSize), false);
    if (usbNet->dataOutEp != NULL) {
        size = (size > usbNet->dataOutEp->maxPacketSize) ? usbNet->dataOutEp->maxPacketSize : size;
        if (memcpy_s(wb->buf, usbNet->dataOutEp->maxPacketSize, buf, size) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s fail", __func__);
            return HDF_FAILURE;
        }
    }

    wb->len = (uint32_t)size;
    if (UsbnetHostStartWb(usbNet, wb) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbnetHostStartWb failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t UsbnetHostWriteBufAlloc(struct UsbnetHost *usbNet)
{
    struct UsbHostWb *wb = (struct UsbHostWb *)&usbNet->wb[0];
    int32_t i;

    for (i = 0; i < USBNET_NW; i++, wb++) {
        wb->buf = OsalMemCalloc(usbNet->dataOutEp->maxPacketSize);
        if (!wb->buf) {
            while (i > 0) {
                --i;
                --wb;
                OsalMemFree(wb->buf);
                wb->buf = NULL;
            }
            return -HDF_ERR_MALLOC_FAIL;
        }
    }
    return HDF_SUCCESS;
}

static int32_t UsbnetHostAllocWriteRequests(struct UsbnetHost *usbNet)
{
    int32_t i;
    for (i = 0; i < USBNET_NW; i++) {
        struct UsbHostWb *snd = &usbNet->wb[i];
        snd->request = UsbRawAllocRequest(usbNet->devHandle, 0, usbNet->dataOutEp->maxPacketSize);
        snd->nNet = usbNet;
        if (snd->request == NULL) {
            HDF_LOGE("%{public}s: UsbRawAllocRequest failed", __func__);
            return HDF_ERR_MALLOC_FAIL;
        }
    }
    return HDF_SUCCESS;
}

static void UsbnetHostFreeWriteRequests(struct UsbnetHost *usbNet)
{
    int32_t i;
    struct UsbHostWb *snd = NULL;
    for (i = 0; i < USBNET_NW; i++) {
        snd = &usbNet->wb[i];
        if (snd->request != NULL) {
            UsbRawFreeRequest(snd->request);
            snd->request = NULL;
        }
    }
    return;
}

static void UsbnetHostWriteBufFree(struct UsbnetHost *usbNet)
{
    struct UsbHostWb *wb = &usbNet->wb[0];
    int32_t i;

    for (i = 0; i < USBNET_NW; i++, wb++) {
        if (wb->buf) {
            OsalMemFree(wb->buf);
            wb->buf = NULL;
        }
    }
    return;
}

static int32_t UsbnetHostNotificationBufferProcess(const struct UsbRawRequest *req,
    struct UsbnetHost *usbNet, unsigned int currentSize, unsigned int expectedSize)
{
    if (usbNet->nbSize < expectedSize) {
        if (usbNet->nbSize) {
            OsalMemFree(usbNet->notificationBuffer);
            usbNet->nbSize = 0;
        }
        unsigned int allocSize = expectedSize;
        usbNet->notificationBuffer = (uint8_t *)OsalMemCalloc(allocSize);
        if (!usbNet->notificationBuffer) {
            return HDF_FAILURE;
        }
        usbNet->nbSize = allocSize;
    }
    unsigned int copySize = MIN(currentSize, expectedSize - usbNet->nbIndex);
    int32_t ret = memcpy_s(&usbNet->notificationBuffer[usbNet->nbIndex],
        usbNet->nbSize - usbNet->nbIndex, req->buffer, copySize);
    if (ret != EOK) {
        HDF_LOGE("memcpy_s fail ret=%{public}d", ret);
    }
    usbNet->nbIndex += copySize;

    return HDF_SUCCESS;
}

static void UsbnetHostProcessNotification(const struct UsbnetHost *usbNet, const unsigned char *buf)
{
    (void)usbNet;
    struct UsbCdcNotification *dr = (struct UsbCdcNotification *)buf;

    switch (dr->bNotificationType) {
        case USB_DDK_CDC_NOTIFY_NETWORK_CONNECTION:
            HARCH_INFO_PRINT("%{public}s - network connection: %{public}d\n", __func__, dr->wValue);
            break;
        case USB_DDK_CDC_NOTIFY_SERIAL_STATE:
            HARCH_INFO_PRINT("the serial State change\n");
            break;
        default:
            HARCH_INFO_PRINT("%{public}s-%{public}d received: index %{public}d len %{public}d\n",
                __func__, dr->bNotificationType, dr->wIndex, dr->wLength);
            /* fall-through */
    }
}

static void UsbnetHostReqCallback(const void *requestArg)
{
    struct UsbRawRequest *req = (struct UsbRawRequest *)requestArg;
    if (req == NULL) {
        HDF_LOGE("%{public}s:%{public}d req is NULL!", __func__, __LINE__);
        return;
    }
    struct UsbnetHost *usbNet = (struct UsbnetHost *)req->userData;
    if (usbNet == NULL) {
        HDF_LOGE("%{public}s:%{public}d userData(usbNet) is NULL!", __func__, __LINE__);
        return;
    }
    struct UsbCdcNotification *dr = (struct UsbCdcNotification *)req->buffer;
    if (dr == NULL) {
        HDF_LOGE("%{public}s:%{public}d req->buffer(dr) is NULL!", __func__, __LINE__);
        return;
    }
    unsigned int currentSize = (unsigned int)req->actualLength;
    unsigned int expectedSize = 0;
    HARCH_INFO_PRINT("Irqstatus:%{public}d,actualLength:%{public}u\n", req->status, currentSize);
    if (req->status != USB_REQUEST_COMPLETED) {
        goto EXIT;
    }

    if (usbNet->nbIndex) {
        dr = (struct UsbCdcNotification *)usbNet->notificationBuffer;
    }

    if (dr != NULL) {
        expectedSize = sizeof(struct UsbCdcNotification) + LE16_TO_CPU(dr->wLength);
    } else {
        HDF_LOGE("%{public}s:%{public}d dr is NULL!", __func__, __LINE__);
        return;
    }

    if (currentSize < expectedSize) {
        if (UsbnetHostNotificationBufferProcess(req, usbNet, currentSize, expectedSize) != HDF_SUCCESS) {
            goto EXIT;
        }
        currentSize = usbNet->nbIndex;
    }

    if (currentSize >= expectedSize) {
        UsbnetHostProcessNotification(usbNet, (unsigned char *)dr);
        usbNet->nbIndex = 0;
    }

    if (UsbRawSubmitRequest(req) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s - UsbRawSubmitRequest failed", __func__);
    }
EXIT:
    HARCH_INFO_PRINT("%{public}s:%{public}d exit", __func__, __LINE__);
}

static int32_t UsbnetHostAllocStatusRequests(struct UsbnetHost *usbNet)
{
    struct UsbRawFillRequestData fillRequestData;
    uint32_t size = usbNet->statusEp->maxPacketSize;
    int32_t ret;

    usbNet->statusReq = UsbRawAllocRequest(usbNet->devHandle, 0, size);
    if (!usbNet->statusReq) {
        HDF_LOGE("statusReq request fail\n");
        return HDF_ERR_MALLOC_FAIL;
    }

    fillRequestData.endPoint = usbNet->statusEp->addr;
    fillRequestData.length = size;
    fillRequestData.numIsoPackets = 0;
    fillRequestData.callback = UsbnetHostReqCallback;
    fillRequestData.userData = (void *)usbNet;
    fillRequestData.timeout = USB_CTRL_SET_TIMEOUT;

    ret = UsbRawFillInterruptRequest(usbNet->statusReq, usbNet->devHandle, &fillRequestData);
    if (ret) {
        HDF_LOGE("%{public}s: FillInterruptRequest failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static void UsbnetHostFreesSatusReqeust(struct UsbnetHost *usbNet)
{
    int32_t ret;
    if ((usbNet == NULL) || (usbNet->statusReq == NULL)) {
        HDF_LOGE("%{public}s: usbNet or statusReq is NULL", __func__);
        return;
    }

    ret = UsbRawFreeRequest(usbNet->statusReq);
    if (ret == HDF_SUCCESS) {
        usbNet->statusReq = NULL;
    } else {
        HDF_LOGE("%{public}s: UsbFreestatusReqeust failed, ret=%{public}d", __func__, ret);
    }
}

static void UsbnetHostReadBulkCallback(const void *requestArg)
{
    g_sendToUrbReadTimes++;
    HARCH_INFO_PRINT("begin g_sendToUrbReadTimes  = %{public}d", g_sendToUrbReadTimes);

    struct UsbRawRequest *req = (struct UsbRawRequest *)requestArg;
    if (req == NULL) {
        HARCH_INFO_PRINT("%{public}s:%{public}d req is NULL!", __func__, __LINE__);
        HDF_LOGE("%{public}s:%{public}d req is NULL!", __func__, __LINE__);
        return;
    }

    struct UsbnetHost *usbNet = (struct UsbnetHost *)req->userData;
    if (usbNet == NULL) {
        HARCH_INFO_PRINT("%{public}s:%{public}d request userData is NULL!", __func__, __LINE__);
        HDF_LOGE("%{public}s:%{public}d request userData is NULL!", __func__, __LINE__);
        return;
    }
    size_t size = (size_t)req->actualLength;

    if (req->status != USB_REQUEST_COMPLETED) {
        HARCH_INFO_PRINT("%{public}s: the request is failed, status=%{public}d", __func__, req->status);
        HDF_LOGE("%{public}s: the request is failed, status=%{public}d", __func__, req->status);
        return;
    }

    HARCH_INFO_PRINT("Bulk status: %{public}d+size:%{public}zu", req->status, size);
    printf_char_buffer((char *)req->buffer, CPU_TO_LE32(size), true);
    HARCH_INFO_PRINT("Bulk status: %{public}d+size:%{public}zu", req->status, size);

    // send readBuf to net begin
    int32_t reply = 0;
    OsalMutexLock(&usbNet->sendNetLock);
    int32_t ret = UsbnetHostSendBufToNet(usbNet->hdfNetIoServ, USB_NET_RECIVE_DATA_FROM_USB,
        (unsigned char *)req->buffer, CPU_TO_LE32(size), &reply);
    if (ret != HDF_SUCCESS || reply != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d fail to UsbnetHostSendBufToNet ret = %{public}d, reply = %{public}d!",
            __func__, __LINE__, ret, reply);
    }
    OsalMutexUnlock(&usbNet->sendNetLock);

    // send readBuf to net end
    if (size == 0) {
        HARCH_INFO_PRINT("DataFifoWrite");
        uint8_t *data = req->buffer;
        OsalMutexLock(&usbNet->readLock);
        if (DataFifoIsFull(&usbNet->readFifo)) {
            DataFifoSkip(&usbNet->readFifo, size);
        }
        uint32_t count = DataFifoWrite(&usbNet->readFifo, data, size);
        if (count != size) {
            HDF_LOGE("%{public}s: write %{public}u less than expected %{public}zu", __func__, count, size);
        }
        OsalMutexUnlock(&usbNet->readLock);
    }

    if (UsbRawSubmitRequest(req) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s UsbRawSubmitRequest failed", __func__);
    }
}

static int32_t UsbnetHostAllocReadRequests(struct UsbnetHost *usbNet)
{
    struct UsbRawFillRequestData reqData = {};
    uint32_t size = usbNet->dataInEp->maxPacketSize;
    HARCH_INFO_PRINT("read maxPacketSize read num = %{public}d", size);

    for (int32_t i = 0; i < usbNet->readReqNum; i++) {
        HARCH_INFO_PRINT("UsbRawAllocRequest read num = %{public}d", i);
        usbNet->readReq[i] = UsbRawAllocRequest(usbNet->devHandle, 0, size);
        if (!usbNet->readReq[i]) {
            HDF_LOGE("readReq request failed\n");
            return HDF_ERR_MALLOC_FAIL;
        }

        reqData.endPoint = usbNet->dataInEp->addr;
        reqData.numIsoPackets = 0;
        reqData.callback = UsbnetHostReadBulkCallback;
        reqData.userData = (void *)usbNet;
        reqData.timeout = USB_CTRL_SET_TIMEOUT;
        reqData.length = size;

        HARCH_INFO_PRINT("UsbRawFillBulkRequest read num = %{public}d", i);
        int32_t ret = UsbRawFillBulkRequest(usbNet->readReq[i], usbNet->devHandle, &reqData);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: FillBulkRequest failed, ret=%{public}d\n", __func__, ret);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

static void UsbnetHostFreeReadRequests(struct UsbnetHost *usbNet)
{
    if (usbNet == NULL) {
        HDF_LOGE("%{public}s: usbNet is NULL", __func__);
        return;
    }

    int32_t i;
    for (i = 0; i < usbNet->readReqNum; i++) {
        if (usbNet->readReq[i]) {
            UsbRawFreeRequest(usbNet->readReq[i]);
            usbNet->readReq[i] = NULL;
        }
    }
}

static int32_t UsbnetHostAllocFifo(struct DataFifo *fifo, uint32_t size)
{
    if (!DataFifoIsInitialized(fifo)) {
        void *data = OsalMemAlloc(size);
        if (data == NULL) {
            HDF_LOGE("%{public}s:allocate failed", __func__);
            return HDF_ERR_MALLOC_FAIL;
        }
        DataFifoInit(fifo, size, data);
    }
    return HDF_SUCCESS;
}

static void  UsbnetHostFreeFifo(const struct DataFifo *fifo)
{
    if (fifo == NULL) {
        HDF_LOGE("%{public}s:%{public}d fifo is null", __func__, __LINE__);
        return;
    }

    if (fifo->data != NULL) {
        OsalMemFree((void *)fifo->data);
    }

    DataFifoInit((struct DataFifo *)fifo, 0, NULL);
}

static int32_t UsbIoThread(void *data)
{
    int32_t ret;
    struct UsbnetHost *usbNet = (struct UsbnetHost *)data;
    HARCH_INFO_PRINT("begin");
    while (true) {
        if (usbNet == NULL) {
            HDF_LOGE("%{public}s:%{public}d usbNet is null", __func__, __LINE__);
            OsalMSleep(USB_RAW_IO_SLEEP_MS_TIME);
            continue;
        }

        if (usbNet->devHandle == NULL) {
            HDF_LOGE("%{public}s:%{public}d usbNet->devHandle is null", __func__, __LINE__);
            OsalMSleep(USB_RAW_IO_SLEEP_MS_TIME);
            continue;
        }

        ret = UsbRawHandleRequests(usbNet->devHandle);
        if ((ret < 0) || (usbNet->usbIoStatus != USB_RAW_IO_PROCESS_RUNNING)) {
            HDF_LOGE("%{public}s:%{public}d UsbIoThread failed, usbNet->usbIoStatus =%{public}d ret=%{public}d ",
                __func__, __LINE__, usbNet->usbIoStatus, ret);
            break;
        }
    }

    OsalMutexLock(&usbNet->usbIoLock);
    usbNet->usbIoStatus = USB_RAW_IO_PROCESS_STOPED;
    OsalMutexUnlock(&usbNet->usbIoLock);

    HARCH_INFO_PRINT("end");
    return HDF_SUCCESS;
}

static int32_t UsbStartIo(struct UsbnetHost *usbNet)
{
    struct OsalThreadParam threadCfg = {};
    int32_t ret = HDF_SUCCESS;

    HARCH_INFO_PRINT("");
    OsalMutexInit(&usbNet->usbIoLock);

    OsalMutexLock(&usbNet->usbIoLock);
    usbNet->usbIoStatus = USB_RAW_IO_PROCESS_RUNNING;
    OsalMutexUnlock(&usbNet->usbIoLock);

    /* create Io thread */
    (void)memset_s(&threadCfg, sizeof(threadCfg), 0, sizeof(threadCfg));
    threadCfg.name = "usb io thread";
    threadCfg.priority = OSAL_THREAD_PRI_LOW;
    threadCfg.stackSize = USB_IO_THREAD_STACK_SIZE;

    ret = OsalThreadCreate(&usbNet->ioThread, (OsalThreadEntry)UsbIoThread, (void *)usbNet);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadCreate failed, ret = %{public}d", __func__, __LINE__, ret);
        return ret;
    }

    ret = OsalThreadStart(&usbNet->ioThread, &threadCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadStart failed, ret = %{public}d", __func__, __LINE__, ret);
        return ret;
    }
    return HDF_SUCCESS;
}

static void UsbStopIo(struct UsbnetHost *usbNet)
{
    int32_t ret;
    int32_t i = 0;

    if (usbNet->usbIoStatus != USB_RAW_IO_PROCESS_STOPED) {
        HARCH_INFO_PRINT("not stopped");
        OsalMutexLock(&usbNet->usbIoLock);
        usbNet->usbIoStatus = USB_RAW_IO_PROCESS_STOP;
        OsalMutexUnlock(&usbNet->usbIoLock);
    } else {
        HARCH_INFO_PRINT("stopped");
    }

    while (usbNet->usbIoStatus != USB_RAW_IO_PROCESS_STOPED) {
        i++;
        OsalMSleep(USB_RAW_IO_SLEEP_MS_TIME);
        if (i > USB_RAW_IO_STOP_WAIT_MAX_TIME) {
            HDF_LOGD("%{public}s:%{public}d", __func__, __LINE__);
            break;
        }
    }

    ret = OsalThreadDestroy(&usbNet->ioThread);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalThreadDestroy failed, ret = %{public}d", __func__, __LINE__, ret);
    }

    OsalMutexDestroy(&usbNet->usbIoLock);
    return;
}

static int32_t UsbnetHostAlloc(struct UsbnetHost *usbNet)
{
    // 1.write request
    int ret = UsbnetHostWriteBufAlloc(usbNet);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d usbNetWriteBufAlloc failed", __func__, __LINE__);
        return ret;
    }

    ret = UsbnetHostAllocWriteRequests(usbNet);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbRawAllocRequest failed", __func__);
        UsbnetHostWriteBufFree(usbNet);
        return ret;
    }

    // 2.status request
    ret = UsbnetHostAllocStatusRequests(usbNet);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbRawAllocRequest failed", __func__);
        UsbnetHostFreeWriteRequests(usbNet);
        return ret;
    }

    // 3.read request
    ret = UsbnetHostAllocReadRequests(usbNet);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbRawAllocRequest failed", __func__);
        UsbnetHostFreesSatusReqeust(usbNet);
        return ret;
    }
    return ret;
}

static int32_t UsbnetHostAllocRequests(struct UsbnetHost *usbNet)
{
    if (usbNet == NULL) {
        HDF_LOGI("UsbnetHostAllocRequests usbNet is null");
        return HDF_FAILURE;
    }

    if (usbNet->allocFlag == true) {
        HDF_LOGI("UsbnetHostAllocRequests has been alloced");
        return HDF_SUCCESS;
    }

    int ret = UsbnetHostAlloc(usbNet);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d UsbnetHostAlloc failed", __func__, __LINE__);
        return ret;
    }

    ret = UsbStartIo(usbNet);
    if (ret) {
        HDF_LOGE("%{public}s:%{public}d UsbAllocReadRequests failed", __func__, __LINE__);
        goto ERR_ALLOC_READ_REQS;
    }

    // status begin
    ret = UsbRawSubmitRequest(usbNet->statusReq);
    if (ret) {
        HDF_LOGE("%{public}s:%{public}d UsbRawSubmitRequest failed", __func__, __LINE__);
        goto ERR_SUBMIT_REQ;
    }

    // read begin
    ret = UsbnetHostAllocFifo(&usbNet->readFifo, READ_BUF_SIZE);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbnetHostAllocFifo failed", __func__);
        goto ERR_SUBMIT_STATUS_REQ;
    }

    for (int32_t i = 0; i < usbNet->readReqNum; i++) {
        HARCH_INFO_PRINT("UsbRawSubmitRequest read num = %{public}d", i);
        ret = UsbRawSubmitRequest(usbNet->readReq[i]);
        if (ret) {
            HDF_LOGE("%{public}s: UsbRawSubmitRequest failed, ret=%{public}d ", __func__, ret);
            goto ERR_SUBMIT_READ_REQ;
        }
    }

    usbNet->allocFlag = true;
    return HDF_SUCCESS;

ERR_SUBMIT_READ_REQ:
    UsbnetHostFreeFifo(&usbNet->readFifo);
ERR_SUBMIT_STATUS_REQ:
    UsbnetHostFreeReadRequests(usbNet);
ERR_SUBMIT_REQ:
    UsbStopIo(usbNet);
ERR_ALLOC_READ_REQS:
    UsbnetHostFreesSatusReqeust(usbNet);

    return ret;
}

static void UsbnetHostFreeRequests(struct UsbnetHost *usbNet)
{
    if (usbNet == NULL) {
        HDF_LOGI("UsbnetHostFreeRequests usbNet is null");
        return;
    }
    // FIFO
    OsalMutexLock(&usbNet->readLock);
    UsbnetHostFreeFifo(&usbNet->readFifo);
    OsalMutexUnlock(&usbNet->readLock);
    // read
    UsbnetHostFreeReadRequests(usbNet);
    // status
    UsbnetHostFreesSatusReqeust(usbNet);
    // write
    UsbnetHostFreeWriteRequests(usbNet);
    UsbnetHostWriteBufFree(usbNet);

    return ;
}

// --------------------------usb get config--------------
static void UsbnetHostPrintConfigDescriptor(struct UsbRawConfigDescriptor *tmpConfig)
{
    HARCH_INFO_PRINT("bLength = %{public}d", tmpConfig->configDescriptor.bLength);
    HARCH_INFO_PRINT("bDescriptorType = %{public}d", tmpConfig->configDescriptor.bDescriptorType);
    HARCH_INFO_PRINT("wTotalLength = %{public}d", tmpConfig->configDescriptor.wTotalLength);
    HARCH_INFO_PRINT("bNumInterfaces = %{public}d", tmpConfig->configDescriptor.bNumInterfaces);
    HARCH_INFO_PRINT("bConfigurationValue = %{public}d", tmpConfig->configDescriptor.bConfigurationValue);
    HARCH_INFO_PRINT("iConfiguration = %{public}d", tmpConfig->configDescriptor.iConfiguration);
    HARCH_INFO_PRINT("bMaxPower = %{public}d", tmpConfig->configDescriptor.bMaxPower);

    for (int i = 0; i < tmpConfig->configDescriptor.bNumInterfaces; i++) {
        HARCH_INFO_PRINT("interface number = %{public}d", i);
        for (int j = 0; j < tmpConfig->interface[i]->numAltsetting; j++) {
            HARCH_INFO_PRINT("altsetting number = %{public}d", j);
            for (int k = 0; k < tmpConfig->interface[i]->altsetting->interfaceDescriptor.bNumEndpoints; k++) {
                HARCH_INFO_PRINT("bLength = %{public}d",
                    tmpConfig->interface[i]->altsetting[j].endPoint[k].endpointDescriptor.bLength);
                HARCH_INFO_PRINT("bDescriptorType = %{public}d",
                    tmpConfig->interface[i]->altsetting[j].endPoint[k].endpointDescriptor.bDescriptorType);
                HARCH_INFO_PRINT("bEndpointAddress = %{public}d",
                    tmpConfig->interface[i]->altsetting[j].endPoint[k].endpointDescriptor.bEndpointAddress);
                HARCH_INFO_PRINT("bmAttributes = %{public}d",
                    tmpConfig->interface[i]->altsetting[j].endPoint[k].endpointDescriptor.bmAttributes);
                HARCH_INFO_PRINT("wMaxPacketSize = %{public}d",
                    tmpConfig->interface[i]->altsetting[j].endPoint[k].endpointDescriptor.wMaxPacketSize);
                HARCH_INFO_PRINT("bInterval = %{public}d",
                    tmpConfig->interface[i]->altsetting[j].endPoint[k].endpointDescriptor.bInterval);
                HARCH_INFO_PRINT("bRefresh = %{public}d",
                    tmpConfig->interface[i]->altsetting[j].endPoint[k].endpointDescriptor.bRefresh);
                HARCH_INFO_PRINT("bSynchAddress = %{public}d",
                    tmpConfig->interface[i]->altsetting[j].endPoint[k].endpointDescriptor.bSynchAddress);
            }
        }
    }
}

static int32_t UsbnetHostGetConfigDescriptor(UsbRawHandle *devHandle, struct UsbRawConfigDescriptor **config)
{
    UsbRawDevice *dev    = NULL;
    int32_t activeConfig = -1;
    int32_t ret = HDF_SUCCESS;
    if (devHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d devHandle is null", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = UsbRawGetConfiguration(devHandle, &activeConfig);
    if (ret) {
        HDF_LOGE("%{public}s:%{public}d UsbRawGetConfiguration failed, ret = %{public}d", __func__, __LINE__, ret);
        return HDF_FAILURE;
    }
    HARCH_INFO_PRINT("activeConfig = %{public}d", activeConfig);
    dev = UsbRawGetDevice(devHandle);
    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d UsbRawGetDevice failed", __func__, __LINE__);
        return HDF_FAILURE;
    }

    ret = UsbRawGetConfigDescriptor(dev, activeConfig, config);
    if (ret) {
        HDF_LOGE("UsbRawGetConfigDescriptor failed, ret = %{public}d\n", ret);
        return HDF_FAILURE;
    }

    struct UsbRawConfigDescriptor *tmpConfig = (struct UsbRawConfigDescriptor *)*config;
    UsbnetHostPrintConfigDescriptor(tmpConfig);
    return HDF_SUCCESS;
}

/* must be called if hard_mtu or rx_urb_size changed */
static void UsbnetHostUpdateMaxQlen(struct UsbnetHost *usbNet)
{
    int32_t ret = UsbRawGetUsbSpeed(usbNet->devHandle);
    HARCH_INFO_PRINT("speed = %{public}d", ret);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d UsbGetUsbSpeed failed", __func__, __LINE__);
        ret = HDF_FAILURE;
    }
    enum UsbnetHostDeviceSpeed speed = ret;
    switch (speed) {
        case USB_SPEED_HIGH:
            usbNet->rxQlen = MAX_QUEUE_MEMORY / usbNet->net.rxUrbSize;
            usbNet->txQlen = MAX_QUEUE_MEMORY / usbNet->net.hardMtu;
            break;
        case USB_SPEED_SUPER:
        case USB_SPEED_SUPER_PLUS:
            /*
            * Not take default 5ms qlen for super speed HC to
            * save memory, and iperf tests show 2.5ms qlen can
            * work well
            */
            usbNet->rxQlen = USBNET_QLEN_TIME * MAX_QUEUE_MEMORY / usbNet->net.rxUrbSize;
            usbNet->txQlen = USBNET_QLEN_TIME * MAX_QUEUE_MEMORY / usbNet->net.hardMtu;
            break;
        default:
            usbNet->rxQlen = usbNet->txQlen = USBNET_QLEN_DEFAULT;
            /* fall-through */
    }
    HARCH_INFO_PRINT("usbNet->rxQlen = %{public}d, usbNet->txQlen = %{public}d,"
        "usbNet->rxUrbSize = %{public}d, usbNet->hardMtu = %{public}d",
        usbNet->rxQlen, usbNet->txQlen, usbNet->net.rxUrbSize, usbNet->net.hardMtu);
}

static int32_t UsbnetHostInitObject(struct UsbnetHost *usbNet)
{
    int ret = HDF_SUCCESS;
     // net init
    usbNet->net.mtu = DEFAULT_MTU;
    usbNet->net.hardHeaderLen = DEFAULT_NET_HEAD_LEN;
    usbNet->net.hardMtu = usbNet->net.mtu + usbNet->net.hardHeaderLen;
    // falgs of usb device
    if (usbNet->driverInfo->flags) {
        usbNet->net.usbFlags = usbNet->driverInfo->flags;
    }

    usbNet->net.isBindDevice = 0;
    if (usbNet->driverInfo->bind) {
        usbNet->net.isBindDevice = 1;
        ret = usbNet->driverInfo->bind(usbNet);
        if (ret) {
            HDF_LOGE("%{public}s:%{public}d bind failed", __func__, __LINE__);
            ret = HDF_FAILURE;
            return ret;
        }

        HARCH_INFO_PRINT("net->mtu = %{public}d, dev->hardMtu= %{public}d ,net->hardHeaderLen = %{public}d",
            usbNet->net.mtu, usbNet->net.hardMtu, usbNet->net.hardHeaderLen);
        /* maybe the remote can't receive an Ethernet MTU */
        if (usbNet->net.mtu > (usbNet->net.hardMtu - usbNet->net.hardHeaderLen)) {
            usbNet->net.mtu = usbNet->net.hardMtu - usbNet->net.hardHeaderLen;
        }
    }

    if (!usbNet->net.rxUrbSize) {
        usbNet->net.rxUrbSize = usbNet->net.hardMtu;
    }

    HARCH_INFO_PRINT("rxUrbSize = %{public}d\n", usbNet->net.rxUrbSize);
    HARCH_INFO_PRINT("net->mtu = %{public}d,dev->hardMtu= %{public}d ,net->hardHeaderLen = %{public}d",
        usbNet->net.mtu, usbNet->net.hardMtu, usbNet->net.hardHeaderLen);
    UsbnetHostUpdateMaxQlen(usbNet);
    usbNet->net.txQlen = usbNet->txQlen;
    if (usbNet->canDmaSg &&
        !(usbNet->driverInfo->flags & FLAG_SEND_ZLP) &&
        !(usbNet->driverInfo->flags & FLAG_MULTI_PACKET)) {
        HARCH_INFO_PRINT();
        usbNet->paddingPkt = (uint8_t *)OsalMemAlloc(1);
        if (!usbNet->paddingPkt) {
            HDF_LOGE("%{public}s:%{public}d OsalMemAlloc failed", __func__, __LINE__);
            ret = HDF_ERR_MALLOC_FAIL;
            return ret;
        }
    }
    usbNet->initFlag = true;
    return ret;
}

static int32_t UsbnetHostUsbRawInit(struct UsbnetHost *usbNet)
{
    int32_t ret = HDF_SUCCESS;
    struct UsbSession *session = NULL;
    HARCH_INFO_PRINT("initFlag:%{public}d", usbNet->initFlag);
    if (usbNet->initFlag) {
        HDF_LOGE("%{public}s:%{public}d: initFlag is true", __func__, __LINE__);
        return HDF_SUCCESS;
    }

    HARCH_INFO_PRINT("busNum:%{public}d, devAddr:%{public}#x", usbNet->busNum, usbNet->devAddr);
    // 1.session
    ret = UsbRawInit(&session);
    if (ret) {
        HDF_LOGE("%{public}s:%{public}d UsbRawInit failed", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    usbNet->session = session;
    // 2.handle
    UsbRawHandle *devHandle = UsbRawOpenDevice(session, usbNet->busNum, usbNet->devAddr);
    if (devHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d UsbRawOpenDevice failed", __func__, __LINE__);
        ret = HDF_FAILURE;
        goto ERR_OPEN_DEVICE;
    }
    usbNet->devHandle = devHandle;
    // 3.get para
    HARCH_INFO_PRINT();
    ret = UsbnetHostGetConfigDescriptor(devHandle, &usbNet->config);
    if (ret) {
        HDF_LOGE("%{public}s:%{public}d UsbGetConfigDescriptor failed", __func__, __LINE__);
        ret = HDF_FAILURE;
        goto ERR_GET_DESC;
    }
    ret = UsbnetHostInitObject(usbNet);
    if (ret!= HDF_SUCCESS) {
        goto ERR_GET_DESC;
    }
    return ret;
ERR_GET_DESC:
    (void)UsbRawCloseDevice(devHandle);
ERR_OPEN_DEVICE:
    UsbRawExit(usbNet->session);
    return ret;
}

static int32_t UsbnetHostUpdateFlags(struct UsbnetHost *usbNet, struct HdfSBuf *data)
{
    int32_t* flags = NULL;
    uint32_t readSize = 0;
    HARCH_INFO_PRINT("begin");
    if (NULL == usbNet || NULL == data) {
        HDF_LOGE("param invalid!");
        return HDF_FAILURE;
    }
    HARCH_INFO_PRINT("before set flags usbNet->flags = %{public}d", usbNet->flags);
    if (!HdfSbufReadBuffer(data, (const void **)&flags, &readSize)) {
        HDF_LOGE("%{public}s:%{public}d fail to read usbnet flags from usb net adapter", __func__, __LINE__);
        return HDF_FAILURE;
    }
    usbNet->flags = *flags;
    HARCH_INFO_PRINT("after set flags usbNet->flags = %{public}d, readSize = %{public}d", usbNet->flags, readSize);
    return HDF_SUCCESS;
}

static void UsbnetHostUpdateHardMtu(struct UsbnetHost *usbNet, struct HdfSBuf *data)
{
    uint32_t readSize = 0;
    HARCH_INFO_PRINT("begin");
    if (NULL == usbNet || NULL == data) {
        HDF_LOGE("param invalid!");
        return;
    }

    HARCH_INFO_PRINT("before hardMtu = %{public}d, rxUrbSize = %{public}d", usbNet->net.hardMtu, usbNet->net.rxUrbSize);
    if (!HdfSbufReadBuffer(data, (const void **)&usbNet->net, &readSize)) {
        HDF_LOGE("%{public}s:%{public}d fail to read usbnet hardMtu from usb net adapter", __func__, __LINE__);
        return;
    }
    HARCH_INFO_PRINT("after hardMtu = %{public}d, rxUrbSize = %{public}d, readSize = %{public}d",
        usbNet->net.hardMtu, usbNet->net.rxUrbSize, readSize);
    return;
}

static int32_t UsbnetHostOpen(struct UsbnetHost *usbNet, struct HdfSBuf *data)
{
    HARCH_INFO_PRINT("begin");
    if (NULL == usbNet || NULL == data) {
        HDF_LOGE("param invalid!");
        return HDF_FAILURE;
    }

    int ret = UsbnetHostUpdateFlags(usbNet, data);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s: fail to Update Flags", __func__);
        return ret;
    }

    /* 3. update usbnet max qlen */
    UsbnetHostUpdateMaxQlen(usbNet);
    usbNet->dataOutEp->maxPacketSize = (usbNet->dataOutEp->maxPacketSize > usbNet->net.rxUrbSize ?
        usbNet->dataOutEp->maxPacketSize : usbNet->net.rxUrbSize);
    usbNet->dataInEp->maxPacketSize = (usbNet->dataInEp->maxPacketSize > usbNet->net.rxUrbSize ?
        usbNet->dataInEp->maxPacketSize : usbNet->net.rxUrbSize);

    HARCH_INFO_PRINT("dataOutEp-maxPacketSize = %{public}d", usbNet->dataOutEp->maxPacketSize);
    HARCH_INFO_PRINT("dataInEp-maxPacketSize = %{public}d", usbNet->dataInEp->maxPacketSize);
    HARCH_INFO_PRINT("read num = %{public}d", usbNet->rxQlen);
    HARCH_INFO_PRINT("write num = %{public}d", usbNet->txQlen);

    OsalMutexInit(&usbNet->readLock);
    OsalMutexInit(&usbNet->writeLock);
    OsalMutexInit(&usbNet->sendNetLock);

    usbNet->readReqNum = usbNet->rxQlen;
    ret = UsbnetHostAllocRequests(usbNet);
    if (ret) {
        HDF_LOGE("%{public}s:%{public}d UsbnetHostAllocRequests failed", __func__, __LINE__);
        return ret;
    }
    return ret;
}

static int32_t UsbnetHostClose(struct UsbnetHost *usbNet, struct HdfSBuf *data)
{
    HARCH_INFO_PRINT("begin");
    if (NULL == usbNet || NULL == data) {
        HDF_LOGE("param invalid!");
        return HDF_FAILURE;
    }

    int ret = UsbnetHostUpdateFlags(usbNet, data);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%{public}s: fail to Update Flags", __func__);
        return ret;
    }

    UsbnetHostFreeRequests(usbNet);
    OsalMutexDestroy(&usbNet->readLock);
    OsalMutexDestroy(&usbNet->writeLock);
    return HDF_SUCCESS;
}

static int32_t OnUsbnetHostEventReceived(void *priv,  uint32_t id, struct HdfSBuf *data)
{
    int32_t ret = HDF_SUCCESS;
    struct HdfDeviceObject *device = (struct HdfDeviceObject *)priv;
    struct UsbnetHost *usbNet = (struct UsbnetHost *)device->service;
    HARCH_INFO_PRINT("begin id = %{public}d", id);
    if (usbNet == NULL) {
        HDF_LOGE("%{public}s: invalid usbNet", __func__);
        return HDF_FAILURE;
    }
    switch (id) {
        case USB_NET_OPEN_USB:
            ret = UsbnetHostOpen(usbNet, data);
            break;
        case USB_NET_SEND_DATA_TO_USB:
            HARCH_INFO_PRINT("start send whole times = %{public}d, success Times = %{public}d",
                g_sendToUrbTimes, g_sendToUrbSuccessTimes);
            ret = UsbnetHostSnedbufToUrb(usbNet, data);
            break;
        case USB_NET_CLOSE_USB:
            ret = UsbnetHostClose(usbNet, data);
            break;
        case USB_NET_UPDATE_FLAGS:
            HARCH_INFO_PRINT();
            UsbnetHostUpdateFlags(usbNet, data);
            break;
        case USB_NET_UPDATE_MAXQLEN:
            HARCH_INFO_PRINT();
            UsbnetHostUpdateHardMtu(usbNet, data);
            UsbnetHostUpdateMaxQlen(usbNet);
            break;
        default:
            break;
    }
    return ret;
}

static int32_t UsbnetHostRegisterNet(struct UsbnetHost *usbNet)
{
    HARCH_INFO_PRINT("begin");
    struct HdfIoService *serv = HdfIoServiceBind(USB_NET_SERVICE_NAME);
    if (serv == NULL) {
        HDF_LOGE("fail to get service %{public}s", USB_NET_SERVICE_NAME);
        return HDF_FAILURE;
    }

    HARCH_INFO_PRINT("success to get service %{public}s", USB_NET_SERVICE_NAME);
    static struct HdfDevEventlistener listener = {
        .callBack = OnUsbnetHostEventReceived,
    };
    listener.priv = (void *)(usbNet->deviceObject);

    HARCH_INFO_PRINT("listener.priv addr = %{public}p", &(listener.priv));
    if (HdfDeviceRegisterEventListener(serv, &listener) != HDF_SUCCESS) {
        HDF_LOGE("fail to register event listener");
        return HDF_FAILURE;
    }

    // send msg to net register net
    int32_t reply = 0;
    int32_t ret = UsbnetHostSendBufToNet(serv, USB_NET_REGISTER_NET,
        (unsigned char *)&(usbNet->net), sizeof(struct UsbnetTransInfo), &reply);
    if (ret != HDF_SUCCESS || reply != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d fail to UsbnetHostSendBufToNet ret = %{public}d, reply = %{public}d!",
            __func__, __LINE__, ret, reply);
        return HDF_FAILURE;
    }
    usbNet->hdfNetIoServ = serv;
    usbNet->hdfNetListener = &listener;
    return HDF_SUCCESS;
}

int32_t UsbnetHostProbe(struct UsbnetHost *usbNet)
{
    int32_t status = HDF_ERR_INVALID_PARAM;
    HARCH_INFO_PRINT("begin");
    if (usbNet->deviceObject == NULL || usbNet->driverInfo == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    // usb init
    status = UsbnetHostUsbRawInit(usbNet);
    if (status != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbnetHostUsbRawInit failed", __func__);
        return HDF_FAILURE;
    }

    // register net
    status = UsbnetHostRegisterNet(usbNet);
    if (status != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbnetHostRegisterNet failed", __func__);
        return HDF_FAILURE;
    }

    HARCH_INFO_PRINT("end");
    return status;
}

// release buf
static void UsbReleaseInterfaces(struct UsbnetHost *usbNet)
{
    int ret = HDF_SUCCESS;
    if ((usbNet == NULL) || (usbNet->devHandle == NULL)) {
        HDF_LOGE("%{public}s:%{public}d usbNet is null", __func__, __LINE__);
        return;
    }

    HARCH_INFO_PRINT("usbNet->ctrlIface = %{public}d", usbNet->ctrlIface);
    HARCH_INFO_PRINT("usbNet->dataIface = %{public}d", usbNet->dataIface);
    if (usbNet->ctrlIface != usbNet->dataIface) {
        ret = UsbRawReleaseInterface(usbNet->devHandle, usbNet->ctrlIface);
        HARCH_INFO_PRINT("ctrlIface ret = %{public}d", ret);

        ret = UsbRawReleaseInterface(usbNet->devHandle, usbNet->dataIface);
        HARCH_INFO_PRINT("dataIface ret = %{public}d", ret);
    } else {
        ret = UsbRawReleaseInterface(usbNet->devHandle, usbNet->ctrlIface);
        HARCH_INFO_PRINT("ctrlIface ret = %{public}d", ret);
    }

    if (usbNet->statusEp) {
        OsalMemFree(usbNet->statusEp);
        usbNet->statusEp = NULL;
    }

    if (usbNet->dataInEp) {
        OsalMemFree(usbNet->dataInEp);
        usbNet->dataInEp = NULL;
    }

    if (usbNet->dataOutEp) {
        OsalMemFree(usbNet->dataOutEp);
        usbNet->dataOutEp = NULL;
    }
}

static void UsbnetHostUnRegisterNet(struct UsbnetHost *usbNet)
{
    HARCH_INFO_PRINT("begin");
    // send msg to net unregister net
    int32_t reply = 0;
    int32_t ret = UsbnetHostSendBufToNet(usbNet->hdfNetIoServ, USB_NET_CLOSE_NET,
        (unsigned char *)&(usbNet->net), sizeof(struct UsbnetTransInfo), &reply);
    if (ret != HDF_SUCCESS || reply != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d fail to UsbnetHostSendBufToNet ret = %{public}d, reply = %{public}d!",
            __func__, __LINE__, ret, reply);
    }

    // net unregister
    if (HdfDeviceUnregisterEventListener(usbNet->hdfNetIoServ, usbNet->hdfNetListener)) {
        HDF_LOGE("fail to  unregister listener");
        return;
    }
    HARCH_INFO_PRINT("HdfDeviceUnregisterEventListener");
    HdfIoServiceRecycle(usbNet->hdfNetIoServ);
    HARCH_INFO_PRINT("HdfIoServiceRecycle");
    return;
}

// Sync write cmd
int32_t UsbnetHostWriteCmdSync(struct UsbnetHost *usbNet, struct UsbnetHostCmdParam cmdParam)
{
    uint8_t cmd = cmdParam.cmd;
    uint8_t reqtype = cmdParam.reqtype;
    uint16_t value = cmdParam.value;
    uint16_t index = cmdParam.index;
    const void *data = cmdParam.data;
    uint16_t size = cmdParam.size;
    HARCH_INFO_PRINT("usbnet_write_cmd cmd=0x%{public}02x reqtype=%{public}02x"
        " value=0x%{public}04x index=0x%{public}04x size=%{public}x\n",
        cmd, reqtype, value, index, size);

    struct UsbControlRequestData ctrlReq = {};
    ctrlReq.requestType = reqtype;
    ctrlReq.requestCmd = cmd;
    ctrlReq.value = CPU_TO_LE16(value);
    ctrlReq.index = CPU_TO_LE16(index);
    ctrlReq.data = (unsigned char *)data;
    ctrlReq.length = CPU_TO_LE16(size);
    ctrlReq.timeout = USB_CTRL_SET_TIMEOUT;

    HARCH_INFO_PRINT("usbfs: UsbRawControlMsg data = %{public}x\n", *(ctrlReq.data));
    int32_t ret = UsbRawControlMsg(usbNet->devHandle, &ctrlReq);
    HARCH_INFO_PRINT("%{public}d", ret);
    if (ret < 0) {
        return HDF_FAILURE;
    }

    HARCH_INFO_PRINT("usbnet_write_cmd cmd=0x%{public}02x reqtype=%{public}02x"
        " value=0x%{public}04x index=0x%{public}04x size=%{public}d, data = %{public}x\n",
        ctrlReq.requestCmd, ctrlReq.requestType, ctrlReq.value, ctrlReq.index, ctrlReq.length, *(ctrlReq.data));
    return ret;
}

static void UsbnetHostWriteCmdAsyncFree(struct UsbnetHost *usbNet)
{
    if (usbNet->ctrlWriteReqAsync) {
        UsbRawFreeRequest(usbNet->ctrlWriteReqAsync);
        usbNet->ctrlWriteReqAsync = NULL;
    }
}

static void UsbnetHostReadCmdSyncFree(struct UsbnetHost *usbNet)
{
    if (usbNet->ctrlReadReqSync) {
        UsbRawFreeRequest(usbNet->ctrlReadReqSync);
        usbNet->ctrlReadReqSync = NULL;
    }
}

void UsbnetHostRelease(struct UsbnetHost *usbNet)
{
    HARCH_INFO_PRINT("begin");
    int ret = HDF_SUCCESS;
    if (usbNet == NULL) {
        HDF_LOGE("%{public}s: invalid usbNet", __func__);
        return;
    }
    HARCH_INFO_PRINT("bus:%{public}d+dev:%{public}d", usbNet->busNum, usbNet->devAddr);
    // net release
    UsbnetHostUnRegisterNet(usbNet);

    // usb io stop
    UsbStopIo(usbNet);
    // usb release
    UsbnetHostFreeRequests(usbNet);
    // cmd release
    UsbnetHostReadCmdSyncFree(usbNet);
    UsbnetHostWriteCmdAsyncFree(usbNet);
    UsbReleaseInterfaces(usbNet);
    if (usbNet->devHandle != NULL) {
        HARCH_INFO_PRINT("UsbRawCloseDevice");
        ret = UsbRawCloseDevice(usbNet->devHandle);
        HARCH_INFO_PRINT("UsbRawCloseDevice ret = %{public}d", ret);
    }

    if (usbNet->paddingPkt) {
        HARCH_INFO_PRINT("free paddingPkt");
        OsalMemFree(usbNet->paddingPkt);
        usbNet->paddingPkt = NULL;
    }

    if (usbNet->config != NULL) {
        HARCH_INFO_PRINT("free Config");
        UsbRawFreeConfigDescriptor(usbNet->config);
        usbNet->config = NULL;
    }

    if (usbNet->session != NULL) {
        HARCH_INFO_PRINT("exit session");
        ret = UsbRawExit(usbNet->session);
        HARCH_INFO_PRINT("session exit ret = %{public}d", ret);
    }

    OsalMutexDestroy(&usbNet->readLock);
    OsalMutexDestroy(&usbNet->writeLock);
    OsalMutexDestroy(&usbNet->sendNetLock);

    usbNet->initFlag = false;
    usbNet->allocFlag = false;
    return;
}
