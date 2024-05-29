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

#include "usbhost_nosdk_speed.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <osal_sem.h>
#include <osal_thread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "implementation/global_implementation.h"
#include "liteos_ddk_usb.h"
#include "osal_mem.h"
#include "osal_time.h"
#include "usb_pnp_notify.h"

#define USB_DEV_FS_PATH                 "/dev/bus/usb"
#define URB_COMPLETE_PROCESS_STACK_SIZE 8196
#define ENDPOINT_IN_OFFSET              7
#define DEFAULT_BUSNUM                  1
#define DEFAULT_DEVADDR                 2
static int32_t g_speedFlag = 0;
static int32_t g_busNum = DEFAULT_BUSNUM;
static int32_t g_devAddr = DEFAULT_DEVADDR;
static struct OsalSem g_sem;
static uint64_t g_send_count = 0;
static uint64_t g_recv_count = 0;
static uint64_t g_byteTotal = 0;
static struct UsbAdapterUrbs urb[TEST_CYCLE];
static struct urb *g_sendUrb = NULL;
static bool g_printData = false;
static uint8_t g_endNum;
static struct OsalSem g_timeSem;
static struct usb_device *g_fd = NULL;
static uint32_t g_sigCnt = 0;
static UsbAdapterHostEndpoint *g_uhe = NULL;
static bool g_writeOrRead = TEST_WRITE;
static struct AcmDevice *g_acm = NULL;

static void CloseDevice(void)
{
    return;
}

static int32_t OpenDevice(void)
{
    struct UsbGetDevicePara paraData;
    paraData.type = USB_PNP_DEVICE_ADDRESS_TYPE;
    paraData.busNum = (uint8_t)g_busNum;
    paraData.devNum = (uint8_t)g_devAddr;
    g_fd = UsbPnpNotifyGetUsbDevice(paraData);
    if (g_fd == NULL) {
        HDF_LOGE("%{public}s: UsbPnpNotifyGetUsbDevice err", __func__);
        return -1;
    }
    return 0;
}

static int32_t ClaimInterface(int32_t iface)
{
    HDF_LOGI("%{public}s: claim success: iface=%{public}d", __func__, iface);
    return HDF_SUCCESS;
}

static void SpeedPrint(void)
{
    double speed;
    uint64_t count;

    g_sigCnt++;
    count = (uint64_t)g_sigCnt * TEST_PRINT_TIME;
    if (count >= TEST_TIME) {
        g_speedFlag = true;
    }
    speed =
        (g_byteTotal * TEST_DOUBLE_COUNT) / (g_sigCnt * TEST_PRINT_TIME * TEST_BYTE_COUNT_UINT * TEST_BYTE_COUNT_UINT);
    printf("\nSpeed:%f MB/s\n", speed);
}

static int32_t SendProcess(void *argurb)
{
    (void)argurb;
    int32_t i;
    while (!g_speedFlag) {
        OsalSemWait(&g_sem, HDF_WAIT_FOREVER);
        for (i = 0; i < TEST_CYCLE; i++) {
            if (urb[i].inUse == 0) {
                urb[i].inUse = 1;
                break;
            }
        }

        if (i == TEST_CYCLE) {
            i = TEST_CYCLE - 1;
        }
        g_sendUrb = urb[i].urb;
        int32_t err = usb_setup_endpoint(g_fd, g_uhe, TEST_BYTE_COUNT_UINT);
        if (err < 0) {
            DPRINTFN(0, "setup failed err:%d\n", err);
            return err;
        }
        err = usb_submit_urb(g_sendUrb, 0);
        if (err < 0) {
            HDF_LOGI("SubmitBulkRequest: err:%{public}d", err);
            urb[i].inUse = 0;
            continue;
        }
        g_send_count++;
    }
    return 0;
}

static void UrbCompleteHandle(const struct urb *curUrb)
{
    if (g_printData) {
        for (int32_t i = 0; i < curUrb->actual_length; i++) {
            printf("%c", *(((char *)curUrb->transfer_buffer) + i));
        }
        fflush(stdout);
    } else if (g_recv_count % TEST_PRINT_MAX_RANGE == 0) {
        printf("#");
        fflush(stdout);
    }
}

static void UrbComplete(struct urb *curUrb)
{
    int32_t i;
    for (i = 0; i < TEST_CYCLE; i++) {
        if (urb[i].urb == curUrb) {
            if (g_byteTotal == 0) {
                OsalSemPost(&g_timeSem);
            }
            g_recv_count++;
            g_byteTotal += curUrb->actual_length;
            UrbCompleteHandle(curUrb);
            urb[i].inUse = 0;
            OsalSemPost(&g_sem);
            break;
        }
    }
}

static int32_t BeginProcessHandleFirst(void)
{
    char *data = NULL;
    for (int32_t i = 0; i < TEST_CYCLE; i++) {
        if (urb[i].urb == NULL) {
            urb[i].urb = OsalMemCalloc(sizeof(struct urb));
            if (urb[i].urb == NULL) {
                HDF_LOGE("%{public}s:%{public}d urb calloc err\n", __func__, __LINE__);
                return -1;
            }
        }
        urb[i].inUse = 0;
        urb[i].urb->dev = g_fd;
        urb[i].urb->endpoint = g_uhe;
        urb[i].urb->complete = UrbComplete;

        if (data == NULL) {
            data = OsalMemCalloc(TEST_LENGTH);
            if (data == NULL) {
                HDF_LOGE("%{public}s:%{public}d data calloc err\n", __func__, __LINE__);
                return -1;
            }
        }

        if (memset_s(data, TEST_LENGTH, 'c', TEST_LENGTH) != EOK) {
            HDF_LOGE("%{public}s:%{public}d memset_s failed.", __func__, __LINE__);
            return -1;
        }
        data[TEST_LENGTH - 1] = '\0';
        urb[i].urb->transfer_buffer = (void *)data;
        urb[i].urb->transfer_buffer_length = TEST_LENGTH;
    }

    return HDF_SUCCESS;
}

static int32_t BeginProcess(unsigned char endPoint)
{
    const int32_t transNum = 0;
    if (endPoint == 0) {
        HDF_LOGE("%{public}s:%{public}d parameter error", __func__, __LINE__);
        return -1;
    }

    g_uhe = usb_find_host_endpoint(g_fd, USB_REQUEST_TYPE_BULK, endPoint);
    if (g_uhe == NULL) {
        HDF_LOGE("%{public}s:%{public}d usb_find_host_endpoint error", __func__, __LINE__);
        return -1;
    }
    int32_t ret = BeginProcessHandleFirst();
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    HDF_LOGI("%{public}s:%{public}d test NO SDK endpoint:%{public}u", __func__, __LINE__, endPoint);

    int32_t i;
    for (i = 0; i < TEST_CYCLE; i++) {
        if (urb[i].inUse == 0) {
            urb[i].inUse = 1;
            urb[i].urbNum = transNum;
            g_sendUrb = urb[i].urb;
            ret = usb_setup_endpoint(g_fd, g_uhe, TEST_BYTE_COUNT_UINT);
            if (ret < 0) {
                DPRINTFN(0, "setup failed ret:%d\n", ret);
                return ret;
            }
            ret = usb_submit_urb(g_sendUrb, 0);
            if (ret < 0) {
                HDF_LOGI("%{public}s:%{public}d SubmitBulkRequest: ret:%{public}d", __func__, __LINE__, ret);
                urb[i].inUse = 0;
                continue;
            }
            g_send_count++;
        }
    }

    OsalSemWait(&g_timeSem, TEST_TIME);
    while (!g_speedFlag) {
        OsalSemWait(&g_timeSem, TEST_PRINT_TIME * TEST_PRINT_TIME_UINT);
        SpeedPrint();
    }

    for (i = 0; i < TEST_CYCLE; i++) {
        usb_kill_urb(urb[i].urb);
    }

    return HDF_SUCCESS;
}

static void ShowHelp(const char *name)
{
    printf(">> usage:\n");
    printf(">>      %s [<busNum> <devAddr>]  <ifaceNum> <endpoint> [<printdata>]\n", name);
    printf("\n");
}

static void UsbGetDevInfo(int32_t * const busNum, int32_t * const devNum)
{
    struct UsbGetDevicePara paraData;
    struct usb_device *usbPnpDevice = NULL;
    paraData.type = USB_PNP_DEVICE_VENDOR_PRODUCT_TYPE;
    paraData.vendorId = USB_DEVICE_VENDOR_ID;
    paraData.productId = USB_DEVICE_PRODUCT_ID;
    usbPnpDevice = UsbPnpNotifyGetUsbDevice(paraData);
    if (usbPnpDevice == NULL) {
        HDF_LOGE("%{public}s:%{public}d UsbPnpNotifyGetUsbDevice is NULL!", __func__, __LINE__);
        return;
    }
    *busNum = (int)usbPnpDevice->address;
    *devNum = (int)usbPnpDevice->port_no;
    printf("%s:%d busNum=%d devNum=%d!\n", __func__, __LINE__, *busNum, *devNum);
}

static int32_t UsbSerialOpen(void)
{
    return HDF_SUCCESS;
}
static int32_t UsbSerialClose(void)
{
    if (!g_speedFlag) {
        g_speedFlag = true;
    }
    return HDF_SUCCESS;
}

static int32_t UsbSerialSpeedInit(const struct UsbSpeedTest * const input, int32_t * const ifaceNum)
{
    int32_t ret = HDF_SUCCESS;
    if (input == NULL) {
        HDF_LOGE("%{public}s:%{public}d input is null", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    g_speedFlag = false;
    g_send_count = 0;
    g_recv_count = 0;
    g_byteTotal = 0;
    g_printData = false;
    g_writeOrRead = TEST_WRITE;
    g_sigCnt = 0;
    g_busNum = DEFAULT_BUSNUM;
    g_devAddr = DEFAULT_DEVADDR;

    UsbGetDevInfo(&g_busNum, &g_devAddr);
    if (input->paramNum == INPUT_COMPARE_PARAMNUM) {
        g_busNum = input->busNum;
        g_devAddr = input->devAddr;
        *ifaceNum = input->ifaceNum;
        g_endNum = input->writeOrRead;
        g_writeOrRead = ((g_endNum >> ENDPOINT_IN_OFFSET) == 0) ? TEST_WRITE : TEST_READ;
        if (g_writeOrRead == TEST_READ) {
            g_printData = input->printData;
        }
    } else if (input->paramNum == INPUT_COMPARE_NUMTWO) {
        g_busNum = input->busNum;
        g_devAddr = input->devAddr;
        *ifaceNum = input->ifaceNum;
        g_endNum = input->writeOrRead;
        g_writeOrRead = ((g_endNum >> ENDPOINT_IN_OFFSET) == 0) ? TEST_WRITE : TEST_READ;
    } else if (input->paramNum == INPUT_COMPARE_NUMONE) {
        *ifaceNum = input->ifaceNum;
        g_endNum = input->writeOrRead;
        g_writeOrRead = ((g_endNum >> ENDPOINT_IN_OFFSET) == 0) ? TEST_WRITE : TEST_READ;
    } else {
        printf("Error: parameter error! \n\n");
        ShowHelp("speedtest");
        return HDF_FAILURE;
    }
    OsalSemInit(&g_sem, 0);
    OsalSemInit(&g_timeSem, 0);

    return ret;
}

static int32_t UsbSerialSpeedThreadCreate(void)
{
    int32_t ret;
    struct OsalThread urbSendProcess;
    struct OsalThreadParam threadCfg;
    ret = memset_s(&threadCfg, sizeof(threadCfg), 0, sizeof(threadCfg));
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memset_s failed", __func__, __LINE__);
        return ret;
    }
    threadCfg.name = "urb send process";
    threadCfg.priority = OSAL_THREAD_PRI_DEFAULT;
    threadCfg.stackSize = URB_COMPLETE_PROCESS_STACK_SIZE;

    ret = OsalThreadCreate(&urbSendProcess, (OsalThreadEntry)SendProcess, NULL);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("OsalThreadCreate failed, ret = %{public}d", ret);
        return ret;
    }

    ret = OsalThreadStart(&urbSendProcess, &threadCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("OsalThreadStart failed, ret = %{public}d", ret);
        return ret;
    }

    return ret;
}

static int32_t UsbSerialSpeed(struct HdfSBuf *data)
{
    int32_t ifaceNum = 3;
    int32_t ret;
    struct UsbSpeedTest *input = NULL;
    uint32_t size = 0;
    if (g_acm->busy) {
        HDF_LOGE("%{public}s: %{public}d speed test busy", __func__, __LINE__);
        ret = HDF_ERR_IO;
        goto END;
    } else {
        g_acm->busy = true;
    }

    (void)HdfSbufReadBuffer(data, (const void **)&input, &size);
    if (input == NULL || size != sizeof(struct UsbSpeedTest)) {
        HDF_LOGE("%{public}s: %{public}d sbuf read buffer failed\n", __func__, __LINE__);
        ret = HDF_ERR_IO;
        goto END;
    }

    ret = UsbSerialSpeedInit(input, &ifaceNum);
    if (ret != HDF_SUCCESS) {
        goto END;
    }

    OpenDevice();

    ret = ClaimInterface(ifaceNum);
    if (ret != HDF_SUCCESS) {
        goto END;
    }

    ret = UsbSerialSpeedThreadCreate();
    if (ret != HDF_SUCCESS) {
        goto END;
    }

    ret = BeginProcess(g_endNum);
    if (ret != HDF_SUCCESS) {
        goto END;
    }

END:
    g_acm->busy = false;
    if (ret != HDF_SUCCESS) {
        printf("please check whether usb drv so is existing or not,like g_acm, ecm,if not,remove it and test again!\n");
    }
    CloseDevice();
    return ret;
}

static int32_t AcmDeviceDispatch(
    struct HdfDeviceIoClient * const client, int32_t cmd, struct HdfSBuf * const data, struct HdfSBuf * const reply)
{
    (void)reply;
    if (client == NULL) {
        HDF_LOGE("%{public}s: client is NULL", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (client->device == NULL) {
        HDF_LOGE("%{public}s: client->device is NULL", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (client->device->service == NULL) {
        HDF_LOGE("%{public}s: client->device->service is NULL", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    g_acm = (struct AcmDevice *)client->device->service;

    switch (cmd) {
        case USB_SERIAL_OPEN:
            return UsbSerialOpen();
        case USB_SERIAL_CLOSE:
            return UsbSerialClose();
        case USB_SERIAL_SPEED:
            return UsbSerialSpeed(data);
        default:
            return HDF_ERR_NOT_SUPPORT;
    }

    return HDF_SUCCESS;
}

static int32_t AcmDriverBind(struct HdfDeviceObject *device)
{
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is null", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    g_acm = (struct AcmDevice *)OsalMemCalloc(sizeof(*g_acm));
    if (g_acm == NULL) {
        HDF_LOGE("%{public}s: Alloc usb g_acm device failed", __func__);
        return HDF_FAILURE;
    }

    g_acm->device = device;
    device->service = &(g_acm->service);
    if (g_acm->device && g_acm->device->service) {
        g_acm->device->service->Dispatch = AcmDeviceDispatch;
    }
    return HDF_SUCCESS;
}

static int32_t AcmDriverInit(struct HdfDeviceObject *device)
{
    (void)device;
    return 0;
}

static void AcmDriverRelease(struct HdfDeviceObject *device)
{
    (void)device;
    return;
}

struct HdfDriverEntry g_usbNoSdkSpeedDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "usb_nosdkspeed",
    .Bind = AcmDriverBind,
    .Init = AcmDriverInit,
    .Release = AcmDriverRelease,
};

HDF_INIT(g_usbNoSdkSpeedDriverEntry);
