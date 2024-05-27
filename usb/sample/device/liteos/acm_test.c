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

#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "hdf_io_service_if.h"
#include "hdf_log.h"
#include "osal_mem.h"
#include "osal_mutex.h"
#include "osal_thread.h"
#include "osal_time.h"
#include "securec.h"
#include "usb_dev_test.h"

#define HDF_LOG_TAG cdc_acm_test

enum UsbSerialCmd {
    USB_SERIAL_OPEN = 0,
    USB_SERIAL_CLOSE,
    USB_SERIAL_READ,
    USB_SERIAL_WRITE,
    USB_SERIAL_GET_BAUDRATE,
    USB_SERIAL_SET_BAUDRATE,
    USB_SERIAL_SET_PROP,
    USB_SERIAL_GET_PROP,
    USB_SERIAL_REGIST_PROP,
};

static struct HdfSBuf *g_data;
static struct HdfSBuf *g_reply;
static struct HdfIoService *g_acmService;
static struct OsalMutex g_lock;

static void TestWrite(const char *buf)
{
    HdfSbufFlush(g_data);
    (void)HdfSbufWriteString(g_data, buf);
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_WRITE, g_data, g_reply);
    if (status != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Dispatch USB_SERIAL_WRITE failed status = %{public}d", __func__, status);
    }
}

static void TestRead(void)
{
    HdfSbufFlush(g_reply);
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_READ, g_data, g_reply);
    if (status != HDF_SUCCESS) {
        printf("%s: Dispatch USB_SERIAL_READ failed status = %d", __func__, status);
        return;
    }
    if (HdfSbufGetDataSize(g_reply) != 0) {
        const char *tmp = HdfSbufReadString(g_reply);
        if (tmp && strlen(tmp) > 0) {
            printf("%s: read : %s \n", __func__, tmp);
        }
    }
}

static bool g_readRuning = false;
#define SLEEP_READ 100
static void ReadThread(void *arg)
{
    (void)arg;
    while (g_readRuning) {
        OsalMutexLock(&g_lock);
        TestRead();
        OsalMutexUnlock(&g_lock);
        OsalMDelay(SLEEP_READ);
    }
}

static void StartPThreadRead(void)
{
    pthread_t tid;
    if ((pthread_create(&tid, NULL, ReadThread, NULL)) == -1) {
        printf("create error!\n");
    }
}

#define STR_LEN       256
#define SLEEP_GETCHAR 100000
static void Test02(void)
{
    char str[STR_LEN] = {0};
    char *getStr = NULL;
    if (OsalMutexInit(&g_lock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: init lock fail!", __func__);
        return;
    }
    while (1) {
        printf("\ninput: \nr: for read acm\nw: for write acm \nq: for exit \n");
        char ch = (char)getchar();
        if (ch == 'r') {
            printf("input: 'q' quit reading\n");
            g_readRuning = true;
            StartPThreadRead();
            while (getchar() != 'q') {
                printf("input: 'q' quit reading\n");
                usleep(SLEEP_GETCHAR);
            }
            g_readRuning = false;
        } else if (ch == 'w') {
            printf("input strings and press enter to send\n");
            getchar();
            getStr = gets_s(str, STR_LEN - 1);
            if (getStr == NULL) {
                HDF_LOGE("%{public}s: gets_s failed", __func__);
            }
            TestWrite(str);
        } else if (ch == 'q') {
            return;
        }
    }
}

int32_t AcmTest(int32_t argc, const char *argv[])
{
    (void)argc;
    (void)argv;
    int32_t status;
    g_acmService = HdfIoServiceBind("usbfn_cdcacm");
    if (g_acmService == NULL || g_acmService->dispatcher == NULL || g_acmService->dispatcher->Dispatch == NULL) {
        HDF_LOGE("%{public}s: GetService err", __func__);
        return HDF_FAILURE;
    }

    g_data = HdfSbufObtainDefaultSize();
    g_reply = HdfSbufObtainDefaultSize();
    if (g_data == NULL || g_reply == NULL) {
        HDF_LOGE("%{public}s: GetService err", __func__);
        return HDF_FAILURE;
    }

    status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_OPEN, g_data, g_reply);
    if (status != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Dispatch USB_SERIAL_OPEN err", __func__);
        return HDF_FAILURE;
    }

    Test02();

    status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_CLOSE, g_data, g_reply);
    if (status != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Dispatch USB_SERIAL_CLOSE err", __func__);
        return HDF_FAILURE;
    }

    HdfSbufRecycle(g_data);
    HdfSbufRecycle(g_reply);
    return HDF_SUCCESS;
}
