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

#include "securec.h"
#include "hdf_log.h"
#include "osal_mem.h"
#include "hdf_io_service_if.h"
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <fcntl.h>
#include "osal_thread.h"
#include "osal_mutex.h"
#include "osal_time.h"
#include "osal_file.h"
#include "securec.h"
#define HDF_LOG_TAG   cdc_acm_speed

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
    USB_SERIAL_WRITE_SPEED,
    USB_SERIAL_WRITE_GET_TEMP_SPEED,
    USB_SERIAL_WRITE_SPEED_DONE,
    USB_SERIAL_WRITE_GET_TEMP_SPEED_UINT32,
};

static struct HdfSBuf *g_data;
static struct HdfSBuf *g_reply;
static struct HdfIoService *g_acmService;
static bool g_readRuning = false;
static void TestSpeed()
{
    HdfSbufFlush(g_reply);
    int status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_WRITE_SPEED, g_data, g_reply);
    if (status) {
        HDF_LOGE("%{public}s: Dispatch USB_SERIAL_WRITE_SPEED failed status = %{public}d", __func__, status);
        return;
    }
}

static void GetTempSpeed()
{
    uint32_t speed;
    HdfSbufFlush(g_reply);
    int status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_WRITE_GET_TEMP_SPEED_UINT32, g_data, g_reply);
    if (status) {
        HDF_LOGE("%{public}s: Dispatch USB_SERIAL_WRITE_GET_TEMP_SPEED failed status = %{public}d", __func__, status);
        return;
    }
    if (!HdfSbufReadUint32(g_reply, &speed)) {
        HDF_LOGE("%{public}s: HdfSbufReadFloat failed", __func__);
        return;
    }
    printf("speed : %f MB/s\n", (float)speed / 10000.0);
}

static void GetSpeedDone()
{
    uint8_t isDone = 0;
    HdfSbufFlush(g_reply);
    int status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_WRITE_SPEED_DONE, g_data, g_reply);
    if (status) {
        HDF_LOGE("%{public}s: Dispatch USB_SERIAL_WRITE_SPEED_DONE failed status = %{public}d", __func__, status);
        return;
    }
    if (!HdfSbufReadUint8(g_reply, &isDone)) {
        HDF_LOGE("%{public}s: HdfSbufReadFloat failed", __func__);
        return;
    }
    if (isDone) {
        g_readRuning = false;
    }
}

int main(int argc, char *argv[])
{
    int status;
    g_acmService = HdfIoServiceBind("usbfn_cdcacm");
    if (g_acmService == NULL) {
        HDF_LOGE("%{public}s: GetService err", __func__);
        return HDF_FAILURE;
    }

    g_data = HdfSBufObtainDefaultSize();
    g_reply = HdfSBufObtainDefaultSize();
    if (g_data == NULL || g_reply == NULL) {
        HDF_LOGE("%{public}s: GetService err", __func__);
        return HDF_FAILURE;
    }

    status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_OPEN, g_data, g_reply);
    if (status) {
        HDF_LOGE("%{public}s: Dispatch USB_SERIAL_OPEN err", __func__);
        return HDF_FAILURE;
    }

    TestSpeed();
    g_readRuning = true;
    while (g_readRuning) {
        sleep(2);
        GetTempSpeed();
        GetSpeedDone();
    }

    status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_CLOSE, g_data, g_reply);
    if (status) {
        HDF_LOGE("%{public}s: Dispatch USB_SERIAL_CLOSE err", __func__);
        return HDF_FAILURE;
    }

    HdfSBufRecycle(g_data);
    HdfSBufRecycle(g_reply);
    HdfIoServiceRecycle(g_acmService);
    return 0;
}
