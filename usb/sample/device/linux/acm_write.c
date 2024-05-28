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

#include <hdf_log.h>
#include <hdf_remote_service.h>
#include <hdf_sbuf.h>
#include <servmgr_hdi.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "cdcacm.h"
#include "usb_dev_test.h"

#define HDF_LOG_TAG cdc_acm_write

static struct HdfSBuf *g_data;
static struct HdfSBuf *g_reply;
static struct HdfRemoteService *g_acmService;

static void TestWrite(char *buf)
{
    HdfSbufFlush(g_data);
    (void)HdfSbufWriteString(g_data, buf);
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, USB_SERIAL_WRITE, g_data, g_reply);
    if (status != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Dispatch USB_SERIAL_WRITE failed status = %{public}d", __func__, status);
    }
}

#define STR_LEN   1024
#define NUM_INPUT 2
int32_t AcmWrite(int32_t argc, const char *argv[])
{
    struct HDIServiceManager *servmgr = HDIServiceManagerGet();
    if (servmgr == NULL) {
        HDF_LOGE("%{public}s: HDIServiceManagerGet err", __func__);
        return HDF_FAILURE;
    }
    g_acmService = servmgr->GetService(servmgr, "usbfn_cdcacm");
    HDIServiceManagerRelease(servmgr);
    if (g_acmService == NULL) {
        return HDF_FAILURE;
    }

    g_data = HdfSbufTypedObtain(SBUF_IPC);
    g_reply = HdfSbufTypedObtain(SBUF_IPC);
    if (g_data == NULL || g_reply == NULL) {
        return HDF_FAILURE;
    }

    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, USB_SERIAL_OPEN, g_data, g_reply);
    if (status != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (argc >= NUM_INPUT) {
        struct timeval time;
        char str[STR_LEN] = {0};
        gettimeofday(&time, NULL);
        status = snprintf_s(str, STR_LEN, STR_LEN - 1, "[XTSCHECK] %d.%06d, send data[%s] to host\n", time.tv_sec,
            time.tv_usec, argv[1]);
        if (status < 0) {
            HDF_LOGE("%{public}s: snprintf_s failed", __func__);
            return HDF_FAILURE;
        }
        FILE *fp = fopen("/data/acm_write_xts", "a+");
        if (fp == NULL) {
            HDF_LOGE("%{public}s: fopen failed", __func__);
            return HDF_FAILURE;
        }
        (void)fwrite(str, strlen(str), 1, fp);
        (void)fclose(fp);
        TestWrite((char *)argv[1]);
    }
    status = g_acmService->dispatcher->Dispatch(g_acmService, USB_SERIAL_CLOSE, g_data, g_reply);
    if (status) {
        HDF_LOGE("%{public}s: Dispatch USB_SERIAL_CLOSE err", __func__);
        return HDF_FAILURE;
    }

    HdfSbufRecycle(g_data);
    HdfSbufRecycle(g_reply);
    return 0;
}
