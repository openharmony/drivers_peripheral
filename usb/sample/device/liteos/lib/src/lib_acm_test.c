/*
 * Copyright (c) 2013-2019, Huawei Technologies Co., Ltd. All rights reserved.
 * Copyright (c) 2020, Huawei Device Co., Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "securec.h"
#include "hdf_log.h"
#include "osal_mem.h"
#include "hdf_io_service_if.h"
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include "osal_thread.h"
#include "osal_mutex.h"
#include "osal_time.h"
#include "securec.h"
#define HDF_LOG_TAG   cdc_acm_write
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
struct HdfSBuf *g_data;
struct HdfSBuf *g_reply;
struct HdfIoService *g_acmService;

int32_t check_service()
{
    if (g_acmService == NULL || g_acmService->dispatcher == NULL || g_acmService->dispatcher->Dispatch == NULL) {
        HDF_LOGE("%s: GetService err", __func__);
        return HDF_FAILURE;
    }
    if (g_data == NULL || g_reply == NULL) {
        HDF_LOGE("%s: GetService err", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void acm_open()
{
    int status;
    g_acmService = HdfIoServiceBind("usbfn_cdcacm");
    if (g_acmService == NULL || g_acmService->dispatcher == NULL || g_acmService->dispatcher->Dispatch == NULL) {
        HDF_LOGE("%s: GetService err", __func__);
    }
    g_data = HdfSBufObtainDefaultSize();
    g_reply = HdfSBufObtainDefaultSize();
    if (g_data == NULL || g_reply == NULL) {
        HDF_LOGE("%s: GetService err", __func__);
    }
    status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_OPEN, g_data, g_reply);
    if (status) {
        HDF_LOGE("%s: Dispatch USB_SERIAL_OPEN err", __func__);
    }
}

void acm_close()
{
    int status;
    if (check_service()) {
        HDF_LOGE("%s: GetService err", __func__);
        return;
    }
    status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_CLOSE, g_data, g_reply);
    if (status) {
        HDF_LOGE("%s: Dispatch USB_SERIAL_CLOSE err", __func__);
    }
    HdfSBufRecycle(g_data);
    HdfSBufRecycle(g_reply);
    HdfIoServiceRecycle(g_acmService);
}

void acm_write(const char *buf)
{
    if (check_service()) {
        HDF_LOGE("%s: GetService err", __func__);
        return;
    }
    HdfSbufFlush(g_data);
    (void)HdfSbufWriteString(g_data, buf);
    int status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_WRITE, g_data, g_reply);
    if (status <= 0) {
        HDF_LOGE("%s: Dispatch USB_SERIAL_WRITE failed status = %d", __func__, status);
        return;
    }
    printf("acm_write:%s\n", buf);
}

void acm_read(char *str, int timeout)
{
    int ret;
    if (check_service()) {
        HDF_LOGE("%s: GetService err", __func__);
        return;
    }
    while(timeout-- > 0) {
        HdfSbufFlush(g_reply);
        int status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_READ, g_data, g_reply);
        if (status) {
            HDF_LOGE("%s: Dispatch USB_SERIAL_READ failed status = %d", __func__, status);
            return;
        }
        const char *tmp = HdfSbufReadString(g_reply);
        if (str && tmp && strlen(tmp) > 0) {
            ret = memcpy_s(str, 256, tmp, strlen(tmp));
            if (ret != EOK) {
                HDF_LOGE("%s:%d ret=%d memcpy_s error", ret);
            }
            printf("acm_read:%s\n", tmp);
            return;
        }
        sleep(1);
    }
}

void acm_prop_regist(const char *propName, const char *propValue)
{
    if (check_service()) {
        HDF_LOGE("%s: GetService err", __func__);
        return;
    }
    HdfSbufFlush(g_data);
    (void)HdfSbufWriteString(g_data, propName);
    (void)HdfSbufWriteString(g_data, propValue);
    int status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_REGIST_PROP, g_data, g_reply);
    if (status) {
        HDF_LOGE("%s: Dispatch USB_SERIAL_WRITE failed status = %d", __func__, status);
        return;
    }
    printf("prop_regist:%s = %s\n", propName, propValue);
}

void acm_prop_write(const char *propName, const char *propValue)
{
    if (check_service()) {
        HDF_LOGE("%s: GetService err", __func__);
        return;
    }
    HdfSbufFlush(g_data);
    HdfSbufFlush(g_reply);
    (void)HdfSbufWriteString(g_data, propName);
    (void)HdfSbufWriteString(g_data, propValue);
    if (g_acmService == NULL || g_acmService->dispatcher == NULL || g_acmService->dispatcher->Dispatch == NULL) {
        HDF_LOGE("%s: GetService err", __func__);
    }
    int status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_SET_PROP, g_data, g_reply);
    if (status) {
        HDF_LOGE("%s: Dispatch USB_SERIAL_WRITE failed status = %d", __func__, status);
        return;
    }
    printf("prop_write:%s = %s\n", propName, propValue);
}

void acm_prop_read(const char *propName, char *propValue)
{
    if (check_service()) {
        HDF_LOGE("%s: GetService err", __func__);
        return;
    }
    HdfSbufFlush(g_data);
    HdfSbufFlush(g_reply);
    (void)HdfSbufWriteString(g_data, propName);
    int status = g_acmService->dispatcher->Dispatch(&g_acmService->object, USB_SERIAL_GET_PROP, g_data, g_reply);
    if (status) {
        HDF_LOGE("%s: Dispatch USB_SERIAL_GET_PROP failed status = %d", __func__, status);
        return;
    }
    const char *tmp = HdfSbufReadString(g_reply);
    if (propValue && tmp && strlen(tmp) > 0) {
        errno_t err = memcpy_s(propValue, 256, tmp, strlen(tmp));
        if (err != EOK) {
            HDF_LOGE("%s:%d err=%d memcpy_s error", err);
        }
        printf("prop_read:%s\n", tmp);
        return;
    }
}
