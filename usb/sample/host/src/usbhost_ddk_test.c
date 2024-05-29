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

#include "usbhost_ddk_test.h"
#include <inttypes.h>
#include <securec.h>
#include <signal.h>

#define HDF_LOG_TAG USB_HOST_DDK_TEST

#ifdef __LITEOS_USB_HOST_DDK_TEST__
typedef enum {
    CMD_OPEN_PARM = 0,
    CMD_CLOSE_PARM,
    CMD_WRITE_PARM,
    CMD_READ_PARM,
    CMD_GET_BAUDRATE,
    CMD_SET_BAUDRATE,
    CMD_WRITE_DATA_SYNC,
    CMD_READ_DATA_SYNC,
    CMD_CLASS_CTRL_SYNC,
    CMD_STD_CTRL_GET_DESCRIPTOR_CMD,
    CMD_STD_CTRL_GET_STATUS_CMD,
    CMD_STD_CTRL_GET_CONFIGURATION,
    CMD_STD_CTRL_GET_INTERFACE,
    CMD_STD_CTRL_GET_DESCRIPTOR_ASYNC,
    CMD_ADD_INTERFACE,
    CMD_REMOVE_INTERFACE,
} SerialOPCmd;
#endif

#define BUFFER_MAX_LEN   1024
#define SPEED_SLEEP_TIME 300

struct HdfSBuf *g_data = NULL;
struct HdfSBuf *g_reply = NULL;
#ifdef __LITEOS_USB_HOST_DDK_TEST__
static struct HdfIoService *g_acmService = NULL;
#else
struct HdfRemoteService *g_acmService = NULL;
#endif
static bool g_exitFlag = false;

int32_t UsbObtainSbuf(void)
{
    if (g_acmService == NULL) {
        HDF_LOGE("%{public}s:%{public}d GetService err", __func__, __LINE__);
        return HDF_FAILURE;
    }

#ifdef __LITEOS_USB_HOST_DDK_TEST__
    g_data = HdfSbufObtainDefaultSize();
    g_reply = HdfSbufObtainDefaultSize();
#else
    g_data = HdfSbufTypedObtain(SBUF_IPC);
    g_reply = HdfSbufTypedObtain(SBUF_IPC);
#endif
    if (g_data == NULL || g_reply == NULL) {
        HDF_LOGE("%{public}s:%{public}d HdfSbufTypedObtain err", __func__, __LINE__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbHostDdkTestInit(const char *apiType)
{
    const char *acmRawServiceName = "usbhost_acm_rawapi_service";
    const char *acmServiceName = "usbhost_acm_pnp_service";
    const char *ecmServiceName = "usbhost_ecm_pnp_service";
#ifndef __LITEOS_USB_HOST_DDK_TEST__
    struct HDIServiceManager *servmgr = HDIServiceManagerGet();
    if (servmgr == NULL) {
        HDF_LOGE("%{public}s:%{public}d HDIServiceManagerGet err", __func__, __LINE__);
        return HDF_FAILURE;
    }
#endif
    if (apiType == NULL) {
        return HDF_FAILURE;
    }
    if (!strcmp(apiType, "-SDK")) {
        HDF_LOGI("%{public}s:%{public}d test SDK API, service=%{public}s", __func__, __LINE__, acmServiceName);
#ifdef __LITEOS_USB_HOST_DDK_TEST__
        g_acmService = HdfIoServiceBind(acmServiceName);
#else
        g_acmService = servmgr->GetService(servmgr, acmServiceName);
#endif
    } else if (!strcmp(apiType, "-RAW")) {
        HDF_LOGI("%{public}s:%{public}d test RAW API, service=%{public}s", __func__, __LINE__, acmRawServiceName);
#ifdef __LITEOS_USB_HOST_DDK_TEST__
        g_acmService = HdfIoServiceBind(acmRawServiceName);
#else
        g_acmService = servmgr->GetService(servmgr, acmRawServiceName);
#endif
    } else if (!strcmp(apiType, "-ECM")) {
        HDF_LOGI("%{public}s:%{public}d test ECM API, service=%{public}s", __func__, __LINE__, ecmServiceName);
#ifdef __LITEOS_USB_HOST_DDK_TEST__
        g_acmService = HdfIoServiceBind(ecmServiceName);
#else
        g_acmService = servmgr->GetService(servmgr, ecmServiceName);
#endif
    } else {
        HDF_LOGE("%{public}s:%{public}d apiType=%{public}s is not define", __func__, __LINE__, apiType);
        return HDF_FAILURE;
    }
#ifndef __LITEOS_USB_HOST_DDK_TEST__
    HDIServiceManagerRelease(servmgr);
#endif
    if (UsbObtainSbuf() != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static void TestModuleWriteLog(int32_t cmdType, const char *str)
{
#ifdef __LITEOS_USB_HOST_DDK_TEST__
    bool runFlag = false;
#else
    bool runFlag = true;
#endif
    if (runFlag) {
        int32_t ret;
        char buffer[BUFFER_MAX_LEN];
        FILE *fp = NULL;
        struct timeval time;

        gettimeofday(&time, NULL);
        switch (cmdType) {
            case HOST_ACM_SYNC_READ:
            case HOST_ACM_ASYNC_READ:
                fp = fopen("/data/acm_read_xts", "a+");
                ret = snprintf_s(buffer, BUFFER_MAX_LEN, BUFFER_MAX_LEN - 1,
                    "[XTSCHECK] %d.%06d, recv data[%s] from device\n", time.tv_sec, time.tv_usec, str);
                break;
            case HOST_ACM_SYNC_WRITE:
            case HOST_ACM_ASYNC_WRITE:
                fp = fopen("/data/acm_write_xts", "a+");
                ret = snprintf_s(buffer, BUFFER_MAX_LEN, BUFFER_MAX_LEN - 1,
                    "[XTSCHECK] %d.%06d, send data[%s] to device\n", time.tv_sec, time.tv_usec, str);
                break;
            case HOST_ACM_CTRL_READ:
                fp = fopen("/data/acm_read_xts", "a+");
                ret = snprintf_s(buffer, BUFFER_MAX_LEN, BUFFER_MAX_LEN - 1, "[XTSCHECK] %d.%06d, %s\n", time.tv_sec,
                    time.tv_usec, str);
                break;
            case HOST_ACM_CTRL_WRITE:
                fp = fopen("/data/acm_write_xts", "a+");
                ret = snprintf_s(buffer, BUFFER_MAX_LEN, BUFFER_MAX_LEN - 1,
                    "[XTSCHECK] %d.%06d, usb serial control command[%s] done\n", time.tv_sec, time.tv_usec, str);
                break;
            case HOST_ACM_SPEED_TEST:
            default:
                ret = HDF_SUCCESS;
        }

        if (ret != HDF_SUCCESS) {
            (void)fclose(fp);
            return;
        }
        (void)fwrite(buffer, strlen(buffer), 1, fp);
        (void)fclose(fp);
    }
}

int32_t UsbHostDdkTestAsyncRead(char * const readSbuf)
{
    HdfSbufFlush(g_reply);
#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_READ_PARM, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_READ_PARM, g_data, g_reply);
#endif
    if (status < 0) {
        g_exitFlag = true;
        printf("%s:%d Dispatch USB_SERIAL_READ failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch USB_SERIAL_READ failed status = %{public}d",
            __func__, __LINE__, status);
        return status;
    }

    const char *tmp = HdfSbufReadString(g_reply);
    if (tmp && strlen(tmp) > 0) {
        if (readSbuf != NULL) {
            errno_t err = memcpy_s(readSbuf, DATA_MAX_LEN, tmp, strlen(tmp));
            if (err != EOK) {
                HDF_LOGE("%{public}s:%{public}d err=%{public}d", __func__, __LINE__, err);
            }
        }
        printf("%s:%d %s-%zu!\n", __func__, __LINE__, tmp, strlen(tmp));
        HDF_LOGD("%{public}s:%{public}d %{public}s-%{public}zu!", __func__, __LINE__, tmp, strlen(tmp));
        TestModuleWriteLog(HOST_ACM_ASYNC_READ, tmp);
    }

    return HDF_SUCCESS;
}

void UsbHostDdkTestAsyncWrite(const char *buf)
{
    if (buf == NULL) {
        return;
    }
    HdfSbufFlush(g_data);

    if (!HdfSbufWriteString(g_data, buf)) {
        printf("%s:%d HdfSbufWriteString error\n", __func__, __LINE__);
        HDF_LOGE("%{public}s:%{public}d HdfSbufWriteString error", __func__, __LINE__);
        return;
    }

#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_WRITE_PARM, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_WRITE_PARM, g_data, g_reply);
#endif
    if (status <= HDF_SUCCESS) {
        g_exitFlag = true;
        printf("%s:%d Dispatch USB_SERIAL_WRITE failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch USB_SERIAL_WRITE failed status = %{public}d",
            __func__, __LINE__, status);
        return;
    }

    printf("%s:%d %s-%zu!\n", __func__, __LINE__, buf, strlen(buf));
    HDF_LOGI("%{public}s:%{public}d %{public}s-%{public}zu!", __func__, __LINE__, buf, strlen(buf));
    TestModuleWriteLog(HOST_ACM_ASYNC_WRITE, buf);
}

void UsbHostDdkTestSyncRead(char *readSbuf)
{
    HdfSbufFlush(g_reply);

#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_READ_DATA_SYNC, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_READ_DATA_SYNC, g_data, g_reply);
#endif
    if (status != HDF_SUCCESS) {
        g_exitFlag = true;
        printf("%s:%d Dispatch CMD_READ_DATA_SYNC failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_READ_DATA_SYNC failed status = %{public}d",
            __func__, __LINE__, status);
        return;
    }

    const char *tmp = HdfSbufReadString(g_reply);
    if (tmp && strlen(tmp) > 0) {
        if (readSbuf != NULL) {
            errno_t err = memcpy_s(readSbuf, DATA_MAX_LEN, tmp, strlen(tmp));
            if (err != EOK) {
                HDF_LOGE("%{public}s:%{public}d err=%{public}d", __func__, __LINE__, err);
            }
        }
        printf("%s:%d %s-%zu!\n", __func__, __LINE__, tmp, strlen(tmp));
        HDF_LOGD("%{public}s:%{public}d %{public}s-%{public}zu !", __func__, __LINE__, tmp, strlen(tmp));
        TestModuleWriteLog(HOST_ACM_SYNC_READ, tmp);
    }
}

void UsbHostDdkTestSyncWrite(const char *buf)
{
    HdfSbufFlush(g_data);

    if (!HdfSbufWriteString(g_data, buf)) {
        printf("%s:%d HdfSbufWriteString error\n", __func__, __LINE__);
        HDF_LOGE("%{public}s:%{public}d HdfSbufWriteString error", __func__, __LINE__);
        return;
    }

#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_WRITE_DATA_SYNC, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_WRITE_DATA_SYNC, g_data, g_reply);
#endif
    if (status < HDF_SUCCESS) {
        g_exitFlag = true;
        printf("%s:%d Dispatch CMD_WRITE_DATA_SYNC failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_WRITE_DATA_SYNC failed status = %{public}d",
            __func__, __LINE__, status);
        return;
    }

    printf("%s:%d %s-%zu!\n", __func__, __LINE__, buf, strlen(buf));
    HDF_LOGD("%{public}s:%{public}d %{public}s-%{public}zu!", __func__, __LINE__, buf, strlen(buf));
    TestModuleWriteLog(HOST_ACM_SYNC_WRITE, buf);
}

void UsbHostDdkTestCtrlClass(char *readSbuf)
{
    HdfSbufFlush(g_reply);

#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_CLASS_CTRL_SYNC, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_CLASS_CTRL_SYNC, g_data, g_reply);
#endif
    if (status < 0) {
        g_exitFlag = true;
        printf("%s:%d Dispatch CMD_CLASS_CTRL_SYNC failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_CLASS_CTRL_SYNC failed status = %{public}d",
            __func__, __LINE__, status);
    } else {
        if (readSbuf != NULL) {
            const char tmp[] = "CMD_CLASS_CTRL";
            errno_t err = memcpy_s(readSbuf, DATA_MAX_LEN, tmp, strlen(tmp));
            if (err != EOK) {
                HDF_LOGE("%{public}s:%{public}d err = %{public}d", __func__, __LINE__, err);
            }
        }
        printf("%s:%d usb serial control CMD_CLASS_CTRL command done\n", __func__, __LINE__);
        TestModuleWriteLog(HOST_ACM_CTRL_WRITE, "CMD_CLASS_CTRL");
    }
}

void UsbHostDdkTestStdGetDes(char *readSbuf)
{
    HdfSbufFlush(g_reply);
#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status =
        g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_STD_CTRL_GET_DESCRIPTOR_CMD, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_STD_CTRL_GET_DESCRIPTOR_CMD, g_data, g_reply);
#endif
    if (status < 0) {
        g_exitFlag = true;
        printf("%s:%d Dispatch UsbHostDdkTestStdGetDes failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch UsbHostDdkTestStdGetDes failed status = %{public}d",
            __func__, __LINE__, status);
    }

    printf("%s:%d usb serial control CMD_STD_CTRL_GET_DESCRIPTOR command done\n", __func__, __LINE__);
    TestModuleWriteLog(HOST_ACM_CTRL_WRITE, "CMD_STD_CTRL_GET_DESCRIPTOR");
    const char *tmp = HdfSbufReadString(g_reply);
    if (tmp && strlen(tmp) > 0) {
        if (readSbuf != NULL) {
            errno_t err = memcpy_s(readSbuf, DATA_MAX_LEN, tmp, strlen(tmp));
            if (err != EOK) {
                HDF_LOGE("%{public}s:%{public}d err = %{public}d", __func__, __LINE__, err);
            }
        }
        printf("%s:%d %s!\n", __func__, __LINE__, tmp);
        TestModuleWriteLog(HOST_ACM_CTRL_READ, tmp);
    } else {
        printf("%s:%d HdfSbufReadBuffer failed\n", __func__, __LINE__);
        HDF_LOGE("%{public}s:%{public}d HdfSbufReadBuffer failed", __func__, __LINE__);
    }
}

void UsbHostDdkTestStdGetDesAsync(char *readSbuf)
{
    HdfSbufFlush(g_reply);
#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status =
        g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_STD_CTRL_GET_DESCRIPTOR_ASYNC, g_data, g_reply);
#else
    int32_t status =
        g_acmService->dispatcher->Dispatch(g_acmService, CMD_STD_CTRL_GET_DESCRIPTOR_ASYNC, g_data, g_reply);
#endif
    if (status < 0) {
        g_exitFlag = true;
        printf("%s:%d Dispatch CMD_STD_CTRL_GET_DESCRIPTOR_ASYNC failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_STD_CTRL_GET_DESCRIPTOR_ASYNC failed status = %{public}d",
            __func__, __LINE__, status);
        return;
    }

    printf("%s:%d usb serial control CMD_STD_CTRL_GET_DESCRIPTOR_ASYNC command done\n", __func__, __LINE__);
    TestModuleWriteLog(HOST_ACM_CTRL_WRITE, "CMD_STD_CTRL_GET_DESCRIPTOR_ASYNC");
    const char *tmp = HdfSbufReadString(g_reply);
    if (tmp && strlen(tmp) > 0) {
        if (readSbuf != NULL) {
            errno_t err = memcpy_s(readSbuf, DATA_MAX_LEN, tmp, strlen(tmp));
            if (err != EOK) {
                HDF_LOGE("%{public}s:%{public}d err = %{public}d", __func__, __LINE__, err);
            }
        }
        printf("%s:%d %s!\n", __func__, __LINE__, tmp);
        TestModuleWriteLog(HOST_ACM_CTRL_READ, tmp);
    } else {
        printf("%s:%d HdfSbufReadBuffer failed\n", __func__, __LINE__);
        HDF_LOGE("%{public}s:%{public}d HdfSbufReadBuffer failed", __func__, __LINE__);
    }
}

void UsbHostDdkTestStdGetStatus(char *readSbuf)
{
    uint16_t data = 0;

    HdfSbufFlush(g_reply);
#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status =
        g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_STD_CTRL_GET_STATUS_CMD, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_STD_CTRL_GET_STATUS_CMD, g_data, g_reply);
#endif
    if (status < 0) {
        g_exitFlag = true;
        printf("%s:%d Dispatch CMD_STD_CTRL_GET_STATUS_CMD failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_STD_CTRL_GET_STATUS_CMD failed status = %{public}d",
            __func__, __LINE__, status);
    }

    status = HdfSbufReadUint16(g_reply, &data);
    if (!status) {
        printf("%s:%d HdfSbufReadBuffer status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d HdfSbufReadBuffer status = %{public}d", __func__, __LINE__, status);
    } else {
        if (readSbuf != NULL) {
            const char tmp[DATA_MAX_LEN] = "CMD_STD_CTRL_GET_STATUS";
            errno_t err = memcpy_s(readSbuf, DATA_MAX_LEN, tmp, strlen(tmp));
            if (err != EOK) {
                HDF_LOGE("%{public}s:%{public}d err = %{public}d", __func__, __LINE__, err);
            }
        }
        printf("%s:%d usb serial control CMD_STD_CTRL_GET_STATUS command done,data = %hu\n", __func__, __LINE__, data);
        TestModuleWriteLog(HOST_ACM_CTRL_WRITE, "CMD_STD_CTRL_GET_STATUS");
    }
}

void TestStdGetConf(void)
{
    uint8_t data;

    HdfSbufFlush(g_reply);

#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status =
        g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_STD_CTRL_GET_CONFIGURATION, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_STD_CTRL_GET_CONFIGURATION, g_data, g_reply);
#endif
    if (status < 0) {
        g_exitFlag = true;
        printf("%s:%d Dispatch CMD_STD_CTRL_GET_CONFIGURATION failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_STD_CTRL_GET_CONFIGURATION failed status = %{public}d",
            __func__, __LINE__, status);
    }

    printf("%s:%d usb serial control CMD_STD_CTRL_GET_CONFIGURATION command done\n", __func__, __LINE__);
    TestModuleWriteLog(HOST_ACM_CTRL_WRITE, "CMD_STD_CTRL_GET_CONFIGURATION");
    status = HdfSbufReadUint8(g_reply, &data);
    if (status < 0) {
        printf("%s:%d HdfSbufReadBuffer status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d HdfSbufReadBuffer status = %{public}d", __func__, __LINE__, status);
    }
}

void TestStdGetInterface(void)
{
    uint8_t data;

    HdfSbufFlush(g_reply);
#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status =
        g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_STD_CTRL_GET_INTERFACE, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_STD_CTRL_GET_INTERFACE, g_data, g_reply);
#endif
    if (status < 0) {
        g_exitFlag = true;
        printf("%s:%d Dispatch CMD_STD_CTRL_GET_INTERFACE failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_STD_CTRL_GET_INTERFACE failed status = %{public}d",
            __func__, __LINE__, status);
    }

    printf("%s:%d usb serial control CMD_STD_CTRL_GET_INTERFACE command done\n", __func__, __LINE__);
    TestModuleWriteLog(HOST_ACM_CTRL_WRITE, "CMD_STD_CTRL_GET_INTERFACE");
    status = HdfSbufReadUint8(g_reply, &data);
    if (status < 0) {
        printf("%s:%d HdfSbufReadBuffer status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d HdfSbufReadBuffer status = %{public}d", __func__, __LINE__, status);
    }
}

void UsbHostDdkTestSetBaudrate(uint32_t value)
{
    HdfSbufFlush(g_data);

    if (!HdfSbufWriteUint32(g_data, value)) {
        printf("%s:%d HdfSbufWriteString error\n", __func__, __LINE__);
        HDF_LOGE("%{public}s:%{public}d HdfSbufWriteString error", __func__, __LINE__);
        return;
    }

#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_SET_BAUDRATE, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_SET_BAUDRATE, g_data, g_reply);
#endif
    if (status != HDF_SUCCESS) {
        g_exitFlag = true;
        printf("%s:%d Dispatch CMD_SET_BAUDRATE failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_SET_BAUDRATE failed status = %{public}d",
            __func__, __LINE__, status);
        return;
    }

    printf("%s:%d CMD_SET_BAUDRATE success\n", __func__, __LINE__);
    HDF_LOGI("%{public}s:%{public}d CMD_SET_BAUDRATE success", __func__, __LINE__);
    TestModuleWriteLog(HOST_ACM_CTRL_WRITE, "CMD_SET_BAUDRATE");
}

void UsbHostDdkTestGetBaudrate(char *readSbuf)
{
    uint32_t value = 0;

    HdfSbufFlush(g_reply);
#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_GET_BAUDRATE, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_GET_BAUDRATE, g_data, g_reply);
#endif
    if (status < 0) {
        g_exitFlag = true;
        printf("%s:%d Dispatch CMD_GET_BAUDRATE failed status = %d\n", __func__, __LINE__, status);
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_GET_BAUDRATE failed status = %{public}d",
            __func__, __LINE__, status);
        return;
    }

    if (HdfSbufReadUint32(g_reply, &value) == true) {
        if (readSbuf != NULL) {
            const char tmp[] = "CMD_GET_BAUDRATE";
            errno_t err = memcpy_s(readSbuf, DATA_MAX_LEN, tmp, strlen(tmp));
            if (err != EOK) {
                HDF_LOGE("%{public}s:%{public}d err=%{public}d", __func__, __LINE__, err);
            }
        }
        printf("%s:%d baudrate=%u usb serial control CMD_GET_BAUDRATE command done\n", __func__, __LINE__, value);
        TestModuleWriteLog(HOST_ACM_CTRL_WRITE, "CMD_GET_BAUDRATE");
    } else {
        printf("%s:%d HdfSbufReadUint32 failed!\n", __func__, __LINE__);
        HDF_LOGD("%{public}s:%{public}d HdfSbufReadUint32 failed!", __func__, __LINE__);
    }
}

void UsbHostDdkTestAddInterface(uint32_t value)
{
    HdfSbufFlush(g_data);

    if (!HdfSbufWriteUint32(g_data, value)) {
        HDF_LOGE("%{public}s:%{public}d HdfSbufWriteString error", __func__, __LINE__);
        return;
    }

#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_ADD_INTERFACE, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_ADD_INTERFACE, g_data, g_reply);
#endif
    if (status != HDF_SUCCESS) {
        g_exitFlag = true;
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_ADD_INTERFACE failed status = %d", __func__, __LINE__, status);
        return;
    }

    printf("%s:%d CMD_ADD_INTERFACE success!\n", __func__, __LINE__);
    HDF_LOGD("%{public}s:%{public}d CMD_ADD_INTERFACE success!", __func__, __LINE__);
}

void UsbHostDdkTestRemoveInterface(uint32_t value)
{
    HdfSbufFlush(g_data);

    if (!HdfSbufWriteUint32(g_data, value)) {
        HDF_LOGE("%{public}s:%{public}d HdfSbufWriteString error", __func__, __LINE__);
        return;
    }

#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_REMOVE_INTERFACE, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_REMOVE_INTERFACE, g_data, g_reply);
#endif
    if (status != HDF_SUCCESS) {
        g_exitFlag = true;
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_REMOVE_INTERFACE failed status = %d", __func__, __LINE__, status);
        return;
    }

    printf("%s:%d CMD_REMOVE_INTERFACE success!\n", __func__, __LINE__);
    HDF_LOGD("%{public}s:%{public}d CMD_REMOVE_INTERFACE success!", __func__, __LINE__);
}

int32_t UsbHostDdkTestOpen(int32_t cmdType)
{
    if (g_exitFlag) {
        HDF_LOGD("%{public}s:%{public}d g_exitFlag is true!", __func__, __LINE__);
        return HDF_FAILURE;
    }

    HdfSbufFlush(g_data);
    if (!HdfSbufWriteInt32(g_data, cmdType)) {
        HDF_LOGE("%{public}s:%{public}d HdfSbufWriteString error", __func__, __LINE__);
        return HDF_FAILURE;
    }

#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_OPEN_PARM, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_OPEN_PARM, g_data, g_reply);
#endif
    if (status != HDF_SUCCESS) {
        g_exitFlag = true;
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_OPEN_PARM status=%{public}d err", __func__, __LINE__, status);
    }

    return status;
}

int32_t UsbHostDdkTestClose(int32_t cmdType)
{
    if (g_exitFlag) {
        HDF_LOGD("%{public}s:%{public}d g_exitFlag is true!", __func__, __LINE__);
        return HDF_FAILURE;
    }

    HdfSbufFlush(g_data);
    if (!HdfSbufWriteInt32(g_data, cmdType)) {
        HDF_LOGE("%{public}s:%{public}d HdfSbufWriteString error", __func__, __LINE__);
        return HDF_FAILURE;
    }

#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t status = g_acmService->dispatcher->Dispatch(&g_acmService->object, CMD_CLOSE_PARM, g_data, g_reply);
#else
    int32_t status = g_acmService->dispatcher->Dispatch(g_acmService, CMD_CLOSE_PARM, g_data, g_reply);
#endif
    if (status != HDF_SUCCESS) {
        g_exitFlag = true;
        HDF_LOGE("%{public}s:%{public}d Dispatch CMD_CLOSE_PARM status=%{public}d err", __func__, __LINE__, status);
    }

    return status;
}

void TestExit(void)
{
#ifdef __LITEOS_USB_HOST_DDK_TEST__
    HdfIoServiceRecycle(g_acmService);
#else
    HdfRemoteServiceRecycle(g_acmService);
#endif
    HdfSbufRecycle(g_data);
    HdfSbufRecycle(g_reply);
}

bool TestGetExitFlag(void)
{
    return g_exitFlag;
}
