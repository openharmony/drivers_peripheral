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

#include "hdf_io_service_if.h"
#include <stdio.h>
#include <unistd.h>

#include <sys/time.h>

#include "hdf_log.h"
#include "osal_mem.h"
#include "osal_mutex.h"
#include "securec.h"
#include "signal.h"

#define TEST_WRITE         true
#define TEST_READ          false
#define SERVER_NAME_SDKAPI "usb_sdkapispeed_service"
#define SERVER_NAME_RAWAPI "usb_rawapispeed_service"
#define SERVER_NAME_NOSDK  "usb_nosdkspeed_service"
#define STRTOL_BASE  10

enum UsbSerialCmd {
    USB_SERIAL_OPEN = 0,
    USB_SERIAL_CLOSE,
    USB_SERIAL_SPEED,
};
struct UsbSpeedTest {
    int32_t busNum;
    int32_t devAddr;
    int32_t ifaceNum;
    int32_t writeOrRead;
    bool printData;
    int32_t paramNum;
};
enum speedServer {
    SDKAPI_SERVER = 0,
    RAWAPI_SERVER,
    NOSDK_SERVER,
};

static struct HdfIoService *g_service = NULL;
static struct HdfSBuf *g_data = NULL;
static struct HdfSBuf *g_reply = NULL;
static struct OsalMutex g_lock;
static enum speedServer g_spdServer = SDKAPI_SERVER;

static sigset_t g_mask;
pid_t g_stopHandlerTid;

static void SpeedTest(struct UsbSpeedTest test)
{
    OsalMutexLock(&g_lock);
    HdfSbufFlush(g_data);
    bool bufok = HdfSbufWriteBuffer(g_data, (const void *)&test, sizeof(test));
    if (!bufok) {
        printf("HdfSbufWriteBuffer err");
        goto RET;
    }
    int32_t status = g_service->dispatcher->Dispatch(&g_service->object, USB_SERIAL_SPEED, g_data, g_reply);
    if (status < 0) {
        printf("%s: Dispatch USB_SERIAL_SPEED failed status = %d\n", __func__, status);
    }
RET:
    OsalMutexUnlock(&g_lock);
}

static void SpeedInit(void)
{
    int32_t status;

    switch (g_spdServer) {
        case SDKAPI_SERVER:
            g_service = HdfIoServiceBind(SERVER_NAME_SDKAPI);
            break;
        case RAWAPI_SERVER:
            g_service = HdfIoServiceBind(SERVER_NAME_RAWAPI);
            break;
        case NOSDK_SERVER:
            g_service = HdfIoServiceBind(SERVER_NAME_NOSDK);
            break;
        default:
            break;
    }
    if (g_service == NULL || g_service->dispatcher == NULL || g_service->dispatcher->Dispatch == NULL) {
        printf("%s: GetService g_spdServer=%d err \n", __func__, g_spdServer);
        return;
    }

    // usb info max size is 2000
    uint32_t usbInfoMaxSize = 2000;
    g_data = HdfSbufObtain(usbInfoMaxSize);
    g_reply = HdfSbufObtain(usbInfoMaxSize);
    if (g_data == NULL || g_reply == NULL) {
        printf("%s: HdfSbufTypedObtain err", __func__);
        return;
    }

    status = g_service->dispatcher->Dispatch(&g_service->object, USB_SERIAL_OPEN, g_data, g_reply);
    if (status) {
        printf("%s: Dispatch USB_SERIAL_OPEN err status = %d\n", __func__, status);
        return;
    }

    if (OsalMutexInit(&g_lock) != HDF_SUCCESS) {
        printf("%s: init lock fail!", __func__);
        return;
    }
}

static void SpeedExit(void)
{
    if (g_service == NULL) {
        printf("%s: g_service is null", __func__);
        return;
    }
    int32_t status = g_service->dispatcher->Dispatch(&g_service->object, USB_SERIAL_CLOSE, g_data, g_reply);
    if (status) {
        printf("%s: Dispatch USB_SERIAL_CLOSE err status = %d\n", __func__, status);
    }

    HdfIoServiceRecycle(g_service);
    g_service = NULL;
    HdfSbufRecycle(g_data);
    HdfSbufRecycle(g_reply);
}

static void ShowHelp(const char *name)
{
    printf(">> usage:\n");
    printf(">> %s <-SDK>/<-RAW>/<-NOSDK> [<busNum> <devAddr>]  <ifaceNum> <w>/<r>/<endpoint> [printdata]> \n", name);
    printf("\n");
}

static void *StopHandler(void)
{
    int32_t signo;
    g_stopHandlerTid = getpid();

    while (true) {
        int32_t err = sigwait(&g_mask, &signo);
        if (err != 0) {
            printf("Sigwait failed: %d\n", err);
        }

        if ((signo == SIGINT) || (signo == SIGQUIT)) {
            printf("normal exit\n");
            SpeedExit();
            return 0;
        } else {
            printf("Unexpected signal %d\n", signo);
        }
    }
}

static enum speedServer checkServer(const char *input)
{
    char middle[10] = {0};
    if (input == NULL) {
        HDF_LOGE("%{public}s:%{public}d input is NULL", __func__, __LINE__);
        return SDKAPI_SERVER;
    }

    int32_t ret = strncpy_s(middle, sizeof(middle), input, (uint32_t)strlen(input));
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d strncpy_s failed", __func__, __LINE__);
        return SDKAPI_SERVER;
    }

    if (strcmp(middle, "-SDK") == 0) {
        return SDKAPI_SERVER;
    }
    if (strcmp(middle, "-RAW") == 0) {
        return RAWAPI_SERVER;
    }
    if (strcmp(middle, "-NOSDK") == 0) {
        return NOSDK_SERVER;
    }
    return SDKAPI_SERVER;
}

static int32_t GetWriteOrReadFlag(const char *buffer)
{
    int32_t writeOrRead;

    if (!strncmp(buffer, "r", 1)) {
        writeOrRead = TEST_READ;
    } else if (!strncmp(buffer, "w", 1)) {
        writeOrRead = TEST_WRITE;
    } else {
        writeOrRead = (int32_t)strtol(buffer, NULL, STRTOL_BASE);
    }

    return writeOrRead;
}

static int32_t CheckParam(int32_t argc, const char *argv[], struct UsbSpeedTest *speedTest)
{
    int32_t ret = HDF_SUCCESS;
    bool printData = false;

    if ((argv == NULL) || (speedTest == NULL) || (argc <= 0)) {
        return HDF_ERR_INVALID_PARAM;
    }
    switch (argc) {
        case 7:                                  // 7 is number of arguments supplied to the main function
        case 6:                                  // 6 is number of arguments supplied to the main function
            g_spdServer = checkServer(argv[1]);  // 1 is argv second element
            speedTest->busNum = (int32_t)strtol(argv[2], NULL, STRTOL_BASE);   // 2 is argv third element
            speedTest->devAddr = (int32_t)strtol(argv[3], NULL, STRTOL_BASE);  // 3 is argv fourth element
            speedTest->ifaceNum = (int32_t)strtol(argv[4], NULL, STRTOL_BASE); // 4 is argv fifth element
            speedTest->writeOrRead = GetWriteOrReadFlag(argv[5]); // 5 is argv sixth element
            // 7 is number of arguments supplied to the main function
            if ((argc == 7) && (speedTest->writeOrRead == TEST_READ)) {
                printData = (strncmp(argv[6], "printdata", 1)) ? false : true; // 6 is argv seventh element
            }
            break;
        case 4:                                 // 4 number of arguments supplied to the main function
            g_spdServer = checkServer(argv[1]); // 1 is argv second element
            speedTest->busNum = 1;
            speedTest->devAddr = 2;                               // 2 is device address
            speedTest->ifaceNum = (int32_t)strtol(argv[2], NULL, STRTOL_BASE);         // 2 is argv third element
            speedTest->writeOrRead = GetWriteOrReadFlag(argv[3]); // 3 is argv fourth element
            break;
        default:
            printf("Error: parameter error!\n");
            ShowHelp(argv[0]); // 0 is argv first element
            ret = HDF_FAILURE;
            break;
    }
    if (ret == HDF_SUCCESS) {
        speedTest->printData = printData;
        speedTest->paramNum = argc - 1;
    }

    return ret;
}

int32_t main(int32_t argc, char *argv[])
{
    int32_t ret;
    struct UsbSpeedTest test;

    ret = CheckParam(argc, argv, &test);
    if (ret != HDF_SUCCESS) {
        goto END;
    }

    pthread_t threads;
    sigemptyset(&g_mask);
    sigaddset(&g_mask, SIGINT);
    sigaddset(&g_mask, SIGQUIT);
    if (pthread_sigmask(SIG_BLOCK, &g_mask, NULL) != 0) {
        printf("SIG_BLOCK error\n");
        ret = HDF_FAILURE;
        goto END;
    }
    if (pthread_create(&threads, NULL, StopHandler, NULL) != 0) {
        printf("Could not create core thread\n");
        ret = HDF_FAILURE;
        goto END;
    }

    SpeedInit();
    SpeedTest(test);
    kill(g_stopHandlerTid, SIGINT);
    pthread_join(threads, NULL);
END:
    return ret;
}
