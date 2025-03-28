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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
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

#include "hdf_log.h"
#include "osal_mem.h"
#include "osal_time.h"
#include "securec.h"
#include "usbhost_nosdk_speed.h"

#define USB_DEV_FS_PATH                 "/dev/bus/usb"
#define URB_COMPLETE_PROCESS_STACK_SIZE 8196

#define TEST_LENGTH          512
#define TEST_CYCLE           30
#define TEST_TIME            0xffffffff
#define TEST_PRINT_TIME      2
#define TEST_PRINT_TIME_UINT 1000
#define ENDPOINT_IN_OFFSET   7
#define PATH_MAX_LENGTH      24
#define STRTOL_BASE          10

static pid_t g_tid;
static int32_t g_exitOk = false;
static int32_t g_speedFlag = 0;
static unsigned int g_busNum = 1;
static unsigned int g_devAddr = 2;
static int32_t g_fd;
static struct OsalSem sem;
static uint64_t g_send_count = 0;
static uint64_t g_recv_count = 0;
static uint64_t g_byteTotal = 0;
static struct UsbAdapterUrbs urb[TEST_CYCLE];
static struct UsbAdapterUrb *g_sendUrb = NULL;
static bool g_printData = false;
static unsigned int g_ifaceNum;
static unsigned char g_endNum;

static void CloseDevice(void)
{
    if (g_fd > 0) {
        fdsan_close_with_tag(g_fd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        g_fd = 0;
    }
    return;
}

static int32_t OpenDevice(void)
{
    char path[PATH_MAX_LENGTH];
    int32_t ret;

    ret = sprintf_s(path, sizeof(char) * PATH_MAX_LENGTH, USB_DEV_FS_PATH "/%03u/%03u", g_busNum, g_devAddr);
    if (ret < 0) {
        HDF_LOGE("%{public}s: sprintf_s path failed", __func__);
        return ret;
    }

    HDF_LOGI("%{public}s: open file action", __func__);
    g_fd = open(path, O_RDWR);

    if (g_fd < 0) {
        HDF_LOGE("%{public}s: open device failed errno = %{public}d %{public}s", __func__, errno, strerror(errno));
    }
    fdsan_exchange_owner_tag(g_fd, 0, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));

    return g_fd;
}

static int32_t ClaimInterface(unsigned int iface)
{
    if (g_fd < 0 || iface == 0) {
        HDF_LOGE("%{public}s: parameter error", __func__);
        return -1;
    }

    int32_t ret = ioctl(g_fd, USBDEVFS_CLAIMINTERFACE, &iface);
    if (ret < 0) {
        HDF_LOGE("%{public}s: sprintf_s path failed claim failed: iface = %{public}u errno = %{public}d %{public}s",
            __func__, iface, errno, strerror(errno));
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: claim success: iface = %{public}u", __func__, iface);
    return HDF_SUCCESS;
}

static void FillUrb(struct UsbAdapterUrb *urb, int32_t len)
{
    if (urb == NULL) {
        HDF_LOGE("%{public}s: urb is null", __func__);
        return;
    }
    urb->userContext = (void *)(urb);
    urb->type = USB_ADAPTER_URB_TYPE_BULK;
    urb->streamId = 0;
    urb->endPoint = g_endNum;
    if ((g_endNum >> ENDPOINT_IN_OFFSET) == 0) {
        int32_t ret = memset_s(urb->buffer, len, 'c', len);
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memset_s failed: ret = %{public}d", __func__, ret);
        }
    }
}

static void SignalHandler(int32_t signo)
{
    static uint32_t sigCnt = 0;
    struct itimerval new_value, old_value;
    switch (signo) {
        case SIGALRM:
            sigCnt++;
            if (sigCnt * TEST_PRINT_TIME >= TEST_TIME) {
                g_speedFlag = 1;
                break;
            }
            new_value.it_value.tv_sec = TEST_PRINT_TIME;
            new_value.it_value.tv_usec = 0;
            new_value.it_interval.tv_sec = TEST_PRINT_TIME;
            new_value.it_interval.tv_usec = 0;
            setitimer(ITIMER_REAL, &new_value, &old_value);
            break;
        case SIGINT:
            g_speedFlag = 1;
            break;
        default:
            break;
    }
}

static int32_t SendProcess(void *argurb)
{
    (void)argurb;
    int32_t i;
    while (!g_speedFlag) {
        OsalSemWait(&sem, HDF_WAIT_FOREVER);
        for (i = 0; i < TEST_CYCLE; i++) {
            if (urb[i].inUse == 0) {
                urb[i].inUse = 1;
                urb[i].urb->userContext = (void *)(&urb[i]);
                break;
            }
        }

        if (i == TEST_CYCLE) {
            i = TEST_CYCLE - 1;
        }
        g_sendUrb = urb[i].urb;
        FillUrb(g_sendUrb, TEST_LENGTH);
        int32_t ret = ioctl(g_fd, USBDEVFS_SUBMITURB, g_sendUrb);
        if (ret < 0) {
            HDF_LOGE("%{public}s: ret:%{public}d errno = %{public}d", __func__, ret, errno);
            urb[i].inUse = 0;
            continue;
        }
        g_send_count++;
    }
    return 0;
}

static int32_t ReapProcess(void * const argurb)
{
    (void)argurb;
    struct UsbAdapterUrb *urbrecv = NULL;
    struct itimerval new_value, old_value;
    if (signal(SIGUSR1, SignalHandler) == SIG_ERR) {
        HDF_LOGE("%{public}s: signal SIGUSR1 failed", __func__);
        return HDF_ERR_IO;
    }
    g_tid = (pid_t)syscall(SYS_gettid);

    while (!g_speedFlag) {
        int32_t r = ioctl(g_fd, USBDEVFS_REAPURB, &urbrecv);
        if (r < 0) {
            continue;
        }
        if (urbrecv == NULL) {
            continue;
        }
        if (urbrecv->status == 0) {
            if (g_byteTotal == 0) {
                new_value.it_value.tv_sec = TEST_PRINT_TIME;
                new_value.it_value.tv_usec = 0;
                new_value.it_interval.tv_sec = TEST_PRINT_TIME;
                new_value.it_interval.tv_usec = 0;
                setitimer(ITIMER_REAL, &new_value, &old_value);
            }
            g_recv_count++;
            g_byteTotal += urbrecv->actualLength;
        }
        unsigned char *recvBuf = (unsigned char *)urbrecv->buffer;

        if (g_printData) {
            for (int32_t i = 0; i < urbrecv->actualLength; i++) {
                HDF_LOGI("%{public}s: recvbuf %{public}c", __func__, recvBuf[i]);
            }
            fflush(stdout);
        } else if (g_recv_count % 10000 == 0) {
            HDF_LOGI("%{public}s: #", __func__);
            fflush(stdout);
        }

        struct UsbAdapterUrbs *urbs = urbrecv->userContext;
        urbs->inUse = 0;
        OsalSemPost(&sem);
    }
    g_exitOk = true;
    return 0;
}

static int32_t FillUrbData(unsigned char endPoint)
{
    int32_t i;
    char *data = NULL;
    for (i = 0; i < TEST_CYCLE; i++) {
        urb[i].urb = calloc(1, sizeof(struct UsbAdapterUrb));
        if (urb[i].urb == NULL) {
            return -1;
        }
        urb[i].inUse = 0;
        urb[i].urb->userContext = (void *)(&urb[i]);
        urb[i].urb->type = USB_ADAPTER_URB_TYPE_BULK;
        urb[i].urb->streamId = 0;
        urb[i].urb->endPoint = endPoint;

        data = OsalMemCalloc(TEST_LENGTH); // AllocMemTest(TEST_LENGTH)
        if (data == NULL) {
            return -1;
        }
        (void)memset_s(data, TEST_LENGTH, 'c', TEST_LENGTH);
        data[TEST_LENGTH - 1] = '\0';
        urb[i].urb->buffer = (void *)data;
        urb[i].urb->bufferLength = TEST_LENGTH;
    }
    return HDF_SUCCESS;
}

static int32_t BeginProcess(unsigned char endPoint)
{
    int32_t ret;
    struct timeval time;
    int32_t transNum = 0;
    int32_t i;

    if ((g_fd < 0) || (endPoint == 0)) {
        HDF_LOGE("%{public}s: g_fd or endPoint is invalied", __func__);
        return -1;
    }

    ret = FillUrbData(endPoint);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Fill urb data failed", __func__);
        return ret;
    }
    gettimeofday(&time, NULL);
    (void)signal(SIGINT, SignalHandler);
    (void)signal(SIGALRM, SignalHandler);

    for (i = 0; i < TEST_CYCLE; i++) {
        urb[i].inUse = 1;
        urb[i].urbNum = transNum;
        urb[i].urb->userContext = (void *)(&urb[i]);
        g_sendUrb = urb[i].urb;
        ret = ioctl(g_fd, USBDEVFS_SUBMITURB, g_sendUrb);
        if (ret < 0) {
            urb[i].inUse = 0;
            continue;
        }
        g_send_count++;
    }

    while (!g_speedFlag) {
        OsalMSleep(10);
    }

    kill(g_tid, SIGUSR1);
    while (!g_exitOk) {
        OsalMSleep(10);
    }
    for (i = 0; i < TEST_CYCLE; i++) {
        munmap(urb[i].urb->buffer, TEST_LENGTH);
        free(urb[i].urb);
    }
    return HDF_SUCCESS;
}

static void ShowHelp(char *name)
{
    HDF_LOGI("%{public}s: usage:", __func__);
    HDF_LOGI("%{public}s: name is %{public}s [<busNum> <devAddr>]  <g_ifaceNum> <endpoint> [<printdata>]",
        __func__, name);
}

static void FillParamData(int32_t argc, char *argv[])
{
    if (argc == TEST_SIX_TYPE) {
        g_busNum = (unsigned int)strtoul(argv[TEST_ONE_TYPE], NULL, STRTOL_BASE);
        g_devAddr = (unsigned int)strtoul(argv[TEST_TWO_TYPE], NULL, STRTOL_BASE); // 2 means get second char of argv
        g_ifaceNum = (unsigned int)strtoul(argv[TEST_THREE_TYPE], NULL, STRTOL_BASE);  // 3 means get third char of argv
        g_endNum = (unsigned char)strtoul(argv[TEST_FOUR_TYPE], NULL, STRTOL_BASE);   // 4 means get fourth char of argv
        if ((g_endNum >> ENDPOINT_IN_OFFSET) != 0) {                // the offset value is 7
            g_printData = (strncmp(argv[TEST_FIVE_TYPE], "printdata", TEST_ONE_TYPE)) ? false : true;
        }
    } else if (argc == TEST_FIVE_TYPE) {
        g_busNum = (unsigned int)strtoul(argv[TEST_ONE_TYPE], NULL, STRTOL_BASE);
        g_devAddr = (unsigned int)strtoul(argv[TEST_TWO_TYPE], NULL, STRTOL_BASE); // 2 means get second char of argv
        g_ifaceNum = (unsigned int)strtoul(argv[TEST_THREE_TYPE], NULL, STRTOL_BASE);  // 3 means get third char of argv
        g_endNum = (unsigned char)strtoul(argv[TEST_FOUR_TYPE], NULL, STRTOL_BASE);   // 4 means get fourth char of argv
    } else if (argc == TEST_THREE_TYPE) {
        g_ifaceNum = (unsigned int)strtoul(argv[TEST_ONE_TYPE], NULL, STRTOL_BASE);
        g_endNum = (unsigned char)strtoul(argv[TEST_TWO_TYPE], NULL, STRTOL_BASE); // 2 means get second char of argv
    } else {
        HDF_LOGE("%{public}s: parameter error!", __func__);
        ShowHelp(argv[TEST_ZERO_TYPE]);
        return HDF_FAILURE;
    }
}

static void PrintErrorLog(int32_t ret)
{
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: please check whether usb drv so is existing or not,like acm, ecm, if not, \
            remove it and test again! ret=%{public}d", __func__, ret);
    }
}

int32_t main(int32_t argc, char *argv[])
{
    int32_t ret;
    FillParamData(argc, argv[]);
    OsalSemInit(&sem, 0);
    g_fd = OpenDevice();
    if (g_fd < 0) {
        ret = -1;
        PrintErrorLog(ret);
    }

    ret = ClaimInterface(g_ifaceNum);
    if (ret != HDF_SUCCESS) {
        PrintErrorLog(ret);
    }

    struct OsalThread urbReapProcess;
    struct OsalThread urbSendProcess;
    struct OsalThreadParam threadCfg;

    (void)memset_s(&threadCfg, sizeof(threadCfg), 0, sizeof(threadCfg));
    threadCfg.name = "urb reap process";
    threadCfg.priority = OSAL_THREAD_PRI_DEFAULT;
    threadCfg.stackSize = URB_COMPLETE_PROCESS_STACK_SIZE;

    ret = OsalThreadCreate(&urbReapProcess, (OsalThreadEntry)ReapProcess, NULL);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: OsalThreadCreate failed, ret=%{public}d", __func__, ret);
        PrintErrorLog(ret);
    }

    ret = OsalThreadStart(&urbReapProcess, &threadCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: OsalThreadStart failed, ret=%{public}d", __func__, ret);
    }

    threadCfg.name = "urb send process";
    threadCfg.priority = OSAL_THREAD_PRI_DEFAULT;
    threadCfg.stackSize = URB_COMPLETE_PROCESS_STACK_SIZE;

    ret = OsalThreadCreate(&urbSendProcess, (OsalThreadEntry)SendProcess, NULL);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: OsalThreadCreate failed, ret=%{public}d", __func__, ret);
        PrintErrorLog(ret);
    }

    ret = OsalThreadStart(&urbSendProcess, &threadCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: OsalThreadStart failed, ret=%{public}d", __func__, ret);
    }

    ret = BeginProcess(g_endNum);
    if (ret != HDF_SUCCESS) {
        PrintErrorLog(ret);
    }
    CloseDevice();
    return ret;
}
