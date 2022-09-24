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
        close(g_fd);
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
        printf("path error\n");
        return ret;
    }

    printf("open: %s\n", path);
    g_fd = open(path, O_RDWR);

    if (g_fd < 0) {
        printf("open device failed! errno=%2d(%s)\n", errno, strerror(errno));
    }

    return g_fd;
}

static int32_t ClaimInterface(unsigned int iface)
{
    if (g_fd < 0 || iface == 0) {
        printf("parameter error\n");
        return -1;
    }

    int32_t ret = ioctl(g_fd, USBDEVFS_CLAIMINTERFACE, &iface);
    if (ret < 0) {
        printf("claim failed: iface=%u, errno=%2d(%s)\n", iface, errno, strerror(errno));
        return HDF_FAILURE;
    }
    printf("claim success: iface=%u\n", iface);
    return HDF_SUCCESS;
}

static void FillUrb(struct UsbAdapterUrb *urb, int32_t len)
{
    if (urb == NULL) {
        urb = OsalMemCalloc(sizeof(struct UsbAdapterUrb));
        urb->userContext = (void *)(urb);
        urb->type = USB_ADAPTER_URB_TYPE_BULK;
        urb->streamId = 0;
        urb->endPoint = g_endNum;
    }
    if ((g_endNum >> ENDPOINT_IN_OFFSET) == 0) {
        int32_t ret = memset_s(urb->buffer, len, 'c', len);
        if (ret != EOK) {
            printf("memset_s failed: ret = %d\n", ret);
        }
    }
}

static void SignalHandler(int32_t signo)
{
    static uint32_t sigCnt = 0;
    struct itimerval new_value, old_value;
    double speed = 0;
    switch (signo) {
        case SIGALRM:
            sigCnt++;
            if (sigCnt * TEST_PRINT_TIME >= TEST_TIME) {
                g_speedFlag = 1;
                break;
            }
            speed = (g_byteTotal * 1.0) / (sigCnt * TEST_PRINT_TIME * 1024 * 1024);
            printf("\nSpeed:%f MB/s\n", speed);
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
            printf("SubmitBulkRequest: ret:%d errno=%d\n", ret, errno);
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
        printf("signal SIGUSR1 failed");
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
                printf("%c", recvBuf[i]);
            }
            fflush(stdout);
        } else if (g_recv_count % 10000 == 0) {
            printf("#");
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
        HDF_LOGE("%s: g_fd or endPoint is invalied", __func__);
        return -1;
    }

    ret = FillUrbData(endPoint);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Fill urb data failed", __func__);
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
    printf(">> usage:\n");
    printf(">>      %s [<busNum> <devAddr>]  <g_ifaceNum> <endpoint> [<printdata>]\n", name);
    printf("\n");
}

int32_t main(int32_t argc, char *argv[])
{
    int32_t ret;
    if (argc == 6) {
        g_busNum = (unsigned int)atoi(argv[1]);
        g_devAddr = (unsigned int)atoi(argv[2]); // 2 means get second char of argv
        g_ifaceNum = (unsigned int)atoi(argv[3]);  // 3 means get third char of argv
        g_endNum = (unsigned char)atoi(argv[4]);   // 4 means get fourth char of argv
        if ((g_endNum >> 7) != 0) {                // the offset value is 7
            g_printData = (strncmp(argv[5], "printdata", 1)) ? false : true;
        }
    } else if (argc == 5) {
        g_busNum = (unsigned int)atoi(argv[1]);
        g_devAddr = (unsigned int)atoi(argv[2]); // 2 means get second char of argv
        g_ifaceNum = (unsigned int)atoi(argv[3]);  // 3 means get third char of argv
        g_endNum = (unsigned char)atoi(argv[4]);   // 4 means get fourth char of argv
    } else if (argc == 3) {
        g_ifaceNum = (unsigned int)atoi(argv[1]);
        g_endNum = (unsigned char)atoi(argv[2]); // 2 means get second char of argv
    } else {
        printf("Error: parameter error!\n\n");
        ShowHelp(argv[0]);
        return -1;
    }
    OsalSemInit(&sem, 0);

    g_fd = OpenDevice();
    if (g_fd < 0) {
        ret = -1;
        goto ERR;
    }

    ret = ClaimInterface(g_ifaceNum);
    if (ret != HDF_SUCCESS) {
        goto ERR;
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
        printf("OsalThreadCreate fail, ret=%d\n", ret);
        goto ERR;
    }

    ret = OsalThreadStart(&urbReapProcess, &threadCfg);
    if (ret != HDF_SUCCESS) {
        printf("OsalThreadStart fail, ret=%d\n", ret);
    }

    threadCfg.name = "urb send process";
    threadCfg.priority = OSAL_THREAD_PRI_DEFAULT;
    threadCfg.stackSize = URB_COMPLETE_PROCESS_STACK_SIZE;

    ret = OsalThreadCreate(&urbSendProcess, (OsalThreadEntry)SendProcess, NULL);
    if (ret != HDF_SUCCESS) {
        printf("OsalThreadCreate fail, ret=%d\n", ret);
        goto ERR;
    }

    ret = OsalThreadStart(&urbSendProcess, &threadCfg);
    if (ret != HDF_SUCCESS) {
        printf("OsalThreadStart fail, ret=%d\n", ret);
    }

    ret = BeginProcess(g_endNum);
    if (ret != HDF_SUCCESS) {
        goto ERR;
    }

ERR:
    if (ret != HDF_SUCCESS) {
        printf("please check whether usb drv so is existing or not,like acm, ecm, if not, remove it and test again!\n");
    }
    CloseDevice();
    return ret;
}
