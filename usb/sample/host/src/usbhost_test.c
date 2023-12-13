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

#include "osal_thread.h"
#include "signal.h"
#include <string.h>
#include "usbhost_ddk_test.h"

#define HDF_LOG_TAG USB_HOST_DDK_TEST
#define STR_LEN     256
#define STRTOL_BASE  10

#define PARAM_CMD_LENGTH  3
#define PARAM_SET_CMD_LEN 3
#define PARAM_GET_CMD_LEN 2
#define ARGV_CMD_API_TYPE 1
#define ARGV_CMD_TYPE     (PARAM_GET_CMD_LEN - ARGV_CMD_API_TYPE)
#define ARGV_CMD_PARAM    (PARAM_SET_CMD_LEN - ARGV_CMD_API_TYPE)
#define READ_SLEEP_TIME   500
int32_t run;
static const std::map<char, int32_t> CMD_TYPE_VALUE_GET_MAP = 
{
    {'R', HOST_ACM_SYNC_READ},
    {'r', HOST_ACM_ASYNC_READ},
    {'c', HOST_ACM_CTRL_CLASS_SYNC},
    {'s', HOST_ACM_CTRL_GET_STATUS},
    {'C', HOST_ACM_CTRL_SYNC_DESCRIPTOR},
    {'d', HOST_ACM_CTRL_ASYNC_DESCRIPTOR},
    {'g', HOST_ACM_CTRL_GET_CONFIGURATION},
    {'i', HOST_ACM_CTRL_GET_INTERFACE},
    {'S', HOST_ACM_SPEED_TEST},
    {'b', HOST_ACM_GET_BAUDRATE}
}

static const std::map<char, int32_t> CMD_TYPE_VALUE_SET_MAP = 
{
    {'W', HOST_ACM_SYNC_WRITE},
    {'w', HOST_ACM_ASYNC_WRITE},
    {'B', HOST_ACM_SET_BAUDRATE},
    {'I', HOST_ACM_ADD_INTERFACE},
    {'D', HOST_ACM_REMOVE_INTERFACE}
}

#ifdef __LITEOS_USB_HOST_DDK_TEST__
static struct OsalThread g_Getchar;
#endif

static void TestHelp(void)
{
    printf("usage: usbhost_ddk_test [options]\n");
    printf("\n");
    printf("options include:\n");
    printf("  -h, --help                    : help info\n");
    printf("  -A, --DDK                     : test host ddk api function for acm\n");
    printf("  -a, --RAW                     : test host raw api function for acm\n");
    printf("  -E, --ECM                     : test host ddk api function for ecm\n");
    printf("  -R, --syncRead                : test sync read for acm\n");
    printf("  -W, --syncWrite               : test sync write for acm\n");
    printf("  -r, --asyncRead               : test async read for acm\n");
    printf("  -w, --asyncWrite              : test async write for acm\n");
    printf("  -c, --ctrlClassSync           : test class ctrl cmd for acm\n");
    printf("  -s, --ctrlGetStatus           : test get status ctrl cmd for acm\n");
    printf("  -C, --ctrlSyncDescriptor      : test sync get descriptor ctrl cmd for acm\n");
    printf("  -d, --ctrlAsyncDescriptor     : test async get descriptor ctrl cmd for acm\n");
    printf("  -g, --ctrlGetConfiguration    : test get configuration ctrl cmd for acm\n");
    printf("  -i, --ctrlGetInterface        : test get interface ctrl cmd for acm\n");
    printf("  -S, --speedTest               : test speed for acm\n");
    printf("  -B, --setBaudrate             : test set baudrate for acm\n");
    printf("  -b, --getBaudrate             : test get baudrate for acm\n");
    printf("  -I, --addInterface [index}    : test add interface for acm(not raw api function) and ecm\n");
    printf("  -D, --removeInterface [index] : test remove interface for acm(not raw api function) and ecm\n");
    printf("\n");
    printf("Examples:\n");
    printf("  usbhost_ddk_test -AR      : test sync read for acm by host ddk api function\n");
    printf("  usbhost_ddk_test -aw 123  : test async write 123 for acm by host raw api function\n");
}

static int32_t TestParaseCommand(int32_t paramNum, const char *cmdParam, int32_t *cmdType, char *apiType)
{
    bool isInvalid = cmdParam == NULL || cmdType == NULL || apiType == NULL || strlen(cmdParam) < PARAM_CMD_LENGTH;
    if (isInvalid) {
        HDF_LOGE("%s:%d command or cmdType is NULL or cmdParam length is error", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t len = strlen(cmdParam);
    for (uint32_t i = 0; i < len; i++) {
        auto iterGetMap = CMD_TYPE_VALUE_GET_MAP.find(cmdParam[i]);
        auto iterSetMap = CMD_TYPE_VALUE_SET_MAP.find(cmdParam[i]);
        if (strcmp(cmdParam[i], 'A') == 0) {
            strcpy_s(apiType, DATA_MAX_LEN, "-SDK");
            break;
        } else if (strcmp(cmdParam[i], 'a') == 0) {
            strcpy_s(apiType, DATA_MAX_LEN, "-RAW");
            break;
        } else if (strcmp(cmdParam[i], 'E') == 0) { 
            strcpy_s(apiType, DATA_MAX_LEN, "-ECM");
            break;
        } else if(iterGetMap != NULL) {
            if (paramNum != PARAM_GET_CMD_LEN) {
            return HDF_FAILURE;
            }
            if (iterGetMap != CMD_TYPE_VALUE_GET_MAP.end()) {
                *cmdType = iterGetMap->second;
                break;
            }
        } else if(iterSetMap != NULL) {
            if (paramNum != PARAM_SET_CMD_LEN) {
            return HDF_FAILURE;
            }
            if (iterSetMap != CMD_TYPE_VALUE_SET_MAP.end()) {
                *cmdType = iterSetMap->second;
                break;
            }
        } else if (strcmp(cmdParam[i], '-') == 0) {
            break;
        } else {
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

static void TestCmdLoopOther(int32_t cmdType, const char *param)
{
    switch (cmdType) {
        case HOST_ACM_CTRL_CLASS_SYNC:
            UsbHostDdkTestCtrlClass(NULL);
            break;
        case HOST_ACM_CTRL_GET_STATUS:
            UsbHostDdkTestStdGetStatus(NULL);
            break;
        case HOST_ACM_CTRL_SYNC_DESCRIPTOR:
            UsbHostDdkTestStdGetDes(NULL);
            break;
        case HOST_ACM_CTRL_ASYNC_DESCRIPTOR:
            UsbHostDdkTestStdGetDesAsync(NULL);
            usleep(READ_SLEEP_TIME);
            break;
        case HOST_ACM_CTRL_GET_CONFIGURATION:
            TestStdGetConf();
            break;
        case HOST_ACM_CTRL_GET_INTERFACE:
            TestStdGetInterface();
            break;
        case HOST_ACM_SET_BAUDRATE:
            UsbHostDdkTestSetBaudrate((uint32_t)(strtoul(param, NULL, STRTOL_BASE)));
            break;
        case HOST_ACM_GET_BAUDRATE:
            UsbHostDdkTestGetBaudrate(NULL);
            break;
        case HOST_ACM_ADD_INTERFACE:
            UsbHostDdkTestAddInterface((uint32_t)(strtoul(param, NULL, STRTOL_BASE)));
            break;
        case HOST_ACM_REMOVE_INTERFACE:
            UsbHostDdkTestRemoveInterface((uint32_t)(strtoul(param, NULL, STRTOL_BASE)));
            break;
        default:
            break;
    }
}

static int32_t TestCmdLoop(int32_t cmdType, const char *param)
{
    bool loopFlag = true;
    bool asyncFlag = false;
    int32_t cnt = 0;

    if (TestGetExitFlag() == true) {
        HDF_LOGD("%s:%d g_exitFlag is true!", __func__, __LINE__);
        return HDF_FAILURE;
    }

    while ((loopFlag) && (!run)) {
        switch (cmdType) {
            case HOST_ACM_SYNC_READ:
                UsbHostDdkTestSyncRead(NULL);
                break;
            case HOST_ACM_SYNC_WRITE:
                UsbHostDdkTestSyncWrite(param);
                break;
            case HOST_ACM_ASYNC_READ:
                if (UsbHostDdkTestAsyncRead(NULL) != HDF_SUCCESS) {
#ifdef __LITEOS_USB_HOST_DDK_TEST__
                    if (cnt++ > 10) {
                        asyncFlag = false;
                        return HDF_DEV_ERR_NO_DEVICE_SERVICE;
                    }
#else
                    asyncFlag = false;
#endif
                } else {
                    cnt = 0;
                    asyncFlag = true;
                    usleep(READ_SLEEP_TIME);
                }
                break;
            case HOST_ACM_ASYNC_WRITE:
                UsbHostDdkTestAsyncWrite(param);
                break;
            default:
                TestCmdLoopOther(cmdType, param);
                break;
        }

        if (!asyncFlag) {
            loopFlag = false;
        }
    }
    return HDF_SUCCESS;
}

#ifdef __LITEOS_USB_HOST_DDK_TEST__
static void *SigHandle(void *arg)
{
    (void)arg;
    run = 0;
    return NULL;
}

static int32_t GetCharThread(void *arg)
{
    char str[STR_LEN] = {0};
    while (run) {
        str[0] = (char)getchar();
    }
    return 0;
}
#endif

#define HDF_PROCESS_STACK_SIZE 100000
static int32_t StartThreadGetChar()
{
#ifdef __LITEOS_USB_HOST_DDK_TEST__
    int32_t ret;
    struct OsalThreadParam threadCfg;
    memset_s(&threadCfg, sizeof(threadCfg), 0, sizeof(threadCfg));
    threadCfg.name = "get char process";
    threadCfg.priority = OSAL_THREAD_PRI_DEFAULT;
    threadCfg.stackSize = HDF_PROCESS_STACK_SIZE;

    ret = OsalThreadCreate(&g_Getchar, (OsalThreadEntry)GetCharThread, NULL);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%s:%d OsalThreadCreate failed, ret=%d ", __func__, __LINE__, ret);
        return HDF_ERR_DEVICE_BUSY;
    }

    ret = OsalThreadStart(&g_Getchar, &threadCfg);
    if (HDF_SUCCESS != ret) {
        HDF_LOGE("%s:%d OsalThreadStart failed, ret=%d ", __func__, __LINE__, ret);
        return HDF_ERR_DEVICE_BUSY;
    }
#endif
    return 0;
}

int32_t main(int32_t argc, char *argv[])
{
    int32_t status;
    int32_t cmdType;
    char apiType[DATA_MAX_LEN];

    if ((argc < ARGV_CMD_TYPE) || (argc < PARAM_GET_CMD_LEN) || (argv[ARGV_CMD_TYPE] == NULL)) {
        HDF_LOGE("%s:%d invalid parma, argc=%d", __func__, __LINE__, argc);
        return HDF_FAILURE;
    }

    if ((argc == PARAM_GET_CMD_LEN) &&
        ((!strcmp(argv[ARGV_CMD_TYPE], "-h")) || (!strcmp(argv[ARGV_CMD_TYPE], "--help")))) {
        TestHelp();
        return HDF_SUCCESS;
    }
    run = 1;

    StartThreadGetChar();
    status = TestParaseCommand(argc, argv[ARGV_CMD_TYPE], &cmdType, apiType);
    if (status != HDF_SUCCESS) {
        run = 0;
        HDF_LOGE("%s:%d TestParaseCommand status=%d err", __func__, __LINE__, status);
        TestHelp();
        return status;
    }

    status = UsbHostDdkTestInit(apiType);
    if (status != HDF_SUCCESS) {
        run = 0;
        HDF_LOGE("%s:%d UsbHostDdkTestInit status=%d err", __func__, __LINE__, status);
        return status;
    }

    if (UsbHostDdkTestOpen(cmdType) != HDF_SUCCESS) {
        goto OUT;
    }
#ifdef __LITEOS_USB_HOST_DDK_TEST__
    (void)signal(SIGINT, SigHandle);
#endif
    status = TestCmdLoop(cmdType, argv[ARGV_CMD_PARAM]);
    if (status == HDF_DEV_ERR_NO_DEVICE_SERVICE) {
        goto OUT;
    }

    if ((cmdType != HOST_ACM_ADD_INTERFACE) && (cmdType != HOST_ACM_REMOVE_INTERFACE)) {
        if (UsbHostDdkTestClose(cmdType) != HDF_SUCCESS) {
            goto OUT;
        }
    }

OUT:
    run = 0;
    TestExit();
    return HDF_SUCCESS;
}
