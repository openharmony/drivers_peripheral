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

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <getopt.h>

#include "securec.h"
#include "parameter.h"
#include "malloc.h"
#include "devhost_dump.h"
#include "devhost_service.h"
#include "devhost_service_full.h"
#include "hdf_base.h"
#include "hdf_core_log.h"
#include "hdf_power_manager.h"

#define HDF_LOG_TAG                    hdf_device_host
#define DEVHOST_MIN_INPUT_PARAM_NUM    5
#define DEVHOST_INPUT_PARAM_HOSTID_POS 1
#define DEVHOST_HOST_NAME_POS          2
#define DEVHOST_PROCESS_PRI_POS        3
#define DEVHOST_THREAD_PRI_POS         4
#define PARAM_BUF_LEN 128
#define MALLOPT_PARA_CNT 2
#define INVALID_PRIORITY "0"
#define DEVHOST_ARGUMENT 2

typedef struct {
    int hostId;
    const char *hostName;
    int schedPriority;
    int processPriority;
    int malloptKey;
    int malloptValue;
} HostConfig;

bool HdfStringToInt(const char *str, int *value)
{
    if (str == NULL || value == NULL) {
        return false;
    }

    char *end = NULL;
    errno = 0;
    const int base = 10;
    long result = strtol(str, &end, base);
    if (end == str || end[0] != '\0' || errno == ERANGE || result > INT_MAX || result < INT_MIN) {
        return false;
    }

    *value = (int)result;
    return true;
}

static void SetMallopt(int32_t malloptKey, int32_t malloptValue)
{
    int ret = mallopt(malloptKey, malloptValue);
    if (ret != 1) {
        HDF_LOGE("mallopt failed, malloptKey:%{public}d, malloptValue:%{public}d, ret:%{public}d",
            malloptKey, malloptValue, ret);
            return;
    }
    HDF_LOGI("host set mallopt succeed, mallopt:%{public}d %{public}d", malloptKey, malloptValue);
}

typedef int32_t (*CommandFunc)(const char *key, const char *value, HostConfig *config);
typedef struct CommandToFunc {
    const char *opt;
    CommandFunc func;
}CommandToFunc;

static int32_t CommandIFunc(const char *key, const char *value, HostConfig *config)
{
    (void)key;
    if (!HdfStringToInt(value, &config->hostId)) {
        HDF_LOGE("Invalid process ID: %{public}s", value);
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

static int32_t CommandNFunc(const char *key, const char *value, HostConfig *config)
{
    (void)key;
    config->hostName = value;
    return HDF_SUCCESS;
}

static int32_t CommandPFunc(const char *key, const char *value, HostConfig *config)
{
    (void)key;
    if (!HdfStringToInt(value, &config->processPriority)) {
        HDF_LOGE("Invalid process ID: %{public}s", value);
    }
    return HDF_SUCCESS;
}

static int32_t CommandSFunc(const char *key, const char *value, HostConfig *config)
{
    (void)key;
    if (!HdfStringToInt(value, &config->schedPriority)) {
        HDF_LOGE("Invalid process ID: %{public}s", value);
    }
    return HDF_SUCCESS;
}

static int32_t CommandMFunc(const char *key, const char *value, HostConfig *config)
{
    (void)key;
    if (!HdfStringToInt(value, &config->malloptKey)) {
        HDF_LOGE("Invalid process ID: %{public}s", value);
    }
    return HDF_SUCCESS;
}

static int32_t CommandVFunc(const char *key, const char *value, HostConfig *config)
{
    (void)key;
    if (!HdfStringToInt(value, &config->malloptValue)) {
        HDF_LOGE("Invalid process ID: %{public}s", value);
    }
    return HDF_SUCCESS;
}

static int32_t CommandNumFunc(const char *key, const char *value, HostConfig *config)
{
    int32_t malloptKey = 0;
    int32_t malloptValue = 0;
    if (!HdfStringToInt(value, &malloptValue)) {
        HDF_LOGE("Invalid value: %{public}s", value);
    }
    if (!HdfStringToInt(key, &malloptKey)) {
        HDF_LOGE("Invalid key: %{public}s", key);
    }
    SetMallopt(malloptKey, malloptValue);
    return HDF_SUCCESS;
}

static struct CommandToFunc g_commandFuncs[] = {
    {"-i", CommandIFunc},
    {"-n", CommandNFunc},
    {"-p", CommandPFunc},
    {"-s", CommandSFunc},
    {"-m", CommandMFunc},
    {"-v", CommandVFunc},
    {"-1005", CommandNumFunc},
    {"-1006", CommandNumFunc},
    {"-1007", CommandNumFunc},
    {"-1008", CommandNumFunc},
    {"-1009", CommandNumFunc},
    {"-1010", CommandNumFunc},
    {"-1011", CommandNumFunc},
    {"-1012", CommandNumFunc},
    {"-1013", CommandNumFunc},
    {"-1014", CommandNumFunc},
};

static void StartMemoryHook(const char* processName)
{
    const char defaultValue[PARAM_BUF_LEN] = { 0 };
    const char targetPrefix[] = "startup:";
    const int targetPrefixLen = strlen(targetPrefix);
    char paramValue[PARAM_BUF_LEN] = { 0 };
    int retParam = GetParameter("libc.hook_mode", defaultValue, paramValue, sizeof(paramValue));
    if (retParam <= 0 || strncmp(paramValue, targetPrefix, targetPrefixLen) != 0) {
        return;
    }
    if (strstr(paramValue + targetPrefixLen, processName) != NULL) {
        const int hookSignal = 36; // 36: native memory hooked signal
        HDF_LOGE("raise hook signal %{public}d to %{public}s", hookSignal, processName);
        raise(hookSignal);
    }
}

static void SetProcTitle(char **argv, const char *newTitle)
{
    if (newTitle == NULL) {
        HDF_LOGE("failed because newTitle is NULL");
        return;
    }
    size_t len = strlen(argv[0]); // 获取原始进程标题的长度
    if (strlen(newTitle) > len) { // 如果新标题的长度超过原始标题的长度
        HDF_LOGE("failed to set new process title because the '%{public}s' is too long", newTitle); // 打印错误日志
        return; // 退出函数
    }
    (void)memset_s(argv[0], len, 0, len); // 将原始标题的内存清零
    if (strcpy_s(argv[0], len + 1, newTitle) != EOK) { // 将新标题复制到原始标题的位置
        HDF_LOGE("failed to set new process title"); // 如果复制失败，打印错误日志
        return; // 退出函数
    }
    prctl(PR_SET_NAME, newTitle); // 使用 prctl 系统调用设置进程的名字
}

static void HdfSetProcPriority(int32_t procPriority, int32_t schedPriority)
{
    if (setpriority(PRIO_PROCESS, 0, procPriority) != 0) {
        HDF_LOGE("host setpriority failed: %{public}d", errno);
    }

    struct sched_param param = {0};
    param.sched_priority = schedPriority;
    if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) {
        HDF_LOGE("host sched_setscheduler failed: %{public}d", errno);
    } else {
        HDF_LOGI("host sched_setscheduler succeed:%{public}d %{public}d", procPriority, schedPriority);
    }
}

static int FindFunc(const char* arg, const char* value, HostConfig *config)
{
    for (size_t i = 0; i < sizeof(g_commandFuncs) / sizeof(g_commandFuncs[0]); ++i) {
        if (strcmp(g_commandFuncs[i].opt, arg) == 0) {
            return g_commandFuncs[i].func(arg, value, config);
        }
    }
    HDF_LOGE("FindFunc failed: %{public}s", arg);
    return HDF_ERR_INVALID_PARAM;
}

static int ParseCommandLineArgs(int argc, char **argv, HostConfig *config)
{
    for (int i = 1; i < argc; i += DEVHOST_ARGUMENT) {
        const char* arg = argv[i];

        if (arg == NULL) {
            HDF_LOGE("NULL argument:arg");
            continue;
        }

        int valueIndex = i + 1;
        if (valueIndex >= argc) {
            HDF_LOGE("Missing argument for -%{public}s", arg);
            continue;
        }
        const char* value = argv[valueIndex];
        if (value == NULL) {
            HDF_LOGE("NULL argument: value");
            continue;
        }
        if (FindFunc(arg, value, config) != HDF_SUCCESS) {
            HDF_LOGE("argument Parse failed for -%s", arg);
        }
    }
    return HDF_SUCCESS;
}

static int InitializeHost(const HostConfig *config, char **argv)
{
    prctl(PR_SET_PDEATHSIG, SIGKILL); // host process should exit with devmgr process

    HDF_LOGI("hdf device host %{public}s %{public}d start", config->hostName, config->hostId);
    SetProcTitle(argv, config->hostName);
    StartMemoryHook(config->hostName);
    if ((config->processPriority != 0) && (config->schedPriority != 0)) {
        HdfSetProcPriority(config->processPriority, config->schedPriority);
    }
    if ((config->malloptKey != 0) && (config->malloptValue != 0)) {
        SetMallopt(config->malloptKey, config->malloptValue);
    }
    return HDF_SUCCESS;
}

static int StartHostService(const HostConfig *config)
{
    struct IDevHostService *instance = DevHostServiceNewInstance(config->hostId, config->hostName);
    if (instance == NULL || instance->StartService == NULL) {
        HDF_LOGE("DevHostServiceGetInstance fail");
        return HDF_ERR_INVALID_OBJECT;
    }
    HDF_LOGD("create IDevHostService of %{public}s success", config->hostName);

    DevHostDumpInit();
    HDF_LOGD("%{public}s start device service begin", config->hostName);
    int status = instance->StartService(instance);
    if (status != HDF_SUCCESS) {
        HDF_LOGE("Devhost StartService fail, return: %{public}d", status);
        DevHostServiceFreeInstance(instance);
        DevHostDumpDeInit();
        return status;
    }

    HdfPowerManagerInit();
    struct DevHostServiceFull *fullService = (struct DevHostServiceFull *)instance;
    struct HdfMessageLooper *looper = &fullService->looper;
    if ((looper != NULL) && (looper->Start != NULL)) {
        HDF_LOGI("%{public}s start loop", config->hostName);
        looper->Start(looper);
    }

    DevHostServiceFreeInstance(instance);
    HdfPowerManagerExit();
    DevHostDumpDeInit();
    return HDF_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc < DEVHOST_MIN_INPUT_PARAM_NUM) {
        HDF_LOGE("Devhost main parameter error, argc: %{public}d", argc);
        return HDF_ERR_INVALID_PARAM;
    }

    HostConfig config = {0};
    if (ParseCommandLineArgs(argc, argv, &config) != HDF_SUCCESS) {
        HDF_LOGE("ParseCommandLineArgs(argc, argv, &config) != HDF_SUCCESS");
        return HDF_ERR_INVALID_PARAM;
    }

    if (InitializeHost(&config, argv) != HDF_SUCCESS) {
        return HDF_ERR_INVALID_PARAM;
    }

    int status = StartHostService(&config);
    HDF_LOGI("hdf device host %{public}s %{public}d exit", config.hostName, config.hostId);
    return status;
}
