/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "ddk_uevent_queue.h"

#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

#include <cstring>
#include <sys/types.h>
#include <unistd.h>

#include "ddk_device_manager.h"
#include "ddk_pnp_listener_mgr.h"
#include "hdf_base.h"
#include "hdf_io_service_if.h"
#include "hdf_log.h"
#include "securec.h"
#include "usbd_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
constexpr size_t MAX_ACTION_LEN = 20;
constexpr size_t MAX_DEVPATH_LEN = 250;
constexpr size_t MAX_SUBSYSTEM_LEN = 30;
constexpr size_t MAX_DEVTYPE_LEN = 30;
constexpr size_t MAX_DEVNUM_LEN = 10;
constexpr size_t MAX_BUSNUM_LEN = 10;
constexpr size_t MAX_TASK_NUM = 100000;
#define HDF_LOG_TAG usb_ddk_uevent_queue
struct DdkUeventTaskInfo {
    char action[MAX_ACTION_LEN];
    char devPath[MAX_DEVPATH_LEN];
    char subSystem[MAX_SUBSYSTEM_LEN];
    char devType[MAX_DEVTYPE_LEN];
    char devNum[MAX_DEVNUM_LEN];
    char busNum[MAX_BUSNUM_LEN];
};

class TaskQueue {
public:
    TaskQueue() = default;
    void Init(void);
    void UnInit(void);
    ~TaskQueue();
    int32_t AddTask(const DdkUeventTaskInfo &task);

private:
    std::queue<DdkUeventTaskInfo> taskQueue_;
    std::mutex queueLock_;
    std::condition_variable conditionVariable_;
    bool threadRun_ {true};
};

static bool DdkUeventCopyTask(DdkUeventTaskInfo &task, const struct DdkUeventInfo *info)
{
    int32_t ret = memcpy_s(task.action, MAX_ACTION_LEN, info->action, strlen(info->action));
    if (ret != EOK) {
        HDF_LOGE("%{public}s: copy action failed:%{public}s", __func__, info->action);
        return false;
    }

    ret = memcpy_s(task.devPath, MAX_DEVPATH_LEN, info->devPath, strlen(info->devPath));
    if (ret != EOK) {
        HDF_LOGE("%{public}s: copy devPath failed:%{public}s", __func__, info->devPath);
        return false;
    }

    ret = memcpy_s(task.subSystem, MAX_SUBSYSTEM_LEN, info->subSystem, strlen(info->subSystem));
    if (ret != EOK) {
        HDF_LOGE("%{public}s: copy subSystem failed:%{public}s", __func__, info->subSystem);
        return false;
    }

    ret = memcpy_s(task.devType, MAX_DEVTYPE_LEN, info->devType, strlen(info->devType));
    if (ret != EOK) {
        HDF_LOGE("%{public}s: copy devType failed:%{public}s", __func__, info->devType);
        return false;
    }

    ret = memcpy_s(task.devNum, MAX_DEVNUM_LEN, info->devNum, strlen(info->devNum));
    if (ret != EOK) {
        HDF_LOGE("%{public}s: copy devNum failed:%{public}s", __func__, info->devNum);
        return false;
    }

    ret = memcpy_s(task.busNum, MAX_BUSNUM_LEN, info->busNum, strlen(info->busNum));
    if (ret != EOK) {
        HDF_LOGE("%{public}s: copy busNum failed:%{public}s", __func__, info->busNum);
        return false;
    }
    return true;
}

static int32_t DdkUeventAddDevice(const char *devPath)
{
    const char *pos = strrchr(devPath, '/');
    if (pos == nullptr) {
        HDF_LOGE("%{public}s: no / in devpath:%{public}s", __func__, devPath);
        return HDF_ERR_INVALID_PARAM;
    }

    const struct UsbPnpNotifyMatchInfoTable *device = DdkDevMgrCreateDevice(pos + 1); // 1 skip '/'
    if (device == nullptr) {
        HDF_LOGE("%{public}s: create device failed:%{public}s", __func__, devPath);
        return HDF_FAILURE;
    }
    DdkListenerMgrNotifyAll(device, USB_PNP_NOTIFY_ADD_DEVICE);
    return HDF_SUCCESS;
}

static int32_t DdkUeventRemoveDevice(const char *busNum, const char *devNum)
{
    struct UsbPnpNotifyMatchInfoTable dev;
    int32_t ret =
        DdkDevMgrRemoveDevice(strtol(busNum, nullptr, 10), strtol(devNum, nullptr, 10), &dev); // 10 means decimal
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: remove device failed, busNum:%{public}s, devNum:%{public}s", __func__, busNum, devNum);
        return HDF_FAILURE;
    }
    DdkListenerMgrNotifyAll(&dev, USB_PNP_NOTIFY_REMOVE_DEVICE);
    return HDF_SUCCESS;
}

static void DdkDispatchUevent(const struct DdkUeventTaskInfo *info)
{
    int32_t ret = HDF_SUCCESS;
    if (strcmp(info->action, "bind") == 0 && strcmp(info->devType, "usb_device") == 0) {
        ret = DdkUeventAddDevice(info->devPath);
    } else if (strcmp(info->action, "remove") == 0 && strcmp(info->devType, "usb_device") == 0) {
        ret = DdkUeventRemoveDevice(info->busNum, info->devNum);
    }

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: action:%{public}s, ret:%{public}d", __func__, info->action, ret);
    }
}

void TaskQueue::Init(void)
{
    auto taskWork = [this]() -> void {
        pthread_setname_np(pthread_self(), "ueventTaskQueue");
        while (threadRun_) {
            std::unique_lock<std::mutex> uniqueLock(queueLock_);
            conditionVariable_.wait(uniqueLock, [this] {
                return (taskQueue_.size() > 0 || !threadRun_);
            });
            if (taskQueue_.size() > 0) {
                DdkUeventTaskInfo task = taskQueue_.front();
                taskQueue_.pop();
                uniqueLock.unlock();
                DdkDispatchUevent(&task);
            }
        }
    };
    std::thread thd(taskWork);

    thd.detach();
}



void TaskQueue::UnInit(void)
{
    threadRun_ = false;
    conditionVariable_.notify_one();

    std::lock_guard<std::mutex> lock(queueLock_);
    while (!taskQueue_.empty()) {
        taskQueue_.pop();
    }
}

TaskQueue::~TaskQueue()
{
    UnInit();
}

int32_t TaskQueue::AddTask(const DdkUeventTaskInfo &task)
{
    std::lock_guard<std::mutex> lock(queueLock_);
    if (taskQueue_.size() > MAX_TASK_NUM) {
        HDF_LOGE("%{public}s: task queue is full", __func__);
        conditionVariable_.notify_one();
        return HDF_FAILURE;
    }
    taskQueue_.emplace(task);
    conditionVariable_.notify_one();
    return HDF_SUCCESS;
}

static TaskQueue g_taskQueue;

int32_t DdkUeventStartDispatchThread()
{
    g_taskQueue.Init();
    return HDF_SUCCESS;
}

int32_t DdkUeventAddTask(const struct DdkUeventInfo *info)
{
    if (strcmp(info->subSystem, "usb") != 0) {
        return HDF_SUCCESS;
    }
    bool isAddDevice = strcmp(info->action, "bind") == 0 && strcmp(info->devType, "usb_device") == 0;
    bool isRemoveDevice = strcmp(info->action, "remove") == 0 && strcmp(info->devType, "usb_device") == 0;
    if (!(isAddDevice || isRemoveDevice)) {
        return HDF_SUCCESS;
    }
    HDF_LOGI("%{public}s: bind=%{public}s, subsystem=%{public}s, devType=%{public}s, devPath=%{public}s",
        __func__, info->action, info->subSystem, info->devType, info->devPath);
    DdkUeventTaskInfo task {
        {0x00},
        {0x00},
        {0x00},
        {0x00},
        {0x00},
        {0x00},
    };
    if (!DdkUeventCopyTask(task, info)) {
        HDF_LOGW("%{public}s: copy task failed", __func__);
        return HDF_FAILURE;
    }
    return g_taskQueue.AddTask(task);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */