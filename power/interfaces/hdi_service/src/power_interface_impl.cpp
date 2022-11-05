/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "power_interface_impl.h"

#include <atomic>
#include <hdf_base.h>
#include <file_ex.h>
#include <iremote_object.h>
#include <iproxy_broker.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <cstdlib>
#include <thread>
#include "errors.h"
#include "hdf_sbuf.h"
#include "pubdef.h"
#include "securec.h"
#include "utils/hdf_log.h"
#include "hdf_device_desc.h"
#include "hdf_remote_service.h"
#include "unique_fd.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_0 {
static constexpr const int32_t MAX_FILE_LENGTH = 32 * 1024 * 1024;
static constexpr const char * const SUSPEND_STATE = "mem";
static constexpr const char * const SUSPEND_STATE_PATH = "/sys/power/state";
static constexpr const char * const LOCK_PATH = "/sys/power/wake_lock";
static constexpr const char * const UNLOCK_PATH = "/sys/power/wake_unlock";
static constexpr const char * const WAKEUP_COUNT_PATH = "/sys/power/wakeup_count";
static std::chrono::milliseconds waitTime_(100); // {100ms};
static std::mutex g_mutex;
static std::mutex g_suspendMutex;
static std::condition_variable g_suspendCv;
static std::unique_ptr<std::thread> g_daemon;
static std::atomic_bool g_suspending;
static std::atomic_bool g_suspendRetry;
static sptr<IPowerHdiCallback> g_callback;
static UniqueFd wakeupCountFd;
static void AutoSuspendLoop();
static int32_t DoSuspend();
static void LoadStringFd(int32_t fd, std::string& content);
static std::string ReadWakeCount();
static bool WriteWakeCount(const std::string& count);
static void NotifyCallback(int code);
namespace {
    sptr<PowerInterfaceImpl::PowerDeathRecipient> g_deathRecipient = nullptr;
    bool g_isHdiStart = false;
}

extern "C" IPowerInterface *PowerInterfaceImplGetInstance(void)
{
    return new (std::nothrow) PowerInterfaceImpl();
}

int32_t PowerInterfaceImpl::RegisterCallback(const sptr<IPowerHdiCallback>& ipowerHdiCallback)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_isHdiStart) {
        g_callback = ipowerHdiCallback;
        if (g_callback == nullptr) {
            UnRegister();
            return HDF_SUCCESS;
        }
        g_deathRecipient = new PowerDeathRecipient(this);
        if (g_deathRecipient == nullptr) {
            return HDF_FAILURE;
        }
        AddPowerDeathRecipient(g_callback);
        g_isHdiStart = true;
    }
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::UnRegister()
{
    HDF_LOGI("UnRegister");
    RemovePowerDeathRecipient(g_callback);
    g_callback = nullptr;
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::StartSuspend()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_suspendRetry = true;
    if (g_suspending) {
        g_suspendCv.notify_one();
        return HDF_SUCCESS;
    }
    g_suspending = true;
    g_daemon = std::make_unique<std::thread>(&AutoSuspendLoop);
    g_daemon->detach();
    return HDF_SUCCESS;
}

void AutoSuspendLoop()
{
    auto suspendLock = std::unique_lock(g_suspendMutex);
    while (true) {
        std::this_thread::sleep_for(waitTime_);

        const std::string wakeupCount = ReadWakeCount();
        if (wakeupCount.empty()) {
            continue;
        }
        if (!g_suspendRetry) {
            g_suspendCv.wait(suspendLock);
        }
        if (!WriteWakeCount(wakeupCount)) {
            continue;
        }

        NotifyCallback(CMD_ON_SUSPEND);
        DoSuspend();
        NotifyCallback(CMD_ON_WAKEUP);
    }
    g_suspending = false;
    g_suspendRetry = false;
}

int32_t DoSuspend()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    UniqueFd suspendStateFd(TEMP_FAILURE_RETRY(open(SUSPEND_STATE_PATH, O_RDWR | O_CLOEXEC)));
    if (suspendStateFd < 0) {
        return HDF_FAILURE;
    }
    bool ret = false;
    do {
        ret = SaveStringToFd(suspendStateFd, SUSPEND_STATE);
    } while (!ret && (errno == EINTR || errno == EBUSY));

    if (!ret) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void NotifyCallback(int code)
{
    if (g_callback == nullptr) {
        return;
    }
    switch (code) {
        case CMD_ON_SUSPEND:
            g_callback->OnSuspend();
            break;
        case CMD_ON_WAKEUP:
            g_callback->OnWakeup();
            break;
    }
}

int32_t PowerInterfaceImpl::StopSuspend()
{
    g_suspendRetry = false;

    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::ForceSuspend()
{
    g_suspendRetry = false;

    NotifyCallback(CMD_ON_SUSPEND);
    DoSuspend();
    NotifyCallback(CMD_ON_WAKEUP);
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::SuspendBlock(const std::string& name)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (name.empty()) {
        return HDF_ERR_INVALID_PARAM;
    }
    UniqueFd fd(TEMP_FAILURE_RETRY(open(LOCK_PATH, O_RDWR | O_CLOEXEC)));
    bool ret = SaveStringToFd(fd, name);
    if (!ret) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::SuspendUnblock(const std::string& name)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (name.empty()) {
        return HDF_ERR_INVALID_PARAM;
    }
    UniqueFd fd(TEMP_FAILURE_RETRY(open(UNLOCK_PATH, O_RDWR | O_CLOEXEC)));
    bool ret = SaveStringToFd(fd, name);
    if (!ret) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::AddPowerDeathRecipient(const sptr<IPowerHdiCallback> &callback)
{
    HDF_LOGI("AddPowerDeathRecipient");
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IPowerHdiCallback>(callback);
    bool result = remote->AddDeathRecipient(g_deathRecipient);
    if (!result) {
        HDF_LOGI("AddPowerDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::RemovePowerDeathRecipient(const sptr<IPowerHdiCallback> &callback)
{
    HDF_LOGI("RemovePowerDeathRecipient");
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IPowerHdiCallback>(callback);
    bool result = remote->RemoveDeathRecipient(g_deathRecipient);
    if (!result) {
        HDF_LOGI("RemovePowerDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void PowerInterfaceImpl::PowerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    powerInterfaceImpl_->UnRegister();
}

void LoadStringFd(int32_t fd, std::string& content)
{
    if (fd <= 0) {
        HDF_LOGW("invalid fd: %{public}d", fd);
        return;
    }

    const int32_t fileLength = lseek(fd, 0, SEEK_END);
    if (fileLength > MAX_FILE_LENGTH || fileLength <= 0) {
        HDF_LOGW("invalid file length(%{public}d)!", fileLength);
        return;
    }
    int32_t loc = lseek(fd, 0, SEEK_SET);
    if (loc == -1) {
        HDF_LOGE("lseek file to begin failed!");
        return;
    }
    content.resize(fileLength);
    const int32_t len = static_cast<int32_t>(read(fd, content.data(), fileLength));
    if (len <= 0) {
        HDF_LOGW("the length read from file is failed, len: %{public}d, fileLen: %{public}d",
            len, fileLength);
        content.clear();
    }
}

std::string ReadWakeCount()
{
    if (wakeupCountFd < 0) {
        wakeupCountFd = UniqueFd(TEMP_FAILURE_RETRY(open(WAKEUP_COUNT_PATH, O_RDWR | O_CLOEXEC)));
    }
    std::string wakeupCount;
    LoadStringFd(wakeupCountFd, wakeupCount);

    return wakeupCount;
}

bool WriteWakeCount(const std::string& count)
{
    if (wakeupCountFd < 0) {
        wakeupCountFd = UniqueFd(TEMP_FAILURE_RETRY(open(WAKEUP_COUNT_PATH, O_RDWR | O_CLOEXEC)));
    }
    bool ret = SaveStringToFd(wakeupCountFd, count.c_str());
    return ret;
}

static void LoadSystemInfo(const std::string& path, std::string& info)
{
    UniqueFd fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDWR | O_CLOEXEC)));
    std::string str;
    if (fd >= 0) {
        bool ret = LoadStringFromFd(fd, str);
        if (!ret) {
            str = "# Failed to read";
        }
    } else {
        str = "# Failed to open";
    }
    info.append(path);
    info.append(": " + str + "\n");
}

int32_t PowerInterfaceImpl::PowerDump(std::string& info)
{
    std::string dumpInfo("");
    LoadSystemInfo(SUSPEND_STATE_PATH, dumpInfo);
    LoadSystemInfo(WAKEUP_COUNT_PATH, dumpInfo);
    LoadSystemInfo(LOCK_PATH, dumpInfo);
    LoadSystemInfo(UNLOCK_PATH, dumpInfo);
    info = dumpInfo;

    return HDF_SUCCESS;
}
} // V1_0
} // Power
} // HDI
} // OHOS
