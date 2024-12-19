/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "errors.h"
#include "hdf_device_desc.h"
#include "hdf_remote_service.h"
#include "hdf_sbuf.h"
#include "pubdef.h"
#include "running_lock_impl.h"
#include "securec.h"
#include "unique_fd.h"
#include "power_hdf_log.h"
#include "power_xcollie.h"
#include "v1_2/power_types.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <file_ex.h>
#include <hdf_base.h>
#include <iproxy_broker.h>
#include <iremote_object.h>
#include <mutex>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include "power_config.h"
#ifdef DRIVERS_PERIPHERAL_POWER_ENABLE_S4
#include "hibernate.h"
#endif

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_2 {
static constexpr const int32_t MAX_FILE_LENGTH = 32 * 1024 * 1024;
static constexpr const char * const SUSPEND_STATE = "mem";
static constexpr const char * const SUSPEND_STATE_PATH = "/sys/power/state";
static constexpr const char * const LOCK_PATH = "/sys/power/wake_lock";
static constexpr const char * const UNLOCK_PATH = "/sys/power/wake_unlock";
static constexpr const char * const WAKEUP_COUNT_PATH = "/sys/power/wakeup_count";
#ifdef FASTER_RETRY_OF_SLEEP
static constexpr std::chrono::milliseconds DEFAULT_WAIT_TIME(100); // 100ms for phone and tablet
#elif defined(SLOWER_RETRY_OF_SLEEP)
static constexpr std::chrono::milliseconds DEFAULT_WAIT_TIME(500); // 500ms for PC
#else
static constexpr std::chrono::milliseconds DEFAULT_WAIT_TIME(1000); // 1000ms
#endif
static constexpr std::chrono::milliseconds MAX_WAIT_TIME(1000 * 60); // 1min
static constexpr int32_t WAIT_TIME_FACTOR = 2;
static std::chrono::milliseconds waitTime_(DEFAULT_WAIT_TIME);
static std::mutex g_mutex;
static std::mutex g_suspendMutex;
static std::condition_variable g_suspendCv;
static std::unique_ptr<std::thread> g_daemon;
static std::atomic_bool g_suspending;
static std::atomic_bool g_suspendRetry;
static sptr<IPowerHdiCallback> g_callback;
static UniqueFd wakeupCountFd;
static PowerHdfState g_powerState {PowerHdfState::AWAKE};
static void AutoSuspendLoop();
static int32_t DoSuspend();
static void LoadStringFd(int32_t fd, std::string &content);
static std::string ReadWakeCount();
static bool WriteWakeCount(const std::string &count);
static void NotifyCallback(int code);
namespace {
sptr<PowerInterfaceImpl::PowerDeathRecipient> g_deathRecipient = nullptr;
bool g_isHdiStart = false;
} // namespace

extern "C" IPowerInterface *PowerInterfaceImplGetInstance(void)
{
    using OHOS::HDI::Power::V1_2::PowerInterfaceImpl;
    PowerInterfaceImpl *service = new (std::nothrow) PowerInterfaceImpl();
    if (service == nullptr) {
        return nullptr;
    }

    if (service->Init() != HDF_SUCCESS) {
        delete service;
        return nullptr;
    }
    return service;
}

int32_t PowerInterfaceImpl::Init()
{
    auto& powerConfig = PowerConfig::GetInstance();
    powerConfig.ParseConfig();
#ifdef DRIVERS_PERIPHERAL_POWER_ENABLE_S4
    Hibernate::GetInstance().Init();
#endif
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::RegisterCallback(const sptr<IPowerHdiCallback> &ipowerHdiCallback)
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
    g_isHdiStart = false;
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::RegisterRunningLockCallback(const sptr<IPowerRunningLockCallback>
    &iPowerRunningLockCallback)
{
    if (iPowerRunningLockCallback != nullptr) {
        UnRegisterRunningLockCallback();
    }
    RunningLockImpl::RegisterRunningLockCallback(iPowerRunningLockCallback);
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::UnRegisterRunningLockCallback()
{
    RunningLockImpl::UnRegisterRunningLockCallback();
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::StartSuspend()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    HDF_LOGI("start suspend");
    g_suspendRetry = true;
    if (g_suspending) {
        g_powerState = PowerHdfState::INACTIVE;
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
        g_powerState = PowerHdfState::SLEEP;
        DoSuspend();
        g_powerState = PowerHdfState::AWAKE;
        NotifyCallback(CMD_ON_WAKEUP);
    }
    g_suspending = false;
    g_suspendRetry = false;
}

#ifdef DRIVER_PERIPHERAL_POWER_SUSPEND_WITH_TAG
static constexpr const int32_t MAX_RETRY_COUNT = 5;
static int32_t g_ulsr_loop = 0;
static std::string g_suspendTag;
int32_t PowerInterfaceImpl::SetSuspendTag(const std::string &tag)
{
    HDF_LOGI("Set suspend tag: %{public}s", tag.c_str());
    g_suspendTag = tag;
    g_ulsr_loop = 0;
    return HDF_SUCCESS;
}

int32_t DoSuspendWithTag()
{
    UniqueFd suspendStateFd(TEMP_FAILURE_RETRY(open(SUSPEND_STATE_PATH, O_RDWR | O_CLOEXEC)));
    if (suspendStateFd < 0) {
        return HDF_FAILURE;
    }

    g_ulsr_loop++;
    bool ret = SaveStringToFd(suspendStateFd, g_suspendTag);
    if (!ret) {
        waitTime_ = std::min(waitTime_ * WAIT_TIME_FACTOR, MAX_WAIT_TIME);
        HDF_LOGE("SaveStringToFd fail, tag:%{public}s loop:%{public}d", g_suspendTag.c_str(), g_ulsr_loop);
        if (g_ulsr_loop >= MAX_RETRY_COUNT) {
            HDF_LOGE("DoSuspendWithTag fail: %{public}s", g_suspendTag.c_str());
            g_suspendTag.clear();
            waitTime_ = DEFAULT_WAIT_TIME;
            return HDF_FAILURE;
        }
        return HDF_SUCCESS;
    }
    HDF_LOGI("Do Suspend %{public}d: echo %{public}s > /sys/power/state", g_ulsr_loop, g_suspendTag.c_str());
    g_suspendTag.clear();
    waitTime_ = DEFAULT_WAIT_TIME;
    return HDF_SUCCESS;
}
#else
int32_t PowerInterfaceImpl::SetSuspendTag(const std::string &tag)
{
    return HDF_SUCCESS;
}
#endif

int32_t DoSuspend()
{
#ifdef DRIVER_PERIPHERAL_POWER_SUSPEND_WITH_TAG
    if (!g_suspendTag.empty()) {
        return DoSuspendWithTag();
    }
#endif

    UniqueFd suspendStateFd(TEMP_FAILURE_RETRY(open(SUSPEND_STATE_PATH, O_RDWR | O_CLOEXEC)));
    if (suspendStateFd < 0) {
        return HDF_FAILURE;
    }
    bool ret = SaveStringToFd(suspendStateFd, SUSPEND_STATE);
    if (!ret) {
        HDF_LOGE("DoSuspend fail");
        waitTime_ = std::min(waitTime_ * WAIT_TIME_FACTOR, MAX_WAIT_TIME);
        return HDF_FAILURE;
    }
    waitTime_ = DEFAULT_WAIT_TIME;
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
        default:
            break;
    }
}

int32_t PowerInterfaceImpl::StopSuspend()
{
    HDF_LOGI("stop suspend");
    g_suspendRetry = false;
    g_powerState = PowerHdfState::AWAKE;
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::ForceSuspend()
{
    //force suspend changed into active suspend
    HDF_LOGI("active suspend");
    StartSuspend();
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::Hibernate()
{
#ifdef DRIVERS_PERIPHERAL_POWER_ENABLE_S4
    HDF_LOGI("hibernate begin.");
    return Hibernate::GetInstance().DoHibernate();
#else
    HDF_LOGI("hdf hibernate interface not supported.");
    return HDF_FAILURE;
#endif
}

int32_t PowerInterfaceImpl::SuspendBlock(const std::string &name)
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

int32_t PowerInterfaceImpl::SuspendUnblock(const std::string &name)
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
    HDF_LOGI("PowerDeathRecipient OnRemoteDied");
    powerInterfaceImpl_->UnRegister();
    RunningLockImpl::Clean();
}

void LoadStringFd(int32_t fd, std::string &content)
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
        HDF_LOGW("the length read from file is failed, len: %{public}d, fileLen: %{public}d", len, fileLength);
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

bool WriteWakeCount(const std::string &count)
{
    if (wakeupCountFd < 0) {
        wakeupCountFd = UniqueFd(TEMP_FAILURE_RETRY(open(WAKEUP_COUNT_PATH, O_RDWR | O_CLOEXEC)));
    }
    bool ret = SaveStringToFd(wakeupCountFd, count.c_str());
    return ret;
}

static void LoadSystemInfo(const std::string &path, std::string &info)
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

int32_t PowerInterfaceImpl::PowerDump(std::string &info)
{
    std::string dumpInfo("");
    LoadSystemInfo(SUSPEND_STATE_PATH, dumpInfo);
    LoadSystemInfo(LOCK_PATH, dumpInfo);
    LoadSystemInfo(UNLOCK_PATH, dumpInfo);
    info = dumpInfo;

    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::HoldRunningLock(const RunningLockInfo &info)
{
    Power::PowerXCollie powerXcollie("Power_HoldRunningLock");
    return RunningLockImpl::Hold(info, g_powerState);
}

int32_t PowerInterfaceImpl::UnholdRunningLock(const RunningLockInfo &info)
{
    Power::PowerXCollie powerXcollie("Power_UnholdRunningLock");
    return RunningLockImpl::Unhold(info);
}

int32_t PowerInterfaceImpl::HoldRunningLockExt(const RunningLockInfo &info,
    uint64_t lockid, const std::string &bundleName)
{
    HDF_LOGI("Background runningLock active, type=%{public}d name=%{public}s", info.type, info.name.c_str());
    Power::PowerXCollie powerXcollie("Power_HoldRunningLockExt");
    return RunningLockImpl::HoldLock(info, g_powerState, lockid, bundleName);
}

int32_t PowerInterfaceImpl::UnholdRunningLockExt(const RunningLockInfo &info,
    uint64_t lockid, const std::string &bundleName)
{
    HDF_LOGI("Background runningLock inactive, type=%{public}d name=%{public}s", info.type, info.name.c_str());
    Power::PowerXCollie powerXcollie("Power_UnholdRunningLockExt");
    return RunningLockImpl::UnholdLock(info, lockid, bundleName);
}

int32_t PowerInterfaceImpl::GetWakeupReason(std::string &reason)
{
#ifdef DRIVER_PERIPHERAL_POWER_WAKEUP_CAUSE_PATH
    return GetPowerConfig("wakeuo_cause", reason);
#else
    HDF_LOGW("wakrup cause path not config");
    return HDF_FAILURE;
#endif
}

int32_t PowerInterfaceImpl::SetPowerConfig(const std::string &sceneName, const std::string &value)
{
    auto& powerConfig = PowerConfig::GetInstance();
    std::map<std::string, PowerConfig::PowerSceneConfig> sceneConfigMap = powerConfig.GetPowerSceneConfigMap();
    if (sceneConfigMap.empty()) {
        HDF_LOGE("SetPowerConfig sceneConfigMap is empty");
        return HDF_ERR_NOT_SUPPORT;
    }

    std::map<std::string, PowerConfig::PowerSceneConfig>::iterator it = sceneConfigMap.find(sceneName);
    if (it == sceneConfigMap.end()) {
        HDF_LOGE("SetPowerConfig sceneName: %{public}s does not exist", sceneName.c_str());
        return HDF_FAILURE;
    }
    std::string setPath = (it->second).setPath;
    HDF_LOGI("SetPowerConfig setPath = %{public}s", setPath.c_str());

    UniqueFd setValueFd = UniqueFd(TEMP_FAILURE_RETRY(open(setPath.c_str(), O_RDWR | O_CLOEXEC)));
    if (setValueFd < 0) {
        HDF_LOGE("SetPowerConfig open failed");
        return HDF_FAILURE;
    }
    bool ret = SaveStringToFd(setValueFd, value);
    if (!ret) {
        HDF_LOGE("SetPowerConfig SaveStringToFd failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t PowerInterfaceImpl::GetPowerConfig(const std::string &sceneName, std::string &value)
{
    auto& powerConfig = PowerConfig::GetInstance();
    std::map<std::string, PowerConfig::PowerSceneConfig> sceneConfigMap = powerConfig.GetPowerSceneConfigMap();
    if (sceneConfigMap.empty()) {
        HDF_LOGE("GetPowerConfig sceneConfigMap is empty");
        return HDF_ERR_NOT_SUPPORT;
    }

    std::map<std::string, PowerConfig::PowerSceneConfig>::iterator it = sceneConfigMap.find(sceneName);
    if (it == sceneConfigMap.end()) {
        HDF_LOGE("GetPowerConfig sceneName: %{public}s does not exist", sceneName.c_str());
        return HDF_FAILURE;
    }
    std::string getPath = (it->second).getPath;
    HDF_LOGI("GetPowerConfig getPath = %{public}s", getPath.c_str());

    UniqueFd getValueFd = UniqueFd(TEMP_FAILURE_RETRY(open(getPath.c_str(), O_RDONLY | O_CLOEXEC)));
    if (getValueFd < 0) {
        HDF_LOGE("GetPowerConfig open failed");
        return HDF_FAILURE;
    }
    LoadStringFd(getValueFd, value);
    return HDF_SUCCESS;
}
} // namespace V1_2
} // namespace Power
} // namespace HDI
} // namespace OHOS
