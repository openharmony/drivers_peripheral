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

#include "usbd_load_usb_service.h"

#include <cstdlib>
#include <iostream>
#include <unistd.h>

#include "hdf_base.h"
#include "iservice_registry.h"
#include "osal_thread.h"
#include "osal_time.h"
#include "securec.h"

using namespace OHOS;
using namespace std;
#define HDF_LOG_TAG usbd_load_usb_service

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_0 {
uint32_t UsbdLoadUsbService::count_ = 0;
bool UsbdLoadUsbService::alarmRunning_ = false;
bool OnDemandLoadCallback::loading_ = false;
timer_t UsbdLoadUsbService::timer_ = nullptr;

OnDemandLoadCallback::OnDemandLoadCallback() {}

void OnDemandLoadCallback::OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    loading_ = false;
    HDF_LOGI("%s: OnLoadSystemAbilitySuccess systemAbilityId: %d", __func__, systemAbilityId);
}

void OnDemandLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    loading_ = false;
    HDF_LOGI("%s: OnLoadSystemAbilityFail systemAbilityId: %d", __func__, systemAbilityId);
}

uint32_t UsbdLoadUsbService::GetUsbLoadRemoveCount()
{
    return count_;
}

void UsbdLoadUsbService::SetUsbLoadRemoveCount(uint32_t count)
{
    count_ = count;
    if (count_ > 0) {
        StartThreadUsbLoad();
    }
}

void UsbdLoadUsbService::IncreaseUsbLoadRemoveCount()
{
    HDF_LOGI("%s: IncreaseUsbLoadRemoveCount count_: %d", __func__, count_);
    count_++;
}

void UsbdLoadUsbService::DecreaseUsbLoadRemoveCount()
{
    HDF_LOGI("%s: DecreaseUsbLoadRemoveCount count_: %d", __func__, count_);
    if (count_ == 0) {
        return;
    }
    count_--;
}

int32_t UsbdLoadUsbService::UsbLoadWorkEntry(void *para)
{
    sptr<ISystemAbilityManager> sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sm == nullptr) {
        HDF_LOGE("GetSystemAbilityManager samgr object null");
        return HDF_FAILURE;
    }
    sptr<OnDemandLoadCallback> loadCallback_ = new (std::nothrow) OnDemandLoadCallback();
    OnDemandLoadCallback::loading_ = true;
    int32_t result = sm->LoadSystemAbility(USB_SYSTEM_ABILITY_ID, loadCallback_);
    if (result != ERR_OK) {
        HDF_LOGE("LoadSystemAbility failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdLoadUsbService::StartThreadUsbLoad()
{
    int32_t ret;
    struct OsalThread threadUsbLoad;
    struct OsalThreadParam threadCfg;
    ret = memset_s(&threadCfg, sizeof(threadCfg), 0, sizeof(threadCfg));
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memset_s failed", __func__, __LINE__);
        return ret;
    }
    threadCfg.priority = OSAL_THREAD_PRI_DEFAULT;
    threadCfg.stackSize = HDF_PROCESS_STACK_SIZE;
    sptr<ISystemAbilityManager> sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sm == nullptr) {
        HDF_LOGE("%{public}s:GetSystemAbilityManager failed", __func__);
        return HDF_FAILURE;
    }
    auto saObj = sm->CheckSystemAbility(USB_SYSTEM_ABILITY_ID);
    if (saObj != nullptr) {
        return HDF_SUCCESS;
    }
    ret = OsalThreadCreate(&threadUsbLoad, static_cast<OsalThreadEntry>(UsbLoadWorkEntry), nullptr);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%d OsalThreadCreate failed, ret = %d ", __func__, __LINE__, ret);
        return HDF_ERR_DEVICE_BUSY;
    }
    ret = OsalThreadStart(&threadUsbLoad, &threadCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%d OsalThreadStart failed, ret = %d ", __func__, __LINE__, ret);
        return HDF_ERR_DEVICE_BUSY;
    }
    return HDF_SUCCESS;
}

void UsbdLoadUsbService::UsbRemoveWorkEntry(union sigval v)
{
    timer_delete(timer_);
    if (GetUsbLoadRemoveCount() == 0) {
        sptr<ISystemAbilityManager> sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (sm == nullptr) {
            HDF_LOGE("GetSystemAbilityManager samgr object null");
            return;
        }
        uint32_t checkCount = CHECK_CNT;
        while (OnDemandLoadCallback::loading_ && (checkCount > 0)) {
            checkCount--;
            auto saObj = sm->CheckSystemAbility(USB_SYSTEM_ABILITY_ID);
            if (saObj == nullptr) {
                OsalMDelay(SLEEP_DELAY);
                continue;
            } else {
                OnDemandLoadCallback::loading_ = false;
            }
        }
        int32_t result = sm->RemoveSystemAbility(USB_SYSTEM_ABILITY_ID);
        if (result != ERR_OK) {
            HDF_LOGE("RemoveSystemAbility failed");
        } else {
            HDF_LOGI("RemoveSystemAbility success");
        }
    }
    alarmRunning_ = false;
}

int32_t UsbdLoadUsbService::LoadUsbService()
{
    if (GetUsbLoadRemoveCount() == 0 && alarmRunning_ == false) {
        if (StartThreadUsbLoad() != HDF_SUCCESS) {
            HDF_LOGE("%s: usb load create thread failed", __func__);
        }
    } else if (OnDemandLoadCallback::loading_ == false) {
        StartThreadUsbLoad();
    }
    IncreaseUsbLoadRemoveCount();
    return HDF_SUCCESS;
}

int32_t UsbdLoadUsbService::RemoveUsbService()
{
    if (GetUsbLoadRemoveCount() == 1 && alarmRunning_ == false) {
        alarmRunning_ = true;
        struct sigevent evp;
        struct itimerspec ts;
        timer_t timer;
        errno_t retSafe = memset_s(&evp, sizeof(sigevent), 0, sizeof(sigevent));
        if (retSafe != EOK) {
            HDF_LOGE("memset_s failed");
            return HDF_FAILURE;
        }
        evp.sigev_value.sival_ptr = &timer;
        evp.sigev_notify = SIGEV_THREAD;
        evp.sigev_notify_function = UsbRemoveWorkEntry;
        int32_t ret = timer_create(CLOCK_REALTIME, &evp, &timer);
        if (ret != 0) {
            HDF_LOGE("timer_create failed");
            return HDF_FAILURE;
        }
        ts.it_interval.tv_sec = 0;
        ts.it_interval.tv_nsec = 0;
        ts.it_value.tv_sec = CHECK_TIME;
        ts.it_value.tv_nsec = 0;
        ret = timer_settime(timer, TIMER_ABSTIME, &ts, NULL);
        if (ret != 0) {
            HDF_LOGE("timer_settime failed");
            timer_delete(timer);
            return HDF_FAILURE;
        }
        timer_ = timer;
    }
    DecreaseUsbLoadRemoveCount();
    return HDF_SUCCESS;
}

void UsbdLoadUsbService::CloseUsbService()
{
    sptr<ISystemAbilityManager> sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sm == nullptr) {
        HDF_LOGE("GetSystemAbilityManager samgr object null");
        return;
    }
    auto saObj = sm->CheckSystemAbility(USB_SYSTEM_ABILITY_ID);
    if (saObj == nullptr) {
        HDF_LOGI("Usb service not start");
        return;
    }
    if (sm->RemoveSystemAbility(USB_SYSTEM_ABILITY_ID) != ERR_OK) {
        HDF_LOGE("RemoveSystemAbility failed");
        return;
    }
    // wait for usb service close
    OsalMSleep(SLEEP_DELAY);
}
} // namespace V1_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS
