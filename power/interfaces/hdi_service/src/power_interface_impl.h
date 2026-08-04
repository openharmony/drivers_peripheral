/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef POWER_INTERFACE_IMPL_H
#define POWER_INTERFACE_IMPL_H

#include <v1_4/ipower_interface.h>
#include "running_lock_info.h"
#include "power_hdi_common.h"
#include "power_hdi_utils.h"
#include "system_suspend_controller.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_4 {
class PowerInterfaceImpl : public IPowerInterface {
public:
    PowerInterfaceImpl() = default;
    ~PowerInterfaceImpl() override = default;

    int32_t RegisterCallback(const sptr<IPowerHdiCallback> &gCallback) override;
    int32_t StartSuspend() override;
    int32_t StopSuspend() override;
    int32_t ForceSuspend() override;
    int32_t SuspendBlock(const std::string &name) override;
    int32_t SuspendUnblock(const std::string &name) override;
    int32_t AddRunningLock(const RunningLockInfo &info) override;
    int32_t RemoveRunningLock(const RunningLockInfo &info) override;
    int32_t SetWorkTriggerList(const RunningLockInfo &info, const WorkTriggerList &list) override;
    int32_t AcquireRunningLock(const RunningLockInfo &info) override;
    int32_t ReleaseRunningLock(const RunningLockInfo &info) override;
    int32_t SetRunningLocks(const RunningLockInfo &info, bool isAcquire);
    int32_t HoldRunningLock(const RunningLockInfo &info) override;
    int32_t UnholdRunningLock(const RunningLockInfo &info) override;
    int32_t PowerModeSwitch(const PowerHdfMode &mode) override;
    int32_t GetPowerMode(PowerHdfMode &mode) override;
    int32_t IsRunningLockTypeSupported(uint32_t type, bool &isSupported) override;
    int32_t ForceDoze() override;
    int32_t SuspendBegin() override;
    int32_t SuspendEnd() override;
    int32_t WakeupBegin() override;
    int32_t WakeupEnd() override;
    int32_t SetDisplaySuspend(bool enable) override;
    int32_t SetAutoSuspend(bool enable, int32_t timeoutMs) override;
    int32_t GetWakeupReasons(std::string &wakeupReasons) override;
    int32_t GetShutdownReason(std::string &reason) override;
    int32_t SetSuspendTag(const std::string &tag) override;
    int32_t RegisterXCollaborator(const sptr<IPowerCollaborator> &collaborator) override;
    int32_t RegisterPowerEventCallback(const sptr<IPowerEventCallback> &eventCallback) override;
    int32_t HandlePowerEvent(uint32_t event) override;
    int32_t LockScreenAfterTimeout(int32_t delayMs) override;
    int32_t ReadHibernationCursor(std::string &cursor) override;
    int32_t AdjustCpuFrequency(bool isScreenOn) override;
    int32_t ForceSuspendIgnoringWakelock(const std::string &tag) override;

private:
    std::vector<sptr<IPowerHdiCallback>> callbackList_ = {};
    std::map<PowerHdfMode, int32_t> modeCallbackStatus_ = {};
    std::unique_ptr<OHOS::PowerMgr::SystemSuspendController> ssCtl_ = nullptr;
    std::shared_ptr<PowerHdiUtils> util_ = nullptr;
    bool isSupportV1_2 = false;
    bool isSupportV1_3 = false;
    bool isSupportV1_4 = false;
    bool isReady = false;
    static std::map<PowerHdfRunningLockType, PowerHdfLockType> runningLockTypeConvertMap_;
    static std::mutex mutex_;
    void InitDlopenMode();
    void InitRunningLockTypeConvertMap();
    void SystemSuspendCtlInit();
    void SystemSuspendCtlDeinit();
    int32_t AddSysAndExtRunningLock(const RunningLockInfo &info);
    int32_t RemoveSysAndExtRunningLock(const RunningLockInfo &info);
    int32_t SetSysAndExtRunningLocks(const RunningLockInfo &info, bool isAcquire);
    int32_t SetHdiRunningLocks(const RunningLockInfo &info, bool isAcquire);
    int32_t AddHdiRunningLock(const RunningLockInfo &info);
    int32_t RemoveHdiRunningLock(const RunningLockInfo &info);
    int32_t DlopenAddRunningLock(const RunningLockInfo &info);
    int32_t DlopenRemoveRunningLock(const RunningLockInfo &info);
    int32_t DlopenSetRunningLocks(const RunningLockInfo &info, bool isAcquire);
    int32_t DlopenPowerModeSwitch(const PowerHdfMode &mode);
    int32_t DlopenGetPowerMode(PowerHdfMode &mode);
    int32_t DlopenIsRunningLockTypeSupported(uint32_t type, bool &isSupported);
    int32_t DlopenRegisterCallback(const sptr<IPowerHdiCallback> &gCallback);
    int32_t DlopenForceDoze();
    int32_t DlopenSuspendBegin();
    int32_t DlopenSuspendEnd();
    int32_t DlopenWakeupBegin();
    int32_t DlopenWakeupEnd();
    int32_t DlopenSetDisplaySuspend(bool enable);
    int32_t DlopenSetAutoSuspend(bool enable, int32_t timeoutMs);
    int32_t DlopenGetWakeupReasons(std::string &wakeupReasons);
    int32_t DlopenGetShutdownReason(std::string &reason);
    int32_t DlopenSetSuspendTag(const std::string &tag);
    int32_t DlopenRegisterXCollaborator(const sptr<IPowerCollaborator> &collaborator);
    int32_t DlopenRegisterPowerEventCallback(const sptr<IPowerEventCallback> &eventCallback);
    int32_t DlopenHandlePowerEvent(uint32_t event);
    int32_t DlopenLockScreenAfterTimeout(int32_t delayMs);
    int32_t DlopenReadHibernationCursor(std::string &cursor);
    int32_t DlopenAdjustCpuFrequency(bool isScreenOn);
    void LoadModeSwitchConfig();
    bool IsModeCallback(const PowerHdfMode &mode);
    int32_t InitV1_2();
    int32_t InitV1_3();
    int32_t InitV1_4();
    int32_t Init();
    int32_t ConvertRunningLockTypeForLock(PowerHdfRunningLockType type, PowerHdfLockType &lockType);
    int32_t ConvertRunningLockTypeForUnlock(PowerHdfRunningLockType type, PowerHdfLockType &lockType);
    void DumpHdfRunningLock(const RunningLockInfo &info, bool isAcquire);
    int32_t StartSuspendInner();
    int32_t StopSuspendInner();
};
} // namespace V1_4
} // namespace Power
} // namespace HDI
} // namespace OHOS

#endif // POWER_INTERFACE_IMPL_H
