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

#ifndef OHOS_HDI_POWER_V1_3_POWERINTERFACEIMPL_H
#define OHOS_HDI_POWER_V1_3_POWERINTERFACEIMPL_H

#include <functional>

#include "iremote_object.h"
#include "refbase.h"
#include "v1_3/ipower_interface.h"
#include "v1_3/running_lock_types.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_3 {
class PowerInterfaceImpl : public IPowerInterface {
public:
    ~PowerInterfaceImpl() override {};

    int32_t Init();

    int32_t RegisterCallback(const sptr<IPowerHdiCallback> &ipowerHdiCallback) override;

    int32_t RegisterRunningLockCallback(const sptr<IPowerRunningLockCallback>
        &iPowerRunningLockCallback) override;

    int32_t UnRegisterRunningLockCallback() override;

    int32_t SetSuspendTag(const std::string &tag) override;

    int32_t StartSuspend() override;

    int32_t StopSuspend() override;

    int32_t ForceSuspend() override;

    int32_t Hibernate() override;

    int32_t SuspendBlock(const std::string &name) override;

    int32_t SuspendUnblock(const std::string &name) override;

    int32_t PowerDump(std::string &info) override;

    int32_t HoldRunningLock(const RunningLockInfo &info) override;

    int32_t UnholdRunningLock(const RunningLockInfo &info) override;

    int32_t HoldRunningLockExt(const RunningLockInfo &info,
        uint64_t lockid, const std::string &bundleName) override;

    int32_t UnholdRunningLockExt(const RunningLockInfo &info,
        uint64_t lockid, const std::string &bundleName) override;

    int32_t GetWakeupReason(std::string &reason) override;

    int32_t SetPowerConfig(const std::string &sceneName, const std::string &value) override;

    int32_t GetPowerConfig(const std::string &sceneName, std::string &value) override;

    class PowerDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit PowerDeathRecipient(const wptr<PowerInterfaceImpl> &powerInterfaceImpl)
            : powerInterfaceImpl_(powerInterfaceImpl) {};
        ~PowerDeathRecipient() override {};
        void OnRemoteDied(const wptr<IRemoteObject> &object) override;

    private:
        wptr<PowerInterfaceImpl> powerInterfaceImpl_;
    };

private:
    int32_t UnRegister();
    int32_t AddPowerDeathRecipient(const sptr<IPowerHdiCallback> &callback);
    int32_t RemovePowerDeathRecipient(const sptr<IPowerHdiCallback> &callback);
};
} // namespace V1_3
} // namespace Power
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_POWER_V1_3_POWERINTERFACEIMPL_H
