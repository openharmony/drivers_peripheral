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

#ifndef OHOS_HDI_RIL_V1_0_RIL_INTERFACE_IMPL_H
#define OHOS_HDI_RIL_V1_0_RIL_INTERFACE_IMPL_H

#include <hdf_log.h>
#include <iproxy_broker.h>
#include <iremote_object.h>

#include "hril_manager.h"
#include "v1_0/iril_interface.h"
#include "vector"

namespace OHOS {
namespace HDI {
namespace Ril {
namespace V1_0 {
class RilInterfaceImpl : public IRilInterface {
public:
    RilInterfaceImpl() = default;
    virtual ~RilInterfaceImpl() = default;

    int32_t SetEmergencyCallList(
        int32_t slotId, int32_t serialId, const IEmergencyInfoList &emergencyInfoList) override;
    int32_t GetEmergencyCallList(int32_t slotId, int32_t serialId) override;

    int32_t ActivatePdpContext(int32_t slotId, int32_t serialId, const IDataCallInfo &dataCallInfo) override;
    int32_t DeactivatePdpContext(int32_t slotId, int32_t serialId, const IUniInfo &uniInfo) override;
    int32_t GetPdpContextList(int32_t slotId, int32_t serialId, const IUniInfo &uniInfo) override;
    int32_t SetInitApnInfo(int32_t slotId, int32_t serialId, const IDataProfileDataInfo &dataProfileDataInfo) override;
    int32_t GetLinkBandwidthInfo(int32_t slotId, int32_t serialId, int32_t cid) override;
    int32_t SetLinkBandwidthReportingRule(int32_t slotId, int32_t serialId,
        const IDataLinkBandwidthReportingRule &dataLinkBandwidthReportingRule) override;
    int32_t SetDataPermitted(int32_t slotId, int32_t serialId, int32_t dataPermitted) override;
    int32_t SetDataProfileInfo(int32_t slotId, int32_t serialId, const IDataProfilesInfo &dataProfilesInfo) override;

    int32_t SetCallback(const sptr<IRilCallback> &rilCallback) override;
    int32_t Init();
    class RilDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit RilDeathRecipient(const wptr<RilInterfaceImpl> &rilInterfaceImpl) : rilInterfaceImpl_(rilInterfaceImpl)
        {}
        virtual ~RilDeathRecipient() = default;
        virtual void OnRemoteDied(const wptr<IRemoteObject> &object) override;

    private:
        wptr<RilInterfaceImpl> rilInterfaceImpl_;
    };
    template<typename FuncType, typename... ParamTypes>
    inline int32_t TaskSchedule(FuncType &&_func, ParamTypes &&... _args) const
    {
        if (_func == nullptr || Telephony::HRilManager::manager_ == nullptr) {
            HDF_LOGE("manager or func is null pointer");
            return HRIL_ERR_NULL_POINT;
        }
        auto ret = (Telephony::HRilManager::manager_.get()->*(_func))(std::forward<ParamTypes>(_args)...);
        return ret;
    }

private:
    int32_t UnRegister();
    int32_t AddRilDeathRecipient(const sptr<IRilCallback> &callback);
    int32_t RemoveRilDeathRecipient(const sptr<IRilCallback> &callback);
};
} // namespace V1_0
} // namespace Ril
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_RIL_V1_0_RILIMPL_H