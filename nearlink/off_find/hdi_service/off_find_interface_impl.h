/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#ifndef OHOS_HDI_NEARLINK_OFF_FIND_V1_0_OFF_FINDINTERFACEIMPL_H
#define OHOS_HDI_NEARLINK_OFF_FIND_V1_0_OFF_FINDINTERFACEIMPL_H

#include "v1_0/ioff_find_interface.h"
#include "v1_0/ioff_find_callback.h"
#include "remote_death_recipient.h"
#include "ffrt_inner.h"

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace OffFind {
namespace V1_0 {
class OffFindInterfaceImpl : public OHOS::HDI::Nearlink::OffFind::V1_0::IOffFindInterface {
public:
    OffFindInterfaceImpl();
    virtual ~OffFindInterfaceImpl();

    int32_t SetReservedPower() override;
    int32_t EnableOffFind(const sptr<OHOS::HDI::Nearlink::OffFind::V1_0::IOffFindCallback>& callbackObj,
    const std::vector<OHOS::HDI::Nearlink::OffFind::V1_0::OffFindParam>& data,
    const OHOS::HDI::Nearlink::OffFind::V1_0::OffFindExtraInfo& info) override;

    int32_t DisableOffFind() override;

private:
    void OnRemoteDied(const wptr<IRemoteObject> &object);
    sptr<IOffFindCallback> callbacks_ = nullptr;
    sptr<RemoteDeathRecipient> remoteDeathRecipient_ = nullptr;
    int32_t AddHciDeathRecipient(const sptr<IOffFindCallback>& callbackObj);
    int32_t RemoveHciDeathRecipient(const sptr<IOffFindCallback>& callbackObj);
    std::shared_ptr<ffrt::queue> eventQueue_ = nullptr;
};
} // V1_0
} // OffFind
} // Nearlink
} // HDI
} // OHOS

#endif // OHOS_HDI_NEARLINK_OFF_FIND_V1_0_OffFindInterfaceImplE_H