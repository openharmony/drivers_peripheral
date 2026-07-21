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
#ifndef OHOS_HDI_NEARLINK_DLI_V1_1_SLEDLIINTERFACEIMPL_H
#define OHOS_HDI_NEARLINK_DLI_V1_1_SLEDLIINTERFACEIMPL_H

#include "v1_1/isle_hci_interface.h"
#include "v1_0/isle_hci_callback.h"
#include "remote_death_recipient.h"

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace Hci {
namespace V1_1 {
    using namespace OHOS::HDI::Nearlink::Dli::V1_1;
class SleHciInterfaceImpl : public OHOS::HDI::Nearlink::Hci::V1_1::ISleHciInterface {
public:
    SleHciInterfaceImpl();
    virtual ~SleHciInterfaceImpl();

    int32_t SleHalInit(const sptr<OHOS::HDI::Nearlink::Hci::V1_0::ISleHciCallback>& callbackObj) override;

    int32_t SleSendHciPacket(const std::vector<uint8_t>& data) override;

    int32_t Close() override;

    int32_t CheckOnBoardState(bool& result) override;
private:
    void OnRemoteDied(const wptr<IRemoteObject> &object);
    sptr<ISleHciCallback> callbacks_ = nullptr;
    sptr<RemoteDeathRecipient> remoteDeathRecipient_ = nullptr;
    int32_t AddDliDeathRecipient(const sptr<ISleHciCallback>& callbackObj);
    int32_t RemoveDliDeathRecipient(const sptr<ISleHciCallback>& callbackObj);
    void SetRTSchedule();
    std::mutex dliCallbackMutex_;
    thread_local static bool isThreadPromoted;
};
} // V1_1
} // Hci
} // Nearlink
} // HDI
} // OHOS

#endif // OHOS_HDI_NEARLINK_DLI_V1_1_SleHciInterfaceImplE_H