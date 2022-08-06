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

#ifndef OHOS_HDI_BLUETOOTH_HCI_V1_0_HCIINTERFACEIMPL_H
#define OHOS_HDI_BLUETOOTH_HCI_V1_0_HCIINTERFACEIMPL_H

#include "v1_0/ihci_interface.h"
#include "v1_0/ihci_callback.h"
#include "remote_death_recipient.h"

namespace OHOS {
namespace HDI {
namespace Bluetooth {
namespace Hci {
namespace V1_0 {
class HciInterfaceImpl : public IHciInterface {
public:
    HciInterfaceImpl();
    virtual ~HciInterfaceImpl();

    int32_t Init(const sptr<IHciCallback>& callbackObj) override;

    int32_t SendHciPacket(BtType type, const std::vector<uint8_t>& data) override;

    int32_t Close() override;
private:
    void OnRemoteDied(const wptr<IRemoteObject> &object);
    sptr<IHciCallback> callbacks_ = nullptr;
    sptr<RemoteDeathRecipient> remoteDeathRecipient_ = nullptr;
    int32_t AddHciDeathRecipient(const sptr<IHciCallback>& callbackObj);
    int32_t RemoveHciDeathRecipient(const sptr<IHciCallback>& callbackObj);
};
} // V1_0
} // Hci
} // Bluetooth
} // HDI
} // OHOS

#endif // OHOS_HDI_BLUETOOTH_HCI_V1_0_HCIINTERFACEIMPL_H