/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_BLUETOOTH_HCI_H4_PROTOCOL_H
#define OHOS_HDI_BLUETOOTH_HCI_H4_PROTOCOL_H

#include "hci_protocol.h"

namespace OHOS {
namespace HDI {
namespace Bluetooth {
namespace Hci {
class H4Protocol : public HciProtocol {
public:
    H4Protocol(int fd, HciDataCallback onAclReceive, HciDataCallback onScoReceive, HciDataCallback onEventReceive,
        HciDataCallback onIsoReceive);

    ssize_t SendPacket(HciPacketType packetType, const std::vector<uint8_t> &packetData) override;
    void ReadData(int fd);
    ~H4Protocol() override;

private:
    void PacketCallback();

private:
    int hciFd_ = 0;
    HciDataCallback onAclReceive_;
    HciDataCallback onScoReceive_;
    HciDataCallback onEventReceive_;
    HciDataCallback onIsoReceive_

    uint8_t packetType_ = 0;
    std::vector<uint8_t> hciPacket_;
    uint32_t readLength_ = 0;
};
}  // namespace Hci
}  // namespace Bluetooth
}  // namespace HDI
}  // namespace OHOS

#endif /* OHOS_HDI_BLUETOOTH_HCI_H4_PROTOCOL_H */