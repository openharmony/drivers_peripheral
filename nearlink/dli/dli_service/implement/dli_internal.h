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

#ifndef OHOS_HDI_NEARLINK_DLI_INTERNAL_H
#define OHOS_HDI_NEARLINK_DLI_INTERNAL_H

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace Dli {
typedef enum {
    DLI_PACKET_TYPE_UNKNOWN = 0,
    DLI_PACKET_TYPE_SLE_CMD = 0xA1,
    DLI_PACKET_TYPE_SLE_EVENT = 0xA2,
    DLI_PACKET_TYPE_SLE_ACB_DATA = 0xA3,
    DLI_PACKET_TYPE_SLE_ICB_DATA = 0xA4,
    DLI_PACKET_TYPE_MAX,
} DliPacketType;

struct PacketHeader {
    uint8_t headerSize;
    uint8_t dataLengthOffset;
    uint8_t dataLengthSize;
};

// opcode (DLI_SLE_Cmd_Complete_Evt opcode)
const uint16_t SLE_DLI_COMMAND_COMPLETE_EVENT = 0x0002;
}  // namespace Dli
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS
#endif /* OHOS_HDI_NEARLINK_DLI_INTERNAL_H */