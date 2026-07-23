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

#ifndef OHOS_HDI_NEARLINK_DLI_PROTOCOL_H
#define OHOS_HDI_NEARLINK_DLI_PROTOCOL_H

#include <cstdio>
#include <vector>

#include <functional>
#include "dli_internal.h"

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace OffFind {
class DliProtocol {
public:
    using DliDataCallback = std::function<void(const std::vector<uint8_t> &data)>;

    DliProtocol() = default;
    virtual ~DliProtocol() = default;

    virtual ssize_t SendPacket(const std::vector<uint8_t> &packetData) = 0;

    const PacketHeader& GetPacketHeaderInfo(DliPacketType packetType);

protected:
    static ssize_t Read(int fd, uint8_t *data, size_t length);
    static ssize_t Write(int fd, const uint8_t *data, size_t length);
    static uint8_t TypeConvert(DliPacketType packetType);
    static const PacketHeader header_[DLI_PACKET_TYPE_MAX];
};
}  // namespace OffFind
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS
#endif /* OHOS_HDI_NEARLINK_DLI_PROTOCOL_H */