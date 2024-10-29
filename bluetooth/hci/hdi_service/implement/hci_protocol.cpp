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

#include "hci_protocol.h"

#include <cerrno>
#include <cstring>

#include <unistd.h>

#include <hdf_log.h>

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD000105

namespace OHOS {
namespace HDI {
namespace Bluetooth {
namespace Hci {
const PacketHeader HciProtocol::header_[HCI_PACKET_TYPE_MAX] = {
    {.headerSize = 0, .dataLengthOffset = 0, .dataLengthSize = 0}, /* HCI_PACKET_TYPE_UNKNOWN */
    {.headerSize = 3, .dataLengthOffset = 2, .dataLengthSize = 1}, /* HCI_PACKET_TYPE_COMMAND */
    {.headerSize = 4, .dataLengthOffset = 2, .dataLengthSize = 2}, /* HCI_PACKET_TYPE_ACL_DATA */
    {.headerSize = 3, .dataLengthOffset = 2, .dataLengthSize = 1}, /* HCI_PACKET_TYPE_SCO_DATA */
    {.headerSize = 2, .dataLengthOffset = 1, .dataLengthSize = 1}, /* HCI_PACKET_TYPE_EVENT */
    {.headerSize = 4, .dataLengthOffset = 2, .dataLengthSize = 2}, /* HCI_PACKET_TYPE_ISO_DATA */
};

const PacketHeader &HciProtocol::GetPacketHeaderInfo(HciPacketType packetType)
{
    if (packetType >= HCI_PACKET_TYPE_MAX) {
        return header_[HCI_PACKET_TYPE_UNKNOWN];
    }
    return header_[packetType];
}

ssize_t HciProtocol::Read(int fd, uint8_t *data, size_t length)
{
    const int bufsize = 256;
    char buf[bufsize] = {0};
    ssize_t ret = TEMP_FAILURE_RETRY(read(fd, data, length));
    if (ret == -1) {
        strerror_r(errno, buf, sizeof(buf));
        HDF_LOGE("read failed err:%s", buf);
        ret = 0;
    }
    return ret;
}

ssize_t HciProtocol::Write(int fd, const uint8_t *data, size_t length)
{
    const int bufsize = 256;
    char buf[bufsize] = {0};
    ssize_t ret = 0;
    do {
        ret = TEMP_FAILURE_RETRY(write(fd, data, length));
    } while (ret == -1 && errno == EAGAIN);

    if (ret == -1) {
        strerror_r(errno, buf, sizeof(buf));
        HDF_LOGE("write failed err:%s", buf);
    } else if (static_cast<size_t>(ret) != length) {
        HDF_LOGE("write data %zd less than %zu.", ret, length);
    }
    return ret;
}
}  // namespace Hci
}  // namespace Bluetooth
}  // namespace HDI
}  // namespace OHOS