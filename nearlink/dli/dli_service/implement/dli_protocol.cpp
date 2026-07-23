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


#include <cerrno>
#include <cstring>
#include <unistd.h>
#include "nearlink_hdf_log.h"
#include "dli_protocol.h"
namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace Dli {
const PacketHeader DliProtocol::header_[DLI_PACKET_TYPE_MAX] = {
    {.headerSize = 0, .dataLengthOffset = 0, .dataLengthSize = 0}, /* 0 */
    {.headerSize = 4, .dataLengthOffset = 2, .dataLengthSize = 2}, /* 1 */
    {.headerSize = 4, .dataLengthOffset = 2, .dataLengthSize = 2}, /* 2 */
    {.headerSize = 4, .dataLengthOffset = 2, .dataLengthSize = 2}, /* 3 */
    {.headerSize = 4, .dataLengthOffset = 2, .dataLengthSize = 2}, /* 4 */
};

const PacketHeader &DliProtocol::GetPacketHeaderInfo(DliPacketType packetType)
{
    if (packetType >= DLI_PACKET_TYPE_MAX) {
        return header_[DLI_PACKET_TYPE_UNKNOWN];
    }
    return header_[DliProtocol::TypeConvert(packetType)];
}

ssize_t DliProtocol::Read(int fd, uint8_t *data, size_t length)
{
    const int bufsize = 256;
    char buf[bufsize] = {0};
    ssize_t ret = TEMP_FAILURE_RETRY(read(fd, data, length));
    if (ret == -1) {
        strerror_r(errno, buf, sizeof(buf));
        HDF_LOGE("read failed");
        ret = 0;
    }
    return ret;
}

ssize_t DliProtocol::Write(int fd, const uint8_t *data, size_t length)
{
    const int bufsize = 256;
    char buf[bufsize] = {0};
    ssize_t ret = 0;
    do {
        ret = TEMP_FAILURE_RETRY(write(fd, data, length));
    } while (ret == -1 && errno == EAGAIN);

    if (ret == -1) {
        strerror_r(errno, buf, sizeof(buf));
        HDF_LOGE("write failed");
    } else if (static_cast<size_t>(ret) != length) {
        HDF_LOGE("write data %{public}zd less than %{public}zu.", ret, length);
    }
    return ret;
}

uint8_t DliProtocol::TypeConvert(DliPacketType packetType)
{
    switch (packetType) {
        case DLI_PACKET_TYPE_SLE_EVENT:
            return static_cast<uint8_t>(DLI_PACKET_TYPE_SLE_EVENT) & 0x0F;
        default:
            HDF_LOGE("type convert error.");
            return 0;
    }
}
}  // namespace Dli
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS