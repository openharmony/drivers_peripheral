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

#include "h4_protocol.h"

#include <cerrno>
#include <cstring>

#include <hdf_log.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD000105

namespace OHOS {
namespace HDI {
namespace Bluetooth {
namespace Hci {
const int32_t RT_PRIORITY = 1;

H4Protocol::H4Protocol(
    int fd, HciDataCallback onAclReceive, HciDataCallback onScoReceive, HciDataCallback onEventReceive,
    HciDataCallback onIsoReceive) : hciFd_(fd), onAclReceive_(onAclReceive), onScoReceive_(onScoReceive),
    onEventReceive_(onEventReceive), onIsoReceive_(onIsoReceive)
{}

void H4Protocol::SetRTSchedule()
{
    std::lock_guard<std::mutex> lock(tidMutex_);
    pid_t tid = gettid();
    auto it = tidMap_.find(tid);
    if (it == tidMap_.end() || !tidMap_[tid]) {
        struct sched_param rtParams = {.sched_priority = RT_PRIORITY};
        int rc = sched_setscheduler(tid, SCHED_FIFO, &rtParams);
        if (rc != 0) {
            HDF_LOGE("PacketCallback set tid fail.");
            tidMap_[tid] = false;
        } else {
            tidMap_[tid] = true;
        }
    }
}

ssize_t H4Protocol::SendPacket(HciPacketType packetType, const std::vector<uint8_t> &packetData)
{
    SetRTSchedule();
    uint8_t type = packetType;
    ssize_t writtenNumber = 0;

    ssize_t ret = Write(hciFd_, &type, sizeof(type));
    if (ret != sizeof(type)) {
        return 0;
    } else {
        do {
            ret = Write(hciFd_, packetData.data() + writtenNumber, packetData.size() - writtenNumber);
            if (ret > 0) {
                writtenNumber += ret;
            } else if (ret < 0) {
                return ret;
            }
        } while (static_cast<size_t>(writtenNumber) != packetData.size());
    }

    return writtenNumber;
}

void H4Protocol::ReadData(int fd)
{
    const int bufsize = 256;
    char buf[bufsize] = {0};
    ssize_t readLen;
    if (hciPacket_.size() == 0) {
        readLen = Read(fd, &packetType_, sizeof(packetType_));
        if (readLen < 0) {
            HDF_LOGE("read fd[%d]", fd);
            return;
        } else if (readLen == 0) {
            HDF_LOGE("read fd[%d] readLen = 0.", fd);
            return;
        }

        if (packetType_ > HCI_PACKET_TYPE_UNKNOWN && packetType_ < HCI_PACKET_TYPE_MAX) {
            hciPacket_.resize(header_[packetType_].headerSize);
        }
    } else if (hciPacket_.size() == header_[packetType_].headerSize) {
        readLen = Read(fd, hciPacket_.data() + readLength_, hciPacket_.size() - readLength_);
        if (readLen < 0) {
            strerror_r(errno, buf, sizeof(buf));
            HDF_LOGE("read fd[%d] err:%s", fd, buf);
            return;
        } else if (readLen == 0) {
            HDF_LOGE("read fd[%d] readLen = 0.", fd);
            return;
        }

        readLength_ += readLen;
        if (readLength_ == hciPacket_.size()) {
            size_t dataLen = 0;
            for (int ii = 0; ii < header_[packetType_].dataLengthSize; ii++) {
                dataLen += (hciPacket_[header_[packetType_].dataLengthOffset + ii] << (ii * 0x08));
            }
            hciPacket_.resize(hciPacket_.size() + dataLen);
        }
    } else {
        readLen = Read(fd, hciPacket_.data() + readLength_, hciPacket_.size() - readLength_);
        if (readLen < 0) {
            strerror_r(errno, buf, sizeof(buf));
            HDF_LOGE("read fd[%d] err:%s", fd, buf);
            return;
        } else if (readLen == 0) {
            HDF_LOGE("read fd[%d] readLen = 0.", fd);
            return;
        }

        readLength_ += readLen;
        if (readLength_ == hciPacket_.size()) {
            PacketCallback();
            hciPacket_.clear();
            readLength_ = 0;
        }
    }
}

H4Protocol::~H4Protocol() {}

void H4Protocol::PacketCallback()
{
    SetRTSchedule();
    switch (packetType_) {
        case HCI_PACKET_TYPE_ACL_DATA:
            if (onAclReceive_) {
                onAclReceive_(hciPacket_);
            }
            break;
        case HCI_PACKET_TYPE_SCO_DATA:
            if (onScoReceive_) {
                onScoReceive_(hciPacket_);
            }
            break;
        case HCI_PACKET_TYPE_EVENT:
            if (onEventReceive_) {
                onEventReceive_(hciPacket_);
            }
            break;
        case HCI_PACKET_TYPE_ISO_DATA:
            if (onIsoReceive_) {
                onIsoReceive_(hciPacket_);
            }
            break;
        default:
            HDF_LOGE("PacketCallback type[%{public}d] error.", packetType_);
            break;
    }
}
}  // namespace Hci
}  // namespace Bluetooth
}  // namespace HDI
}  // namespace OHOS