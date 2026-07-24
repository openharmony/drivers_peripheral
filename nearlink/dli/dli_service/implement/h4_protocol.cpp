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
#include <dlfcn.h>
#include "nearlink_hdf_log.h"
#include "h4_protocol.h"
#include <unistd.h>
#include "sle_hal_constant.h"

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace Dli {
constexpr const char *SLE_MAC_LIB = "libnearlink_mac.z.so";
constexpr const char *SET_VIP_PRIO = "SetVipPrio";
constexpr int NEARLINK_HOST_PRIORITY = 10;

thread_local bool H4Protocol::isThreadPromoted = false;

H4Protocol::H4Protocol(
    int fd, DliDataCallback onAcbReceive, DliDataCallback onIcbReceive, DliDataCallback onEventReceive)
    : dliFd_(fd), onAcbReceive_(onAcbReceive), onIcbReceive_(onIcbReceive), onEventReceive_(onEventReceive)
{}

ssize_t H4Protocol::SendPacket(const std::vector<uint8_t> &packetData)
{
    SetRTSchedule();
    ssize_t writtenNumber = 0;
    ssize_t ret = 0;
    do {
        ret = Write(dliFd_, packetData.data() + writtenNumber, packetData.size() - writtenNumber);
        if (ret > 0) {
            writtenNumber += ret;
        } else if (ret < 0) {
            return ret;
        }
    } while (static_cast<size_t>(writtenNumber) != packetData.size());
    return writtenNumber;
}

static bool ReadLengthCheck(ssize_t readLen, char *buf, int fd)
{
    const int bufsize = 256;
    if (readLen < 0) {
        strerror_r(errno, buf, bufsize);
        HDF_LOGE("read fd[%{public}d] fail", fd);
        return false;
    } else if (readLen == 0) {
        HDF_LOGE("read fd[%{public}d] readLen = 0.", fd);
        return false;
    }
    return true;
}

void H4Protocol::ReadData(int fd)
{
    SetRTSchedule();
    const int bufsize = 256;
    char buf[bufsize] = {0};
    static uint8_t typeNo{0};
    ssize_t readLen = 0;
    if (dliPacket_.size() == 0) {
        readLen = Read(fd, &packetType_, sizeof(packetType_));
        NL_HDF_CHECK_RETURN(readLen > 0, "read fd[%{public}d], readLen[%{public}zd]", fd, readLen);
        typeNo = (packetType_) & 0x0F;
        if (packetType_ > DLI_PACKET_TYPE_UNKNOWN && packetType_ < DLI_PACKET_TYPE_MAX) {
            dliPacket_.resize(header_[typeNo].headerSize);
        }
    } else if (dliPacket_.size() == header_[typeNo].headerSize) {
        readLen = Read(fd, dliPacket_.data() + readLength_, dliPacket_.size() - readLength_);
        NL_HDF_CHECK_RETURN(ReadLengthCheck(readLen, buf, fd),
            "hciPacket size[%{public}zu], readLength[%{public}u]", dliPacket_.size(), readLength_);
        readLength_ += readLen;
        if (readLength_ == dliPacket_.size()) {
            size_t dataLen = 0;
            for (int ii = 0; ii < header_[typeNo].dataLengthSize; ii++) {
                dataLen += (dliPacket_[header_[typeNo].dataLengthOffset + ii] << (ii * 0x08));
            }
            if (dataLen == 0) {
                HDF_LOGE("dataLen == 0, proc data error.");
                dliPacket_.clear();
                readLength_ = 0;
                typeNo = 0;
            } else {
                dliPacket_.resize(dliPacket_.size() + dataLen);
            }
        }
    } else {
        readLen = Read(fd, dliPacket_.data() + readLength_, dliPacket_.size() - readLength_);
        NL_HDF_CHECK_RETURN(ReadLengthCheck(readLen, buf, fd),
            "hciPacket size[%{public}zu], readLength[%{public}u]", dliPacket_.size(), readLength_);
        readLength_ += readLen;
        if (readLength_ == dliPacket_.size()) {
            PacketCallback();
            dliPacket_.clear();
            readLength_ = 0;
            typeNo = 0;
        }
    }
}

H4Protocol::~H4Protocol() {}

void H4Protocol::PacketCallback()
{
    switch (packetType_) {
        case DLI_PACKET_TYPE_SLE_ACB_DATA:
            if (onAcbReceive_) {
                onAcbReceive_(dliPacket_);
            }
            break;
        case DLI_PACKET_TYPE_SLE_ICB_DATA:
            if (onIcbReceive_) {
                onIcbReceive_(dliPacket_);
            }
            break;
        case DLI_PACKET_TYPE_SLE_EVENT:
            if (onEventReceive_) {
                onEventReceive_(dliPacket_);
            }
            break;
        default:
            HDF_LOGE("PacketCallback type[%{public}d] error.", packetType_);
            break;
    }
}

bool SetVipPrio(unsigned int vipPrio)
{
    void *libMac = dlopen(SLE_MAC_LIB, RTLD_LAZY);
    if (libMac == nullptr) {
        HDF_LOGI("SetVipPrio no mac lib ready for dlopen");
        return false;
    }
    using GetMacFun = bool (*)(unsigned int);
    GetMacFun setVipPrio = reinterpret_cast<GetMacFun>(dlsym(libMac, SET_VIP_PRIO));
    if (setVipPrio == nullptr) {
        HDF_LOGE("SetVipPrio dlsym error");
        dlclose(libMac);
        return false;
    }
    bool result = false;
    result = setVipPrio(vipPrio);
    dlclose(libMac);
    return result;
}

void H4Protocol::SetRTSchedule()
{
    if (isThreadPromoted) {
        return;
    }
    SetVipPrio(NEARLINK_HOST_PRIORITY);
    pid_t tid = gettid();
    struct sched_param rtParams = {.sched_priority = SLE_THREAD_PRIORITY};
    int rc = sched_setscheduler(tid, SCHED_FIFO, &rtParams);
    isThreadPromoted = (rc != 0) ? false : true;
}
}  // namespace Dli
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS