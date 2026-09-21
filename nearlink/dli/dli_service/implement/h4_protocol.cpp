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
#include <mutex>
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

namespace {
using SetVipPrioFun = bool (*)(unsigned int);

class MacLibAdapter {
public:
    static MacLibAdapter &GetInstance()
    {
        static MacLibAdapter instance;
        return instance;
    }

    bool Init()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (macHandle_ != nullptr) {
            HDF_LOGI("%{public}s already opened", SLE_MAC_LIB);
            return true;
        }
        macHandle_ = dlopen(SLE_MAC_LIB, RTLD_NOW);
        if (macHandle_ == nullptr) {
            HDF_LOGE("dlopen %{public}s faild", SLE_MAC_LIB);
            return false;
        }
        setVipPrio_ = reinterpret_cast<SetVipPrio>(dlsym(macHandle_, SET_VIP_PRIO));
        if (setVipPrio_ == nullptr) {
            HDF_LOGE("MacLibAdapter dlsym %{public}s failed", SET_VIP_PRIO);
            dlclose(macHandle_);
            macHandle_ = nullptr;
            return false;
        }
        return true;
    }

    bool SetVipPrio(unsigned int vipPrio)
    {
        if (setVipPrio_ == nullptr) {
            HDF_LOGE("setVipPrio_ is nullptr");
            return false;
        }
        return setVipPrio_(vipPrio);
    }

private:
    MacLibAdapter() = default;
    ~MacLibAdapter()
    {
        CleanUp();
    }

    void CleanUp()
    {
        if (macHandle_ == nullptr) {
            return;
        }
        setVipPrio_ = nullptr;
        dlclose(macHandle_);
        macHandle_ = nullptr;
    }

    std::mutex mutex_;
    void *macHandle_ = nullptr;
    SetVipPrioFun = setVipPrio_ = nullptr;
};
}

thread_local bool H4Protocol::isThreadPromoted = false;

H4Protocol::H4Protocol(
    int fd, DliDataCallback onAcbReceive, DliDataCallback onIcbReceive, DliDataCallback onEventReceive)
    : dliFd_(fd), onAcbReceive_(onAcbReceive), onIcbReceive_(onIcbReceive), onEventReceive_(onEventReceive)
{
    MacLibAdapter::GetInstance().Init();
}

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
    MacLibAdapter &macLibAdapter = MacLibAdapter::GetInstance();
    if (!macLibAdapter.Init()) {
        return false
    } 
    return macLibAdapter.SetVipPrio(vipPrio);
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