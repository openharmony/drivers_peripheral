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
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include "securec.h"
#include "dli_internal.h"
#include "nearlink_hdf_log.h"
#include "sle_address.h"
namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace Dli {
namespace {
constexpr int ADDRESS_STR_LEN = 17;
constexpr int ADDRESS_SIZE = 6;
constexpr const char *SLE_MAC_LIB = "libnearlink_mac.z.so";
constexpr const char *GET_SLE_MAC_SYMBOL_NAME = "GetConstantMac";
}  // namespace

SleAddress::SleAddress()
{
    address_.resize(ADDRESS_SIZE);
}

constexpr int START_POS = 6;
constexpr int END_POS = 13;
constexpr int ADDR_BYTE = 18;
std::string SleAddress::GetEncryptAddr(std::string addr)
{
    if (addr.empty() || addr.length() != ADDRESS_STR_LEN) {
        HDF_LOGE("addr is invalid, length= %{public}zu", addr.length());
        return std::string("");
    }
    std::string tmp = "**:**:**:**:**:**";
    std::string out = addr;
    for (int i = START_POS; i <= END_POS; i++) {
        out[i] = tmp[i];
    }
    return out;
}

void SleAddress::ParseAddressToString(std::vector<uint8_t> &address, std::string &outString)
{
    char temp[ADDR_BYTE] = {0};
    int ret = sprintf_s(temp, sizeof(temp), "%02X:%02X:%02X:%02X:%02X:%02X",
        address[0], address[1], address[2], address[3], address[4], address[5]);
    if (ret == -1) {
        HDF_LOGE("ConvertAddr sprintf_s return error, ret -1");
    }
    outString = temp;
}

int SleAddress::ParseAddressFromString(const std::string &string) const
{
    size_t offset = 0;
    int bytesIndex = 0;
    int readCount = 0;
    for (bytesIndex = 0; bytesIndex < ADDRESS_SIZE && offset < string.size(); bytesIndex++) {
        readCount = 0;
        if (sscanf_s(&string[offset], "%02hhx:%n", &address_[bytesIndex], &readCount) > 0) {
            if (readCount == 0 && bytesIndex != ADDRESS_SIZE - 1) {
                return bytesIndex;
            }
            offset += static_cast<uint32_t>(readCount);
        } else {
            break;
        }
    }

    return bytesIndex;
}

bool SleAddress::GetConstantAddress(char *address, int len)
{
    if (address == nullptr || len < ADDRESS_STR_LEN + 1) {
        HDF_LOGE("GetConstantAddress buf error");
        return false;
    }

    void *libMac = dlopen(SLE_MAC_LIB, RTLD_LAZY);
    if (libMac == nullptr) {
        HDF_LOGI("GetConstantAddress no mac lib ready for dlopen");
        return false;
    }

    using GetMacFun = int (*)(char*, int);
    GetMacFun getMac = reinterpret_cast<GetMacFun>(dlsym(libMac, GET_SLE_MAC_SYMBOL_NAME));
    if (getMac == nullptr) {
        HDF_LOGE("GetConstantAddress dlsym error");
        dlclose(libMac);
        return false;
    }

    int ret = getMac(address, len);
    HDF_LOGI("GetConstantAddress ret: %{public}d", ret);
    dlclose(libMac);
    return (ret == 0);
}

#ifdef RELOAD_ADDRESS
// system boot less 2min, need ReadSleAddress from NV
bool SleAddress::NeedReloadAddress()
{
    const int64_t maxNeedReloadTime = 120000; // 120s
    constexpr int64_t msPerSecond = 1000;
    constexpr int64_t nsPerMs = 1000000;
    struct timespec times = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &times) < 0) {
        HDF_LOGE("Failed clock_gettime:%{public}s, needReloadAddress:false", strerror(errno));
        return false;
    }
    int64_t relativeTime = ((times.tv_sec * msPerSecond) + (times.tv_nsec / nsPerMs));
    HDF_LOGI("relativeTime:%{public}lu", relativeTime);
    return relativeTime < maxNeedReloadTime;
}
#endif

std::shared_ptr<SleAddress> SleAddress::UpdateAddressFromNV(const std::string &path)
{
    const int bufsize = 256;
    char buf[bufsize] = {0};
    int newFd = open(path.c_str(), O_RDWR | O_CREAT, 00644);
    HDF_LOGI("GetDeviceAddress open newFd %{public}d.", newFd);
    char addressStr[ADDRESS_STR_LEN + 1] = {"00:11:22:33:44:55"};
    bool readNVSucc = GetConstantAddress(addressStr, ADDRESS_STR_LEN + 1);
    bool needUpdateTxt = true;
    if (newFd < 0) {
        auto ptr = std::make_shared<SleAddress>();
        int ret = ptr->ParseAddressFromString(addressStr);
        if (ret != ADDRESS_SIZE) {
            HDF_LOGE("UpdateAddressFromNV ParseAddressFromString failed, ret:%{public}d.", ret);
            return nullptr;
        }
        return ptr;
    }
    if (!readNVSucc) {
        // read NV fail ,if slemac.txt exsit mac, not update, needUpdateTxt = false
        if (read(newFd, addressStr, ADDRESS_STR_LEN) != ADDRESS_STR_LEN) {
            auto tmpPtr = GenerateDeviceAddress();
            std::string strAddress;
            ParseAddressToString(tmpPtr->address_, strAddress);
            HDF_LOGI("device mac addr: %{public}s", GetEncryptAddr(strAddress).c_str());
            int ret = strcpy_s(addressStr, ADDRESS_STR_LEN + 1, strAddress.c_str());
            if (ret != 0) {
                HDF_LOGE("ParseAddressToString strcpy_s err!");
            }
        } else {
            HDF_LOGI("newFd %{public}d not update", newFd);
            needUpdateTxt = false;
        }
    }
    if (needUpdateTxt) {
        int fdRet = write(newFd, addressStr, ADDRESS_STR_LEN);
        if (fdRet < 0) {
            strerror_r(errno, buf, sizeof(buf));
            HDF_LOGE("GetDeviceAddress addr write failed, err:%{public}s.", buf);
        }
    }
    close(newFd);
    auto ptr = std::make_shared<SleAddress>();
    int result = ptr->ParseAddressFromString(addressStr);
    if (result != ADDRESS_SIZE) {
        HDF_LOGE("UpdateAddressFromNV ParseAddressFromString failed, result:%{public}d.", result);
        return nullptr;
    }
    return ptr;
}

std::shared_ptr<SleAddress> SleAddress::GetDeviceAddress(const std::string &path)
{
#ifdef RELOAD_ADDRESS
    if (NeedReloadAddress()) {
        return UpdateAddressFromNV(path);
    }
#endif
    int addrFd = open(path.c_str(), O_RDONLY);
    if (addrFd < 0) {
        return UpdateAddressFromNV(path);
    }
    char addressStr[ADDRESS_STR_LEN + 1] = {0};
    if (read(addrFd, addressStr, ADDRESS_STR_LEN) != ADDRESS_STR_LEN) {
        HDF_LOGE("read %{public}s failed.", path.c_str());
        close(addrFd);
        return UpdateAddressFromNV(path);
    }
    close(addrFd);
    auto ptr = std::make_shared<SleAddress>();
    int result = ptr->ParseAddressFromString(addressStr);
    if (result != ADDRESS_SIZE) {
        HDF_LOGE("GetDeviceAddress ParseAddressFromString failed, result:%{public}d.", result);
        return UpdateAddressFromNV(path);
    }
    return ptr;
}

std::shared_ptr<SleAddress> SleAddress::GenerateDeviceAddress(const std::string &prefix)
{
    const int bufsize = 256;
    char buf[bufsize] = {0};
    auto ptr = std::make_shared<SleAddress>();
    char addressStr[ADDRESS_STR_LEN + 1] = {"00:11:22:33:44:55"};
    ptr->ParseAddressFromString(addressStr);
    int prefixCount = ptr->ParseAddressFromString(prefix);
    if (prefixCount < ADDRESS_SIZE) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            strerror_r(errno, buf, sizeof(buf));
            HDF_LOGE("open /dev/urandom failed err:%{public}s.", buf);
            return ptr;
        }
        if (read(fd, &ptr->address_[prefixCount], ADDRESS_SIZE - prefixCount) != ADDRESS_SIZE - prefixCount) {
            strerror_r(errno, buf, sizeof(buf));
            HDF_LOGE("read /dev/urandom failed err:%{public}s.", buf);
        }
        close(fd);
    }
    return ptr;
}

void SleAddress::ReadAddress(std::vector<uint8_t> &address) const
{
    address = address_;
}

void SleAddress::ReadAddress(std::string &address) const
{
    address.resize(ADDRESS_STR_LEN + 1);

    int offset = 0;
    for (int ii = 0; ii < ADDRESS_SIZE; ii++) {
        int ret = snprintf_s(
            &address[offset], (ADDRESS_STR_LEN + 1) - offset, ADDRESS_STR_LEN - offset, "%02x:", address_[ii]);
        if (ret < 0) {
            break;
        }
        offset += ret;
    }
}
}  // namespace Dli
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS