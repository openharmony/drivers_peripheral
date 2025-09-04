/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "iface_tool.h"
#include <cstring>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_bridge.h>
#include <linux/if.h>
#include <unistd.h>
#include <hdf_log.h>
#include "unique_fd.h"
#include "securec.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V2_0 {
const char K_WLAN0_INTERFACE_NAME[] = "wlan0";
const int MAC_LEN = 6;
const int MAC_POS_1 = 1;
const int MAC_POS_2 = 2;
const int MAC_POS_3 = 3;
const int MAC_POS_4 = 4;
const int MAC_POS_5 = 5;

bool GetIfState(const char* ifName, int sock, struct ifreq* ifr)
{
    if (memset_s(ifr, sizeof(*ifr), 0, sizeof(*ifr)) != EOK) {
        HDF_LOGE("memset_s failed");
        return false;
    }
    if (strlcpy(ifr->ifr_name, ifName, sizeof(ifr->ifr_name)) >=
        sizeof(ifr->ifr_name)) {
        HDF_LOGE("Interface name is too long: %{public}s", ifName);
        return false;
    }
    if (TEMP_FAILURE_RETRY(ioctl(sock, SIOCGIFFLAGS, ifr)) != 0) {
        HDF_LOGE("Could not read interface state for %{public}s, %{public}s", ifName, strerror(errno));
        return false;
    }
    return true;
}

bool IfaceTool::GetUpState(const char* ifName)
{
    UniqueFd sock(socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (sock.Get() < 0) {
        HDF_LOGE("Failed to open socket to set up/down state %{public}s", strerror(errno));
        return false;
    }
    struct ifreq ifr;
    if (!GetIfState(ifName, sock.Get(), &ifr)) {
        return false;
    }
    return ifr.ifr_flags & IFF_UP;
}

bool IfaceTool::SetUpState(const char* ifName, bool requestUp)
{
    UniqueFd sock(socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (sock.Get() < 0) {
        HDF_LOGE("Failed to open socket to set up/down state %{public}s", strerror(errno));
        return false;
    }
    struct ifreq ifr;
    if (!GetIfState(ifName, sock.Get(), &ifr)) {
        return false;
    }
    const bool currentlyUp = ifr.ifr_flags & IFF_UP;
    if (currentlyUp == requestUp) {
        return true;
    }
    if (requestUp) {
        ifr.ifr_flags |= IFF_UP;
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }
    if (TEMP_FAILURE_RETRY(ioctl(sock.Get(), SIOCSIFFLAGS, &ifr)) != 0) {
        HDF_LOGE("Could not set interface flags for %{public}s, %{public}s", ifName, strerror(errno));
        return false;
    }
    return true;
}

bool IfaceTool::SetWifiUpState(bool requestUp)
{
    return SetUpState(K_WLAN0_INTERFACE_NAME, requestUp);
}

bool IfaceTool::SetMacAddress(const char* ifName, const char* mac)
{
    struct ifreq ifr;

    unsigned char macBin[MAC_LEN];
    if (sscanf_s(mac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
        &macBin[0], &macBin[MAC_POS_1], &macBin[MAC_POS_2],
        &macBin[MAC_POS_3], &macBin[MAC_POS_4], &macBin[MAC_POS_5]) == EOF) {
        return false;
    }
    UniqueFd sock(socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (sock.Get() < 0) {
        HDF_LOGE("Failed to open socket to set MAC address %{public}s", strerror(errno));
        return false;
    }
    if (!GetIfState(ifName, sock.Get(), &ifr)) {
        return false;
    }
    if (memset_s(&ifr.ifr_hwaddr, sizeof(ifr.ifr_hwaddr), 0, sizeof(ifr.ifr_hwaddr)) < 0) {
        HDF_LOGE("Failed to memset");
    }
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    if (memcpy_s(ifr.ifr_hwaddr.sa_data, MAC_LEN, macBin, MAC_LEN) < 0) {
        HDF_LOGE("Failed to memcpy");
    }
    if (TEMP_FAILURE_RETRY(ioctl(sock.Get(), SIOCSIFHWADDR, &ifr)) != 0) {
        HDF_LOGE("Failed to set interface MAC address for %{public}s, %{public}s",
            ifName, strerror(errno));
        return false;
    }
    return true;
}
}
}
}
}
}