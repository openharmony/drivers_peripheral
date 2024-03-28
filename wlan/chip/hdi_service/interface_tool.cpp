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

#include "interface_tool.h"
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
namespace V1_0 {
const char K_WLAN0_INTERFACE_NAME[] = "wlan0";

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
}
}
}
}
}