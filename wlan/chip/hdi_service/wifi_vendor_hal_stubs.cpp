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

#include "wifi_vendor_hal_stubs.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {

template <typename>
struct StubFunction;

template <typename R, typename... Args>
struct StubFunction<R (*)(Args...)> {
    static constexpr R Invoke(Args...) { return HAL_NOT_SUPPORTED; }
};
template <typename... Args>
struct StubFunction<void (*)(Args...)> {
    static constexpr void Invoke(Args...) {}
};

template <typename T>
void PopulateStubFor(T* val)
{
    *val = &StubFunction<T>::Invoke;
}

bool InitHalFuncTableWithStubs(WifiHalFn* halFn)
{
    if (halFn == nullptr) {
        return false;
    }
    PopulateStubFor(&halFn->vendorHalInit);
    PopulateStubFor(&halFn->waitDriverStart);
    PopulateStubFor(&halFn->vendorHalExit);
    PopulateStubFor(&halFn->startHalLoop);
    PopulateStubFor(&halFn->wifiGetSupportedFeatureSet);
    PopulateStubFor(&halFn->wifiGetChipFeatureSet);
    PopulateStubFor(&halFn->vendorHalGetIfaces);
    PopulateStubFor(&halFn->vendorHalGetIfName);
    PopulateStubFor(&halFn->vendorHalGetChannelsInBand);
    PopulateStubFor(&halFn->vendorHalCreateIface);
    PopulateStubFor(&halFn->vendorHalDeleteIface);
    PopulateStubFor(&halFn->vendorHalSetRestartHandler);
    PopulateStubFor(&halFn->vendorHalPreInit);
    PopulateStubFor(&halFn->triggerVendorHalRestart);
    PopulateStubFor(&halFn->wifiSetCountryCode);
    PopulateStubFor(&halFn->getChipCaps);
    PopulateStubFor(&halFn->getPowerMode);
    PopulateStubFor(&halFn->setPowerMode);
    PopulateStubFor(&halFn->wifiStartScan);
    PopulateStubFor(&halFn->wifiStartPnoScan);
    PopulateStubFor(&halFn->wifiStopPnoScan);
    PopulateStubFor(&halFn->getScanResults);
    PopulateStubFor(&halFn->enablePowerMode);
    PopulateStubFor(&halFn->getSignalPollInfo);
    PopulateStubFor(&halFn->setDpiMarkRule);
    PopulateStubFor(&halFn->registerIfaceCallBack);
    PopulateStubFor(&halFn->setTxPower);
    return true;
}
    
} // namespace v1_0
} // namespace Chip
} // namespace Wlan
} // namespace HDI
} // namespace OHOS
## wlan/client/src/netlink/netlink_cmd_adapter.c
static int32_t WaitStartActionLock(void)
{
    int32_t count = 0;
    while (g_cookieStart == 0) {
        if (count < RETRIES) {
            HILOG_DEBUG(LOG_CORE, "%{public}s: wait g_cookieStart %{public}d 5ms",
                __FUNCTION__, count);
            count++;
            usleep(WAITFORSEND);

    if (PthreadMutexLock() != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: pthread trylock failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    /* try to set NETLINK_EXT_ACK to 1, ignoring errors */
    int32_t opt = 1;
    if (setsockopt(nl_socket_get_fd(g_wifiHalInfo.cmdSock), SOL_NETLINK, NETLINK_EXT_ACK, &opt, sizeof(opt)) < 0) {
        HILOG_ERROR(LOG_CORE, "%s: setsockopt one failed", __FUNCTION__);
    }
{
    if (ifName == NULL || attr == NULL) {
        HILOG_ERROR(LOG_CORE, "%{public}s: is null", __FUNCTION__);
        return;
    }
    if (WaitStartActionLock() == RET_CODE_FAILURE) {
        HILOG_ERROR(LOG_CORE, "%{public}s: WaitStartActionLock error", __FUNCTION__);
        return;
    }
    g_cookieSucess = (uint32_t)nla_get_u64(attr[NL80211_ATTR_COOKIE]);
    HILOG_DEBUG(LOG_CORE, "%{public}s: g_cookieStart = %{public}u g_cookieSucess = %{public}u "
    ntlMsg = (struct HwCommMsgT *)OsalMemAlloc(len);
    if (ntlMsg == NULL) {
        return RET_CODE_FAILURE;
    }

    if (memset_s(&ntlAddr, sizeof(ntlAddr), 0, sizeof(ntlAddr)) != EOK) {
        HILOG_ERROR(LOG_CORE, "ntlAddr memset_s is failed");
        OsalMemFree(ntlMsg);
        ntlMsg = NULL;
        return RET_CODE_FAILURE;
    }
    ntlAddr.nl_family = AF_NETLINK;
    ntlAddr.nl_pid = 0;
    ntlAddr.nl_groups = 0;

    if (memset_s(ntlMsg, len, 0, len) != EOK) {
        HILOG_ERROR(LOG_CORE, "ntlMsg memset_s is failed");
        OsalMemFree(ntlMsg);
        ntlMsg = NULL;
        return RET_CODE_FAILURE;
    }
    ntlMsg->hdr.nlmsg_len = NLMSG_LENGTH(DPI_MSG_LEN + datalen + 1);
    ntlMsg->hdr.nlmsg_flags = 0;
    ntlMsg->hdr.nlmsg_type = nlmsgType;
    ntlMsg->hdr.nlmsg_pid = (unsigned int)(getpid());
    ntlMsg->opt = opt;

    if (data != NULL && datalen != 0) {
        if (memcpy_s(ntlMsg->data, datalen, data, datalen) != EOK) {
            HILOG_ERROR(LOG_CORE, "memcpy_s is failed");
            OsalMemFree(ntlMsg);
            ntlMsg = NULL;
            return RET_CODE_FAILURE;
        }
    }
    ret = sendto(skfd, ntlMsg, ntlMsg->hdr.nlmsg_len, 0, (struct sockaddr*)&ntlAddr, sizeof(ntlAddr));
    OsalMemFree(ntlMsg);
    ntlMsg = NULL;
    return ret;
}