/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/pkt_sched.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/object-api.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/attr.h>
#include <netlink/handlers.h>
#include <netlink/msg.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include "wifi_hal.h"
#include "wifi_scan.h"
#include "common.h"
#include "cpp_bindings.h"

static bool SetExtFeatureFlag(const uint8_t *extFeatureFlagsBytes, uint32_t extFeatureFlagsLen, uint32_t extFeatureFlag)
{
    uint32_t extFeatureFlagBytePos;
    uint32_t extFeatureFlagBitPos;

    if (extFeatureFlagsBytes == nullptr || extFeatureFlagsLen == 0) {
        HDF_LOGE("param is NULL.");
        return false;
    }
    extFeatureFlagBytePos = extFeatureFlag / BITNUMS_OF_ONE_BYTE;
    extFeatureFlagBitPos = extFeatureFlag % BITNUMS_OF_ONE_BYTE;
    if (extFeatureFlagBytePos >= extFeatureFlagsLen) {
        return false;
    }
    return extFeatureFlagsBytes[extFeatureFlagBytePos] & (1U << extFeatureFlagBitPos);
}

class GetWiphyIndexCommand : public WifiCommand {
public:
    GetWiphyIndexCommand(wifiInterfaceHandle handle, uint32_t *wiphyIndex)
        : WifiCommand("GetWiphyIndexCommand", handle, 0)
        {
        mWiphyIndex = wiphyIndex;
    }
    int Create() override
    {
        int ret;

        ret = mMsg.Create(FamilyId(), NL80211_CMD_GET_WIPHY, NLM_F_DUMP, 0);
        if (ret < 0) {
            HDF_LOGE("Can't create message to send to driver - %{public}d", ret);
            return ret;
        }
        ret = mMsg.PutU32(NL80211_ATTR_IFINDEX, IfaceId());
        if (ret < 0) {
            HDF_LOGE("put ifaceid fail %{public}d", IfaceId());
            return ret;
        }
        return HAL_SUCCESS;
    }
protected:
    int HandleResponse(WifiEvent& reply) override
    {
        struct nlattr **attr = reply.Attributes();

        if (!attr[NL80211_ATTR_WIPHY]) {
            HDF_LOGE("HandleResponse: wiphy info missing!");
            return NL_SKIP;
        }
        *mWiphyIndex = nla_get_u32(attr[NL80211_ATTR_WIPHY]);
        return NL_SKIP;
    }
private:
    uint32_t *mWiphyIndex;
};

static int WifiGetWiphyIndex(wifiInterfaceHandle handle, uint32_t *wiphyIndex)
{
    GetWiphyIndexCommand command(handle, wiphyIndex);
    auto lock = ReadLockData();
    return command.RequestResponse();
}

class GetWiphyInfoCommand : public WifiCommand {
public:
    GetWiphyInfoCommand(wifiInterfaceHandle handle, uint32_t wiphyIndex)
        : WifiCommand("GetWiphyInfoCommand", handle, 0)
    {
        mWiphyIndex = wiphyIndex;
        if (memset_s(&mWiphyInfo, sizeof(WiphyInfo), 0, sizeof(WiphyInfo)) != EOK) {
            HDF_LOGE("memset mWiphyInfo failed");
        }
    }
    int Create() override
    {
        int ret;

        ret = mMsg.Create(FamilyId(), NL80211_CMD_GET_WIPHY, 0, 0);
        if (ret < 0) {
            HDF_LOGE("Can't create message to send to driver - %{public}d", ret);
            return ret;
        }
        ret = mMsg.PutU32(NL80211_ATTR_WIPHY, mWiphyIndex);
        if (ret < 0) {
            return ret;
        }
        return HAL_SUCCESS;
    }

    WiphyInfo &GetWiphyInfo()
    {
        return mWiphyInfo;
    }
protected:
    int HandleResponse(WifiEvent& reply) override
    {
        struct nlattr **attr = reply.Attributes();
        uint32_t featureFlags = 0;
        uint8_t *extFeatureFlagsBytes = nullptr;
        uint32_t extFeatureFlagsLen = 0;

        if (attr[NL80211_ATTR_MAX_NUM_SCAN_SSIDS] != nullptr) {
            mWiphyInfo.scanCapabilities.maxNumScanSsids = nla_get_u8(attr[NL80211_ATTR_MAX_NUM_SCAN_SSIDS]);
        }
        if (attr[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS] != nullptr) {
            mWiphyInfo.scanCapabilities.maxNumSchedScanSsids = nla_get_u8(attr[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS]);
        }
        if (attr[NL80211_ATTR_MAX_MATCH_SETS] != nullptr) {
            mWiphyInfo.scanCapabilities.maxMatchSets = nla_get_u8(attr[NL80211_ATTR_MAX_MATCH_SETS]);
        }
        if (attr[NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS] != nullptr) {
            mWiphyInfo.scanCapabilities.maxNumScanPlans = nla_get_u32(attr[NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS]);
        }
        if (attr[NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL] != nullptr) {
            mWiphyInfo.scanCapabilities.maxScanPlanInterval = nla_get_u32(attr[NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL]);
        }
        if (attr[NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS] != nullptr) {
            mWiphyInfo.scanCapabilities.maxScanPlanIterations =
                nla_get_u32(attr[NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS]);
        }
        if (attr[NL80211_ATTR_FEATURE_FLAGS] != nullptr) {
            featureFlags = nla_get_u32(attr[NL80211_ATTR_FEATURE_FLAGS]);
        }
        mWiphyInfo.wiphyFeatures.supportsRandomMacSchedScan = featureFlags & NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR;
        if (attr[NL80211_ATTR_EXT_FEATURES] != nullptr) {
            extFeatureFlagsBytes = reinterpret_cast<uint8_t *>(nla_data(attr[NL80211_ATTR_EXT_FEATURES]));
            extFeatureFlagsLen = static_cast<uint32_t>(nla_len(attr[NL80211_ATTR_EXT_FEATURES]));
            mWiphyInfo.wiphyFeatures.supportsLowPowerOneshotScan =
                SetExtFeatureFlag(extFeatureFlagsBytes, extFeatureFlagsLen, NL80211_EXT_FEATURE_LOW_POWER_SCAN);
            mWiphyInfo.wiphyFeatures.supportsExtSchedScanRelativeRssi =
                SetExtFeatureFlag(extFeatureFlagsBytes, extFeatureFlagsLen,
                    NL80211_EXT_FEATURE_SCHED_SCAN_RELATIVE_RSSI);
        }
        return NL_SKIP;
    }
private:
    uint32_t mWiphyIndex;
    WiphyInfo mWiphyInfo;
};

static int WifiGetWiphyInfo(wifiInterfaceHandle handle, uint32_t wiphyIndex, WiphyInfo &wiphyInfo)
{
    GetWiphyInfoCommand command(handle, wiphyIndex);
    auto lock = ReadLockData();
    command.RequestResponse();
    wiphyInfo = command.GetWiphyInfo();
    return HAL_SUCCESS;
}

class ScanCommand : public WifiCommand {
    const OHOS::HDI::Wlan::Chip::V1_0::ScanParams mScanParams;
    WiphyInfo mWiphyInfo;
public:
    ScanCommand(wifiInterfaceHandle iface,
        const OHOS::HDI::Wlan::Chip::V1_0::ScanParams& scanParams,
        WiphyInfo &wiphyInfo)
        : WifiCommand("ScanCommand", iface, 0), mScanParams(scanParams), mWiphyInfo(wiphyInfo)
    { }

    int CreateSetupRequest(WifiRequest& request)
    {
        int result = request.Create(FamilyId(), NL80211_CMD_TRIGGER_SCAN, 0, 0);
        int i = 0;

        if (result < 0) {
            return result;
        }
        result = request.PutU32(NL80211_ATTR_IFINDEX, IfaceId());
        if (result < 0) {
            return result;
        }
        nlattr *ssid = request.AttrStart(NL80211_ATTR_SCAN_SSIDS);

        /* chip nedd add an empty ssid for a wildcard scan */
        request.Put(1, nullptr, 0);
        i += 1;
        for (auto iter = mScanParams.ssids.begin(); iter != mScanParams.ssids.end(); ++iter) {
            if (i >= mWiphyInfo.scanCapabilities.maxNumScanSsids) {
                HDF_LOGI("Skip the excess hidden ssids for scan");
                break;
            }
            request.Put(i + 1, (void *)(*iter).c_str(), (*iter).length());
            i++;
        }
        request.AttrEnd(ssid);
        i = 0;
        nlattr *freqs = request.AttrStart(NL80211_ATTR_SCAN_FREQUENCIES);
        for (auto iter = mScanParams.freqs.begin(); iter != mScanParams.freqs.end(); ++iter) {
            request.PutU32(i + 1, (*iter));
            i++;
        }
        request.AttrEnd(freqs);

        if (!mScanParams.extraIes.empty()) {
            request.Put(NL80211_ATTR_IE, (void *)mScanParams.extraIes.c_str(), mScanParams.extraIes.length());
        }

        if (!mScanParams.bssid.empty()) {
            request.Put(NL80211_ATTR_MAC, (void *)mScanParams.bssid.c_str(), mScanParams.bssid.length());
        }
        return HAL_SUCCESS;
    }

    int Start()
    {
        HDF_LOGI("start scan");
        WifiRequest request(FamilyId(), IfaceId());
        int result = CreateSetupRequest(request);
        if (result != HAL_SUCCESS) {
            HDF_LOGE("failed to create setup request; result = %{public}d", result);
            return result;
        }
        auto lock = ReadLockData();
        result = RequestResponse(request);
        if (result < 0) {
            HDF_LOGE("failed to configure setup; result = %{public}d", result);
            return result;
        }
        return HAL_SUCCESS;
    }
};


WifiError WifiStartScan(wifiInterfaceHandle handle,
    const OHOS::HDI::Wlan::Chip::V1_0::ScanParams& scanParam)
{
    uint32_t wiphyIndex;
    WiphyInfo wiphyInfo;
    if (!handle) {
        HDF_LOGE("Handle is null");
        return HAL_INVALID_ARGS;
    }
    if (WifiGetWiphyIndex(handle, &wiphyIndex) < 0) {
        HDF_LOGE("can not get wiphyIndex");
        return HAL_NONE;
    }
    if (WifiGetWiphyInfo(handle, wiphyIndex, wiphyInfo) < 0) {
        HDF_LOGE("can not get wiphyInfo");
        return HAL_NONE;
    }
    ScanCommand scanCommand(handle, scanParam, wiphyInfo);
    return (WifiError)scanCommand.Start();
}

class PnoScanCommand : public WifiCommand {
    const OHOS::HDI::Wlan::Chip::V1_0::PnoScanParams mPnoScanParams;
    WiphyInfo mWiphyInfo;
public:
    PnoScanCommand(wifiInterfaceHandle iface,
        const OHOS::HDI::Wlan::Chip::V1_0::PnoScanParams& pnoScanParams,
        WiphyInfo &wiphyInfo)
        : WifiCommand("PnoScanCommand", iface, 0), mPnoScanParams(pnoScanParams), mWiphyInfo(wiphyInfo)
    { }

    int CreateSetupRequest(WifiRequest& request)
    {
        int result = request.Create(FamilyId(), NL80211_CMD_START_SCHED_SCAN, 0, 0);
        if (result < 0) {
            return result;
        }
        result = request.PutU32(NL80211_ATTR_IFINDEX, IfaceId());
        if (result < 0) {
            return result;
        }
        if (ProcessMatchSsidToMsg(request) != HAL_SUCCESS || ProcessSsidToMsg(request) != HAL_SUCCESS ||
            ProcessScanPlanToMsg(request) != HAL_SUCCESS || ProcessReqflagsToMsg(request) != HAL_SUCCESS) {
            HDF_LOGE("%{public}s: Fill parameters to netlink failed.", __FUNCTION__);
            return HAL_NOT_AVAILABLE;
        }
        return HAL_SUCCESS;
    }

    int ProcessMatchSsidToMsg(WifiRequest& request)
    {
        nlattr *nestedMatchSsid = request.AttrStart(NL80211_ATTR_SCHED_SCAN_MATCH);
        int i = 0;
        for (auto iter = mPnoScanParams.savedssids.begin(); iter != mPnoScanParams.savedssids.end(); ++iter) {
            if (i >= mWiphyInfo.scanCapabilities.maxNumSchedScanSsids) {
                HDF_LOGI("Skip the excess saved ssids for pnoscan");
                break;
            }
            nlattr *nest = request.AttrStart(i);
            request.Put(NL80211_SCHED_SCAN_MATCH_ATTR_SSID, (void *)(*iter).c_str(), (*iter).length());
            request.PutU32(NL80211_SCHED_SCAN_MATCH_ATTR_RSSI, mPnoScanParams.min5gRssi);
            i++;
            request.AttrEnd(nest);
        }
        request.AttrEnd(nestedMatchSsid);
        return HAL_SUCCESS;
    }

    int ProcessSsidToMsg(WifiRequest& request)
    {
        nlattr *hiddenSsid = request.AttrStart(NL80211_ATTR_SCAN_SSIDS);
        int i = 0;
        for (auto iter = mPnoScanParams.savedssids.begin(); iter != mPnoScanParams.savedssids.end(); ++iter) {
            if (i >= mWiphyInfo.scanCapabilities.maxNumScanSsids) {
                HDF_LOGI("Skip the excess hidden ssids for pnoscan");
                break;
            }
            request.Put(i, (void *)(*iter).c_str(), (*iter).length());
            i++;
        }
        request.AttrEnd(hiddenSsid);
        return HAL_SUCCESS;
    }

    int ProcessScanPlanToMsg(WifiRequest& request)
    {
        bool supportNumScanPlans = (mWiphyInfo.scanCapabilities.maxNumScanPlans >= 2);
        bool supportScanPlanInterval = (mWiphyInfo.scanCapabilities.maxScanPlanInterval * MS_PER_SECOND >=
            (uint32_t)mPnoScanParams.scanIntervalMs * SLOW_SCAN_INTERVAL_MULTIPLIER);
        bool supportScanPlanIterations = (mWiphyInfo.scanCapabilities.maxScanPlanIterations >= FAST_SCAN_ITERATIONS);

        if (supportNumScanPlans && supportScanPlanInterval && supportScanPlanIterations) {
            nlattr *nestedPlan = request.AttrStart(NL80211_ATTR_SCHED_SCAN_PLANS);
            nlattr *plan = request.AttrStart(SCHED_SCAN_PLANS_ATTR_INDEX1);
            request.PutU32(NL80211_SCHED_SCAN_PLAN_INTERVAL, mPnoScanParams.scanIntervalMs);
            request.PutU32(NL80211_SCHED_SCAN_PLAN_ITERATIONS, mPnoScanParams.scanIterations);
            request.AttrEnd(plan);
            plan = request.AttrStart(SCHED_SCAN_PLANS_ATTR_INDEX2);
            request.PutU32(NL80211_SCHED_SCAN_PLAN_INTERVAL,
                mPnoScanParams.scanIntervalMs * SLOW_SCAN_INTERVAL_MULTIPLIER);
            request.AttrEnd(plan);
            request.AttrEnd(nestedPlan);
        } else {
            request.PutU32(NL80211_ATTR_SCHED_SCAN_INTERVAL, mPnoScanParams.scanIntervalMs * MS_PER_SECOND);
        }
        return HAL_SUCCESS;
    }

    int ProcessReqflagsToMsg(WifiRequest& request)
    {
        uint32_t scanFlag = 0;
        if (mWiphyInfo.wiphyFeatures.supportsExtSchedScanRelativeRssi) {
            struct nl80211_bss_select_rssi_adjust rssiAdjust;
            (void)memset_s(&rssiAdjust, sizeof(rssiAdjust), 0, sizeof(rssiAdjust));
            rssiAdjust.band = NL80211_BAND_2GHZ;
            rssiAdjust.delta = mPnoScanParams.min2gRssi - mPnoScanParams.min5gRssi;
            nl_msg *msg = request.GetMessage();
            nla_put(msg, NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST, sizeof(rssiAdjust), &rssiAdjust);
        }
        if (mWiphyInfo.wiphyFeatures.supportsRandomMacSchedScan) {
            scanFlag |= NL80211_SCAN_FLAG_RANDOM_ADDR;
        }
        if (mWiphyInfo.wiphyFeatures.supportsLowPowerOneshotScan) {
            scanFlag |= NL80211_SCAN_FLAG_LOW_POWER;
        }
        if (scanFlag != 0) {
            request.PutU32(NL80211_ATTR_SCAN_FLAGS, scanFlag);
        }
        int i = 0;
        nlattr *freqs = request.AttrStart(NL80211_ATTR_SCAN_FREQUENCIES);
        for (auto iter = mPnoScanParams.freqs.begin(); iter != mPnoScanParams.freqs.end(); ++iter) {
            request.PutU32(i + 1, (*iter));
            i++;
        }
        request.AttrEnd(freqs);
        return HAL_SUCCESS;
    }

    int Start()
    {
        HDF_LOGD("start pno scan");
        WifiRequest request(FamilyId(), IfaceId());
        int result = CreateSetupRequest(request);
        if (result != HAL_SUCCESS) {
            HDF_LOGE("failed to create setup request; result = %{public}d", result);
            return result;
        }
        auto lock = ReadLockData();
        result = RequestResponse(request);
        if (result < 0) {
            HDF_LOGE("failed to configure setup; result = %{public}d", result);
            return result;
        }
        return HAL_SUCCESS;
    }
};

class StopPnoScanCommand : public WifiCommand {
public:
    explicit StopPnoScanCommand(wifiInterfaceHandle handle)
        : WifiCommand("StopPnoScanCommand", handle, 0) {
    }
    int Create() override
    {
        int ret;

        ret = mMsg.Create(FamilyId(), NL80211_CMD_STOP_SCHED_SCAN, 0, 0);
        if (ret < 0) {
            HDF_LOGE("Can't create message to send to driver - %{public}d", ret);
            return ret;
        }
        ret = mMsg.PutU32(NL80211_ATTR_IFINDEX, IfaceId());
        if (ret < 0) {
            HDF_LOGE("put ifaceid fail %{public}d", IfaceId());
            return ret;
        }
        return HAL_SUCCESS;
    }
};


WifiError WifiStartPnoScan(wifiInterfaceHandle handle,
    const OHOS::HDI::Wlan::Chip::V1_0::PnoScanParams& pnoScanParam)
{
    uint32_t wiphyIndex;
    WiphyInfo wiphyInfo;
    if (!handle) {
        HDF_LOGE("Handle is null");
        return HAL_INVALID_ARGS;
    }
    if (WifiGetWiphyIndex(handle, &wiphyIndex) < 0) {
        HDF_LOGE("can not get wiphyIndex");
        return HAL_NONE;
    }
    if (WifiGetWiphyInfo(handle, wiphyIndex, wiphyInfo) < 0) {
        HDF_LOGE("can not get wiphyInfo");
        return HAL_NONE;
    }
    PnoScanCommand pnoScanCommand(handle, pnoScanParam, wiphyInfo);
    return (WifiError)pnoScanCommand.Start();
}

WifiError WifiStopPnoScan(wifiInterfaceHandle handle)
{
    if (!handle) {
        HDF_LOGE("Handle is null");
        return HAL_INVALID_ARGS;
    }
    StopPnoScanCommand stopPnoScanCommand(handle);
    auto lock = ReadLockData();
    return (WifiError)stopPnoScanCommand.RequestResponse();
}

class GetScanResultsCommand : public WifiCommand {
public:
    explicit GetScanResultsCommand(wifiInterfaceHandle handle)
        : WifiCommand("GetScanResultsCommand", handle, 0) {
    }
    int Create() override
    {
        int ret;

        ret = mMsg.Create(FamilyId(), NL80211_CMD_GET_SCAN, NLM_F_DUMP, 0);
        if (ret < 0) {
            HDF_LOGE("Can't create message to send to driver - %{public}d", ret);
            return ret;
        }
        ret = mMsg.PutU32(NL80211_ATTR_IFINDEX, IfaceId());
        if (ret < 0) {
            HDF_LOGE("put ifaceid fail %{public}d", IfaceId());
            return ret;
        }

        return HAL_SUCCESS;
    }
    std::vector<OHOS::HDI::Wlan::Chip::V1_0::ScanResultsInfo> &GetScanResultsInfo()
    {
        return mscanResults;
    }
protected:
    int HandleResponse(WifiEvent& reply) override
    {
        OHOS::HDI::Wlan::Chip::V1_0::ScanResultsInfo scanResult;
        struct nlattr **attr = reply.Attributes();
        struct nlattr *bssAttr[NL80211_BSS_MAX + 1];
        static struct nla_policy bssPolicy[NL80211_BSS_MAX + 1];
        memset_s(bssPolicy, sizeof(bssPolicy), 0, sizeof(bssPolicy));
        bssPolicy[NL80211_BSS_FREQUENCY].type = NLA_U32;
        bssPolicy[NL80211_BSS_TSF].type = NLA_U64;
        bssPolicy[NL80211_BSS_BEACON_INTERVAL].type = NLA_U16;
        bssPolicy[NL80211_BSS_CAPABILITY].type = NLA_U16;
        bssPolicy[NL80211_BSS_SIGNAL_MBM].type = NLA_U32;
        bssPolicy[NL80211_BSS_SIGNAL_UNSPEC].type = NLA_U8;
        bssPolicy[NL80211_BSS_STATUS].type = NLA_U32;
        bssPolicy[NL80211_BSS_SEEN_MS_AGO].type = NLA_U32;

        if (!attr[NL80211_ATTR_BSS]) {
            return NL_SKIP;
        }
        if (nla_parse_nested(bssAttr, NL80211_BSS_MAX, attr[NL80211_ATTR_BSS], bssPolicy)) {
            HDF_LOGE("failed to parse nested attributes");
            return NL_SKIP;
        }
        if (HandleBssAttr(bssAttr, scanResult) != HAL_SUCCESS) {
            return NL_SKIP;
        }
        mscanResults.push_back(scanResult);
        return NL_SKIP;
    }

    int HandleBssAttr(struct nlattr **bssAttr, OHOS::HDI::Wlan::Chip::V1_0::ScanResultsInfo &scanResult)
    {
        if (bssAttr[NL80211_BSS_INFORMATION_ELEMENTS]) {
            uint8_t *ie =  reinterpret_cast<uint8_t*>(nla_data(bssAttr[NL80211_BSS_INFORMATION_ELEMENTS]));
            int ieLen =  static_cast<int32_t>(nla_len(bssAttr[NL80211_BSS_INFORMATION_ELEMENTS]));
            std::vector<uint8_t> ieVec(ie, ie + ieLen);
            scanResult.ie = ieVec;
        }
        if (bssAttr[NL80211_BSS_BEACON_IES]) {
            uint8_t *beaconIe = reinterpret_cast<uint8_t*>(nla_data(bssAttr[NL80211_BSS_INFORMATION_ELEMENTS]));
            int beaconIeLen = static_cast<int32_t>(nla_len(bssAttr[NL80211_BSS_INFORMATION_ELEMENTS]));
            std::vector<uint8_t> beaconIeVec(beaconIe, beaconIe + beaconIeLen);
            scanResult.beaconIe = beaconIeVec;
        }
        if (bssAttr[NL80211_BSS_BSSID]) {
            uint8_t *bssid = reinterpret_cast<uint8_t*>(nla_data(bssAttr[NL80211_BSS_BSSID]));
            std::vector<uint8_t> bssidVec(bssid, bssid + ETH_ADDR_LEN);
            scanResult.bssid = bssidVec;
        }
        if (bssAttr[NL80211_BSS_FREQUENCY]) {
            scanResult.freq = nla_get_u32(bssAttr[NL80211_BSS_FREQUENCY]);
        }
        if (bssAttr[NL80211_BSS_BEACON_INTERVAL]) {
            scanResult.beaconInterval = nla_get_u16(bssAttr[NL80211_BSS_BEACON_INTERVAL]);
        }
        if (bssAttr[NL80211_BSS_CAPABILITY]) {
            scanResult.caps = nla_get_u16(bssAttr[NL80211_BSS_CAPABILITY]);
        }
        if (bssAttr[NL80211_BSS_SIGNAL_MBM]) {
            scanResult.level = (int32_t)nla_get_u32(bssAttr[NL80211_BSS_SIGNAL_MBM]) / SIGNAL_LEVEL_CONFFICIENT;
            scanResult.flags |= SCAN_LEVEL_DBM | SCAN_QUAL_INVALID;
        } else if (bssAttr[NL80211_BSS_SIGNAL_UNSPEC]) {
            scanResult.level = (int32_t)nla_get_u8(bssAttr[NL80211_BSS_SIGNAL_UNSPEC]);
            scanResult.flags |= SCAN_QUAL_INVALID;
        } else {
            scanResult.flags |= SCAN_LEVEL_INVALID | SCAN_QUAL_INVALID;
        }
        if (bssAttr[NL80211_BSS_TSF]) {
            scanResult.tsf = nla_get_u64(bssAttr[NL80211_BSS_TSF]);
        }
        if (bssAttr[NL80211_BSS_BEACON_TSF]) {
            uint64_t tsf = nla_get_u64(bssAttr[NL80211_BSS_BEACON_TSF]);
            if (tsf > scanResult.tsf) {
                scanResult.tsf = tsf;
            }
        }
        if (bssAttr[NL80211_BSS_SEEN_MS_AGO]) {
            scanResult.age = nla_get_u32(bssAttr[NL80211_BSS_SEEN_MS_AGO]);
        }
        return HAL_SUCCESS;
    }

private:
    std::vector<OHOS::HDI::Wlan::Chip::V1_0::ScanResultsInfo> mscanResults;
};

WifiError WifiGetScanInfo(wifiInterfaceHandle handle,
    std::vector<OHOS::HDI::Wlan::Chip::V1_0::ScanResultsInfo>& mscanResults)
{
    if (!handle) {
        HDF_LOGE("Handle is null");
        return HAL_INVALID_ARGS;
    }
    GetScanResultsCommand command(handle);
    auto lock = ReadLockData();
    WifiError status = (WifiError)command.RequestResponse();
    if (status == HAL_SUCCESS) {
        HDF_LOGE("command.RequestResponse() return %{public}d", status);
    }
    mscanResults = command.GetScanResultsInfo();
    return status;
}

