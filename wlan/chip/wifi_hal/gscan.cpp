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

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <sys/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/errqueue.h>
#include <linux/nl80211.h>
#include <linux/pkt_sched.h>
#include <netlink/object-api.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/handlers.h>
#include "common.h"
#include "cpp_bindings.h"
#include "gscan.h"

typedef enum {
    GSCAN_ATTRIBUTE_NUM_BUCKETS = 10,
    GSCAN_ATTRIBUTE_BASE_PERIOD,
    GSCAN_ATTRIBUTE_BUCKETS_BAND,
    GSCAN_ATTRIBUTE_BUCKET_ID,
    GSCAN_ATTRIBUTE_BUCKET_PERIOD,
    GSCAN_ATTRIBUTE_BUCKET_NUM_CHANNELS,
    GSCAN_ATTRIBUTE_BUCKET_CHANNELS,
    GSCAN_ATTRIBUTE_NUM_AP_PER_SCAN,
    GSCAN_ATTRIBUTE_REPORT_THRESHOLD,
    GSCAN_ATTRIBUTE_NUM_SCANS_TO_CACHE,
    GSCAN_ATTRIBUTE_BAND = GSCAN_ATTRIBUTE_BUCKETS_BAND,

    GSCAN_ATTRIBUTE_ENABLE_FEATURE = 20,
    GSCAN_ATTRIBUTE_SCAN_RESULTS_COMPLETE,              /* indicates_no_more_results */
    GSCAN_ATTRIBUTE_FLUSH_FEATURE,                      /* Flush all the configs */
    GSCAN_ENABLE_FULL_SCAN_RESULTS,
    GSCAN_ATTRIBUTE_REPORT_EVENTS,

    /* remaining reserved for additional attributes */
    GSCAN_ATTRIBUTE_NUM_OF_RESULTS = 30,
    GSCAN_ATTRIBUTE_FLUSH_RESULTS,
    GSCAN_ATTRIBUTE_SCAN_RESULTS,                       /* flat array of wifi_scan_result */
    GSCAN_ATTRIBUTE_SCAN_ID,                            /* indicates scan number */
    GSCAN_ATTRIBUTE_SCAN_FLAGS,                         /* indicates if scan was aborted */
    GSCAN_ATTRIBUTE_AP_FLAGS,                           /* flags on significant change event*/
    GSCAN_ATTRIBUTE_NUM_CHANNELS,
    GSCAN_ATTRIBUTE_CHANNEL_LIST,
    GSCAN_ATTRIBUTE_CH_BUCKET_BITMASK,
    /* remaining reserved for additional attributes */

    GSCAN_ATTRIBUTE_SSID = 40,
    GSCAN_ATTRIBUTE_BSSID,
    GSCAN_ATTRIBUTE_CHANNEL,
    GSCAN_ATTRIBUTE_RSSI,
    GSCAN_ATTRIBUTE_TIMESTAMP,
    GSCAN_ATTRIBUTE_RTT,
    GSCAN_ATTRIBUTE_RTTSD,

    /* remaining reserved for additional attributes */

    GSCAN_ATTRIBUTE_HOTLIST_BSSIDS = 50,
    GSCAN_ATTRIBUTE_RSSI_LOW,
    GSCAN_ATTRIBUTE_RSSI_HIGH,
    GSCAN_ATTRIBUTE_HOTLIST_ELEM,
    GSCAN_ATTRIBUTE_HOTLIST_FLUSH,
    GSCAN_ATTRIBUTE_HOTLIST_BSSID_COUNT,

    /* remaining reserved for additional attributes */
    GSCAN_ATTRIBUTE_RSSI_SAMPLE_SIZE = 60,
    GSCAN_ATTRIBUTE_LOST_AP_SAMPLE_SIZE,
    GSCAN_ATTRIBUTE_MIN_BREACHING,
    GSCAN_ATTRIBUTE_SIGNIFICANT_CHANGE_BSSIDS,
    GSCAN_ATTRIBUTE_SIGNIFICANT_CHANGE_FLUSH,

    /* EPNO */
    GSCAN_ATTRIBUTE_EPNO_SSID_LIST = 70,
    GSCAN_ATTRIBUTE_EPNO_SSID,
    GSCAN_ATTRIBUTE_EPNO_SSID_LEN,
    GSCAN_ATTRIBUTE_EPNO_RSSI,
    GSCAN_ATTRIBUTE_EPNO_FLAGS,
    GSCAN_ATTRIBUTE_EPNO_AUTH,
    GSCAN_ATTRIBUTE_EPNO_SSID_NUM,
    GSCAN_ATTRIBUTE_EPNO_FLUSH,

    /* remaining reserved for additional attributes */

    GSCAN_ATTRIBUTE_WHITELIST_SSID = 80,
    GSCAN_ATTRIBUTE_NUM_WL_SSID,
    GSCAN_ATTRIBUTE_WL_SSID_LEN,
    GSCAN_ATTRIBUTE_WL_SSID_FLUSH,
    GSCAN_ATTRIBUTE_WHITELIST_SSID_ELEM,
    GSCAN_ATTRIBUTE_NUM_BSSID,
    GSCAN_ATTRIBUTE_BSSID_PREF_LIST,
    GSCAN_ATTRIBUTE_BSSID_PREF_FLUSH,
    GSCAN_ATTRIBUTE_BSSID_PREF,
    GSCAN_ATTRIBUTE_RSSI_MODIFIER,

    /* remaining reserved for additional attributes */

    GSCAN_ATTRIBUTE_A_BAND_BOOST_THRESHOLD = 90,
    GSCAN_ATTRIBUTE_A_BAND_PENALTY_THRESHOLD,
    GSCAN_ATTRIBUTE_A_BAND_BOOST_FACTOR,
    GSCAN_ATTRIBUTE_A_BAND_PENALTY_FACTOR,
    GSCAN_ATTRIBUTE_A_BAND_MAX_BOOST,
    GSCAN_ATTRIBUTE_LAZY_ROAM_HYSTERESIS,
    GSCAN_ATTRIBUTE_ALERT_ROAM_RSSI_TRIGGER,
    GSCAN_ATTRIBUTE_LAZY_ROAM_ENABLE,
    
    /* BSSID AVOID */
    GSCAN_ATTRIBUTE_BSSID_AVOID_FLUSH = 100,
    GSCAN_ATTRIBUTE_AVOID_BSSID,
    
    /* ANQPO */
    GSCAN_ATTRIBUTE_ANQPO_HS_LIST = 110,
    GSCAN_ATTRIBUTE_ANQPO_HS_LIST_SIZE,
    GSCAN_ATTRIBUTE_ANQPO_HS_NETWORK_ID,
    GSCAN_ATTRIBUTE_ANQPO_HS_NAI_REALM,
    GSCAN_ATTRIBUTE_ANQPO_HS_ROAM_CONSORTIUM_ID,
    GSCAN_ATTRIBUTE_ANQPO_HS_PLMN,

    /* Adaptive scan attributes */
    GSCAN_ATTRIBUTE_BUCKET_STEP_COUNT = 120,
    GSCAN_ATTRIBUTE_BUCKET_MAX_PERIOD,

    /* ePNO cfg */
    GSCAN_ATTRIBUTE_EPNO_5G_RSSI_THR = 130,
    GSCAN_ATTRIBUTE_EPNO_2G_RSSI_THR,
    GSCAN_ATTRIBUTE_EPNO_INIT_SCORE_MAX,
    GSCAN_ATTRIBUTE_EPNO_CUR_CONN_BONUS,
    GSCAN_ATTRIBUTE_EPNO_SAME_NETWORK_BONUS,
    GSCAN_ATTRIBUTE_EPNO_SECURE_BONUS,
    GSCAN_ATTRIBUTE_EPNO_5G_BONUS,

    /* Roaming features */
    GSCAN_ATTRIBUTE_ROAM_STATE_SET = 140,
    GSCAN_ATTRIBUTE_MAX
} GSCAN_ATTRIBUTE;

class GetChannelListCommand : public WifiCommand {
    std::vector<uint32_t> mFreqs;
    int mBand;
public:
    GetChannelListCommand(wifiInterfaceHandle iface, int band)
        : WifiCommand("GetChannelListCommand", iface, 0), mBand(band)
    {}
    int Create() override
    {
        int ret = mMsg.Create(FamilyId(), NL80211_CMD_GET_WIPHY, NLM_F_DUMP, 0);
        if (ret < 0) {
            HDF_LOGE("Can't create message to send to driver - %{public}d", ret);
            return ret;
        }
        mMsg.PutFlag(NL80211_ATTR_SPLIT_WIPHY_DUMP);
        ret = mMsg.PutU32(NL80211_ATTR_IFINDEX, IfaceId());
        if (ret < 0) {
            HDF_LOGE("put ifaceid fail %{public}d", IfaceId());
        }
        return ret;
    }

    void GetCenterFreq(struct nlattr *bands)
    {
        struct nlattr *attrFreq[NL80211_FREQUENCY_ATTR_MAX + 1];
        struct nlattr *nlFreq = nullptr;
        void *data = nullptr;
        int32_t len;
        int32_t i;
        uint32_t freq;
        static struct nla_policy freqPolicy[NL80211_FREQUENCY_ATTR_MAX + 1];
        freqPolicy[NL80211_FREQUENCY_ATTR_FREQ].type = NLA_U32;
        freqPolicy[NL80211_FREQUENCY_ATTR_MAX_TX_POWER].type = NLA_U32;

        nla_for_each_nested(nlFreq, bands, i) {
            data = nla_data(nlFreq);
            len = nla_len(nlFreq);
            nla_parse(attrFreq, NL80211_FREQUENCY_ATTR_MAX, (struct nlattr *)data, len, freqPolicy);
            if (attrFreq[NL80211_FREQUENCY_ATTR_FREQ] == nullptr) {
                continue;
            }
            if (attrFreq[NL80211_FREQUENCY_ATTR_DISABLED] != nullptr) {
                continue;
            }
            freq = nla_get_u32(attrFreq[NL80211_FREQUENCY_ATTR_FREQ]);
            switch (mBand) {
                case NL80211_BAND_2GHZ:
                    if (freq > LOW_LITMIT_FREQ_2_4G && freq < HIGH_LIMIT_FREQ_2_4G) {
                        mFreqs.push_back(freq);
                    }
                    break;
                case NL80211_BAND_5GHZ:
                    if (freq > LOW_LIMIT_FREQ_5G && freq < HIGH_LIMIT_FREQ_5G) {
                        mFreqs.push_back(freq);
                    }
                    break;
                default:
                    break;
            }
        }
    }

    std::vector<uint32_t> &GetFreqs()
    {
        return mFreqs;
    }
protected:
    int HandleResponse(WifiEvent& reply) override
    {
        struct nlattr *attrBand[NL80211_BAND_ATTR_MAX + 1];
        struct nlattr *nlBand = nullptr;
        struct nlattr **attr = reply.Attributes();
        int32_t i;
        void *data = nullptr;
        int32_t len;
        
        if (!attr[NL80211_ATTR_WIPHY_BANDS]) {
            return NL_SKIP;
        }
        struct nlattr *attrWiphyBands = attr[NL80211_ATTR_WIPHY_BANDS];
        if (attrWiphyBands == nullptr) {
            return NL_SKIP;
        }
        nla_for_each_nested(nlBand, attrWiphyBands, i) {
            data = nla_data(nlBand);
            len = nla_len(nlBand);
            nla_parse(attrBand, NL80211_BAND_ATTR_MAX, (struct nlattr *)data, len, NULL);
            if (attrBand[NL80211_BAND_ATTR_FREQS] == nullptr) {
                continue;
            }
            GetCenterFreq(attrBand[NL80211_BAND_ATTR_FREQS]);
        }

        return NL_OK;
    }
};

WifiError VendorHalGetChannelsInBand(wifiInterfaceHandle handle,
    int band, std::vector<uint32_t>& freqs)
{
    HDF_LOGI("VendorHalGetChannelsInBand band = %{public}d", band);
    if (!handle) {
        HDF_LOGE("Handle is null");
        return HAL_INVALID_ARGS;
    }
    if (band > 0 && band <= IEEE80211_NUM_BANDS) {
        band = band - 1;
    }
    if (band >= IEEE80211_NUM_BANDS) {
        HDF_LOGE("Invalid input parameter, band = %{public}d", band);
        return HAL_INVALID_ARGS;
    }
    GetChannelListCommand command(handle, band);
    auto lock = ReadLockData();
    int ret = command.RequestResponse();
    if (ret < 0) {
        return HAL_NONE;
    }
    freqs = command.GetFreqs();
    return HAL_SUCCESS;
}
