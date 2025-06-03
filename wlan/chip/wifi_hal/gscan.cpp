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
