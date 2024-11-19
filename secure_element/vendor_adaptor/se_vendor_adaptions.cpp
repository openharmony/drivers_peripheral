/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "se_vendor_adaptions.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <vector>
#include <iproxy_broker.h>

#ifdef SE_VENDOR_ADAPTION_USE_CA
#include "secure_element_ca_proxy.h"
#endif

#define HDF_LOG_TAG hdf_se

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD000305

namespace OHOS {
namespace HDI {
namespace SecureElement {
static sptr<ISecureElementCallback> g_callbackV1_0 = nullptr;
static std::mutex g_mutex {};
#ifdef SE_VENDOR_ADAPTION_USE_CA
static const int RES_BUFFER_MAX_LENGTH = 512;
static const uint16_t SW1_OFFSET = 2;
static const uint16_t SW2_OFFSET = 1;
static const uint16_t MAX_CHANNEL_NUM = 4;
static const uint16_t MAX_CHANNEL_SIZE = 0xFF;
static const uint16_t MIN_RES_LEN = 2;
uint16_t g_openedChannelCount = 0;
bool g_openedChannels[MAX_CHANNEL_NUM] = {false, false, false, false};
#endif

SeVendorAdaptions::SeVendorAdaptions()
{
    remoteDeathRecipient_ =
        new RemoteDeathRecipient(std::bind(&SeVendorAdaptions::OnRemoteDied, this, std::placeholders::_1));
}

SeVendorAdaptions::~SeVendorAdaptions()
{
    RemoveSecureElementDeathRecipient(g_callbackV1_0);
}

int32_t SeVendorAdaptions::init(const sptr<ISecureElementCallback>& clientCallback, SecureElementStatus& status)
{
    HDF_LOGD("SeVendorAdaptions:%{public}s!", __func__);
    std::lock_guard<std::mutex> lock(g_mutex);
    if (clientCallback == nullptr) {
        HDF_LOGE("init failed, clientCallback is null");
        status = SecureElementStatus::SE_NULL_POINTER_ERROR;
        return HDF_ERR_INVALID_PARAM;
    }
#ifdef SE_VENDOR_ADAPTION_USE_CA
    g_openedChannelCount = 0;
    int ret = SecureElementCaProxy::GetInstance().VendorSecureElementCaInit();
    if (ret != SECURE_ELEMENT_CA_RET_OK) {
        HDF_LOGE("VendorSecureElementCaInit failed ret %{public}u", ret);
        status = SecureElementStatus::SE_GENERAL_ERROR;
        return HDF_ERR_INVALID_PARAM;
    }
#endif
    g_callbackV1_0 = clientCallback;
    g_callbackV1_0->OnSeStateChanged(true);
    AddSecureElementDeathRecipient(g_callbackV1_0);
    status = SecureElementStatus::SE_SUCCESS;
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::getAtr(std::vector<uint8_t>& response)
{
    HDF_LOGD("SeVendorAdaptions:%{public}s!", __func__);
#ifdef SE_VENDOR_ADAPTION_USE_CA
    uint8_t res[RES_BUFFER_MAX_LENGTH] = {0};
    uint32_t resLen = RES_BUFFER_MAX_LENGTH;
    int ret = SecureElementCaProxy::GetInstance().VendorSecureElementCaGetAtr(res, &resLen);
    for (uint32_t i = 0; i < resLen; i++) {
        response.push_back(res[i]);
    }
    if (ret != SECURE_ELEMENT_CA_RET_OK) {
        HDF_LOGE("getAtr failed ret %{public}u", ret);
    }
#endif
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::isSecureElementPresent(bool& present)
{
    HDF_LOGD("SeVendorAdaptDons:%{public}s!", __func__);
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_callbackV1_0 == nullptr) {
        present = false;
    } else {
        present = true;
    }
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::openLogicalChannel(const std::vector<uint8_t>& aid, uint8_t p2,
    std::vector<uint8_t>& response, uint8_t& channelNumber, SecureElementStatus& status)
{
    HDF_LOGD("SeVendorAdaptions:%{public}s!", __func__);
    std::lock_guard<std::mutex> lock(g_mutex);
    if (aid.empty()) {
        HDF_LOGE("aid is null");
        status = SecureElementStatus::SE_ILLEGAL_PARAMETER_ERROR;
        return HDF_ERR_INVALID_PARAM;
    }
#ifdef SE_VENDOR_ADAPTION_USE_CA
    uint8_t res[RES_BUFFER_MAX_LENGTH] = {0};
    uint32_t resLen = RES_BUFFER_MAX_LENGTH;
    uint32_t channelCreated = MAX_CHANNEL_SIZE + 1;
    int ret = SecureElementCaProxy::GetInstance().VendorSecureElementCaOpenLogicalChannel(
        (uint8_t *)&aid[0], aid.size(), p2, res, &resLen, &channelCreated);
    for (uint32_t i = 0; i < resLen; i++) {
        response.push_back(res[i]);
    }
    if ((ret != SECURE_ELEMENT_CA_RET_OK) || (resLen < MIN_RES_LEN)) {
        HDF_LOGE("openLogicalChannel failed ret %{public}u", ret);
        status = SecureElementStatus::SE_GENERAL_ERROR;
        if (g_openedChannelCount == 0) {
            HDF_LOGI("openLogicalChannel: g_openedChannelCount = %{public}d, Uninit", g_openedChannelCount);
            SecureElementCaProxy::GetInstance().VendorSecureElementCaUninit();
        }
        return HDF_SUCCESS;
    }
    status = getStatusBySW(res[resLen - SW1_OFFSET], res[resLen - SW2_OFFSET]);
    if ((ret == SECURE_ELEMENT_CA_RET_OK) && (channelCreated < MAX_CHANNEL_NUM - 1) &&
        !g_openedChannels[channelCreated] && (status == SecureElementStatus::SE_SUCCESS)) {
        g_openedChannels[channelCreated] = true;
        g_openedChannelCount++;
    } else if (g_openedChannelCount == 0) { // If there are no channels remaining close secureElement
        HDF_LOGI("openLogicalChannel: g_openedChannelCount = %{public}d, Uninit", g_openedChannelCount);
        SecureElementCaProxy::GetInstance().VendorSecureElementCaUninit();
    }

    if (channelCreated <= MAX_CHANNEL_SIZE) {
        channelNumber = static_cast<uint8_t>(channelCreated);
    } else {
        HDF_LOGE("openLogicalChannel err, channelCreated = %{public}d", channelCreated);
    }
    HDF_LOGI("openLogicalChannel [%{public}d] status:[%{public}d], now has %{public}d channel inuse",
        channelNumber, static_cast<uint8_t>(status), g_openedChannelCount);
#endif
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::openBasicChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
    SecureElementStatus& status)
{
    HDF_LOGD("SeVendorAdaptions:%{public}s!", __func__);
    std::lock_guard<std::mutex> lock(g_mutex);
    if (aid.empty()) {
        HDF_LOGE("aid is null");
        status = SecureElementStatus::SE_ILLEGAL_PARAMETER_ERROR;
        return HDF_ERR_INVALID_PARAM;
    }
#ifdef SE_VENDOR_ADAPTION_USE_CA
    uint8_t res[RES_BUFFER_MAX_LENGTH] = {0};
    uint32_t resLen = RES_BUFFER_MAX_LENGTH;
    int ret = SecureElementCaProxy::GetInstance().VendorSecureElementCaOpenBasicChannel(
        (uint8_t *)&aid[0], aid.size(), res, &resLen);
    for (uint32_t i = 0; i < resLen; i++) {
        response.push_back(res[i]);
    }
    if ((ret != SECURE_ELEMENT_CA_RET_OK) || (resLen < MIN_RES_LEN)) {
        HDF_LOGE("openBasicChannel failed ret %{public}u", ret);
        status = SecureElementStatus::SE_GENERAL_ERROR;
        if (g_openedChannelCount == 0) {
            HDF_LOGI("openBasicChannel failed: g_openedChannelCount = %{public}d, Uninit", g_openedChannelCount);
            SecureElementCaProxy::GetInstance().VendorSecureElementCaUninit();
        }
        return HDF_SUCCESS;
    }
    status = getStatusBySW(res[resLen - SW1_OFFSET], res[resLen - SW2_OFFSET]);
    if ((ret == SECURE_ELEMENT_CA_RET_OK) && !g_openedChannels[0] && (status == SecureElementStatus::SE_SUCCESS)) {
        g_openedChannels[0] = true;
        g_openedChannelCount++;
    } else if (g_openedChannelCount == 0) {
        HDF_LOGI("openBasicChannel failed: g_openedChannelCount = %{public}d, Uninit", g_openedChannelCount);
        SecureElementCaProxy::GetInstance().VendorSecureElementCaUninit();
    }
    HDF_LOGI("openBasicChannel [0] status:[%{public}d], now has %{public}d channel inuse",
        static_cast<uint8_t>(status),
        g_openedChannelCount);
#endif
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::closeChannel(uint8_t channelNumber, SecureElementStatus& status)
{
    HDF_LOGD("SeVendorAdaptions:%{public}s!", __func__);
    std::lock_guard<std::mutex> lock(g_mutex);
#ifdef SE_VENDOR_ADAPTION_USE_CA
    int ret = SecureElementCaProxy::GetInstance().VendorSecureElementCaCloseChannel(channelNumber);
    if (ret != SECURE_ELEMENT_CA_RET_OK) {
        status = SecureElementStatus::SE_GENERAL_ERROR;
        HDF_LOGE("closeChannel failed ret %{public}u", ret);
        return HDF_SUCCESS;
    }
    HDF_LOGI("closeChannel: channelNumber = %{public}d", channelNumber);
    if (channelNumber < MAX_CHANNEL_NUM - 1 && g_openedChannels[channelNumber]) {
        g_openedChannels[channelNumber] = false;
        g_openedChannelCount--;
    }
    if (g_openedChannelCount == 0) {
        HDF_LOGI("closeChannel: g_openedChannelCount = %{public}d, Uninit", g_openedChannelCount);
        SecureElementCaProxy::GetInstance().VendorSecureElementCaUninit();
    }
    HDF_LOGI("closeChannel [%{public}d] succ, now has %{public}d channel inuse",
        channelNumber, g_openedChannelCount);
#endif
    status = SecureElementStatus::SE_SUCCESS;
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::transmit(const std::vector<uint8_t>& command, std::vector<uint8_t>& response,
    SecureElementStatus& status)
{
    HDF_LOGD("SeVendorAdaptions:%{public}s!", __func__);
    std::lock_guard<std::mutex> lock(g_mutex);
#ifdef SE_VENDOR_ADAPTION_USE_CA
    uint8_t res[RES_BUFFER_MAX_LENGTH] = {0};
    uint32_t resLen = RES_BUFFER_MAX_LENGTH;
    int ret = SecureElementCaProxy::GetInstance().VendorSecureElementCaTransmit(
        (uint8_t *)&command[0], command.size(), res, &resLen);
    for (uint32_t i = 0; i < resLen; i++) {
        response.push_back(res[i]);
    }
    if (ret != SECURE_ELEMENT_CA_RET_OK) {
        HDF_LOGE("transmit failed ret %{public}u", ret);
        status = SecureElementStatus::SE_GENERAL_ERROR;
        return HDF_SUCCESS;
    }
    if (resLen >= MIN_RES_LEN) {
        status = getStatusBySW(res[resLen - SW1_OFFSET], res[resLen - SW2_OFFSET]);
        return HDF_SUCCESS;
    }
    HDF_LOGE("transmit failed resLen %{public}d", resLen);
#endif
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::reset(SecureElementStatus& status)
{
    HDF_LOGI("SeVendorAdaptions:%{public}s!", __func__);
    HDF_LOGE("reset is not support");
    status = SecureElementStatus::SE_SUCCESS;
    return HDF_SUCCESS;
}

SecureElementStatus SeVendorAdaptions::getStatusBySW(uint8_t sw1, uint8_t sw2) const
{
    /* 0x9000, 0x62XX, 0x63XX Status is success */
    if ((sw1 == 0x90 && sw2 == 0x00) || (sw1 == 0x62) || (sw1 == 0x63)) {
        return SecureElementStatus::SE_SUCCESS;
    }
    /* 0x6A82, 0x6999, 0x6985 AID provided doesn't match any applet on the secure element */
    if ((sw1 == 0x6A && sw2 == 0x82) || (sw1 == 0x69 && (sw2 == 0x99 || sw2 == 0x85))) {
        return SecureElementStatus::SE_NO_SUCH_ELEMENT_ERROR;
    }
    /* 0x6A86 Operation provided by the P2 parameter is not permitted by the applet. */
    if (sw1 == 0x6A && sw2 == 0x86) {
        return SecureElementStatus::SE_OPERATION_NOT_SUPPORTED_ERROR;
    }
    HDF_LOGE("getStatusBySW fail, SW:0x%{public}02x%{public}02x", sw1, sw2);
    return SecureElementStatus::SE_GENERAL_ERROR;
}

void SeVendorAdaptions::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    HDF_LOGI("OnRemoteDied");
    // don't lock here, lock in closeChannel
#ifdef SE_VENDOR_ADAPTION_USE_CA
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    for (size_t i = 0; i < MAX_CHANNEL_NUM; i++) {
        if (g_openedChannels[i]) {
            closeChannel(i, status);
            HDF_LOGI("OnRemoteDied, close channel [%{public}zu], status = %{public}d", i, status);
        }
    }
#endif
    std::lock_guard<std::mutex> lock(g_mutex);
    g_callbackV1_0 = nullptr;
}

int32_t SeVendorAdaptions::AddSecureElementDeathRecipient(const sptr<ISecureElementCallback> &callbackObj)
{
    if (callbackObj == nullptr) {
        HDF_LOGE("SeVendorAdaptions AddSecureElementDeathRecipient callbackObj is nullptr");
        return HDF_FAILURE;
    }
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<ISecureElementCallback>(callbackObj);
    bool result = remote->AddDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("SeVendorAdaptions AddDeathRecipient failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::RemoveSecureElementDeathRecipient(const sptr<ISecureElementCallback> &callbackObj)
{
    if (callbackObj == nullptr) {
        HDF_LOGE("SeVendorAdaptions callbackObj is nullptr!");
        return HDF_FAILURE;
    }
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<ISecureElementCallback>(callbackObj);
    bool result = remote->RemoveDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("SeVendorAdaptions RemoveDeathRecipient failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
} // SecureElement
} // HDI
} // OHOS