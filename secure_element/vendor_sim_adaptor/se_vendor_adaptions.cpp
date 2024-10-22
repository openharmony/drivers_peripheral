/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "securec.h"

#define HDF_LOG_TAG hdf_sim_se

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD000305

namespace OHOS {
namespace HDI {
namespace SecureElement {
namespace SimSecureElement {
namespace V1_0 {
static sptr<ISecureElementCallback> g_callbackV1_0 = nullptr;
static std::mutex g_callbackMutex {};
static const int RES_BUFFER_MAX_LENGTH = 512;
static const uint16_t SW1_OFFSET = 2;
static const uint16_t SW2_OFFSET = 1;
static const uint16_t MAX_CHANNEL_NUM = 4;
uint16_t g_openedChannelCount = 0;
bool g_openedChannels[MAX_CHANNEL_NUM] = {false, false, false, false};
bool g_initFuncFlag = false;

SimSeVendorAdaptions::SimSeVendorAdaptions()
{
    HDF_LOGE("SimSeVendorAdaptions enter");
    remoteDeathRecipient_ =
        new RemoteDeathRecipient(std::bind(&SimSeVendorAdaptions::OnRemoteDied, this, std::placeholders::_1));
    InitFunc();
}

SimSeVendorAdaptions::~SimSeVendorAdaptions() {}

SimSeVendorAdaptions::DynamicLoad::DynamicLoad(const std::string &lib) : libPath_(lib) {}

SimSeVendorAdaptions::DynamicLoad::~DynamicLoad()
{
    (void)CloseLib();
}

bool SimSeVendorAdaptions::DynamicLoad::LoadLib()
{
    if (libPath_.empty() || handle_) {
        return false;
    }
    handle_ = dlopen(libPath_.c_str(), RTLD_LAZY | RTLD_LOCAL);
    if (!handle_) {
        HDF_LOGE("load %{public}s fail, %{public}s", libPath_.c_str(), dlerror());
        return false;
    }
    HDF_LOGI("load %{public}s success", libPath_.c_str());
    return true;
}

bool SimSeVendorAdaptions::DynamicLoad::CloseLib()
{
    if (handle_) {
        if (dlclose(handle_) != 0) {
            handle_ = nullptr;
            HDF_LOGE("close %{public}s fail, %{public}s", libPath_.c_str(), dlerror());
            return false;
        }
        handle_ = nullptr;
    }
    HDF_LOGI("close %{public}s success", libPath_.c_str());
    return true;
}

void SimSeVendorAdaptions::InitFunc()
{
    HDF_LOGE("SimSeVendorAdaptions::InitFunc enter!");
    if (!loader_) {
        loader_ = std::make_unique<DynamicLoad>(LIB_NAME);
        HDF_LOGE("SimSeVendorAdaptions::InitFunc enter %{public}s!", LIB_NAME);
        if (!loader_->LoadLib()) {
            return;
        }
    }
    vendorSimSecureElementInitFunc_ = loader_->FindTheFunc<VendorSimSecureElementInitT>(SIM_INIT_SYMBOL);
    vendorSimSecureElementUninitFunc_ = loader_->FindTheFunc<VendorSimSecureElementUninitT>(SIM_UNINIT_SYMBOL);
    vendorSimSecureElementIsCardPresentFunc_ = loader_->FindTheFunc<VendorSimSecureElementIsCardPresentT>(
        SIM_IS_CARD_PRESENT_SYMBOL);
    vendorSimSecureElementGetAtrFunc_ = loader_->FindTheFunc<VendorSimSecureElementGetAtrT>(SIM_GET_ATR_SYMBOL);
    vendorSimSecureElementOpenLogicalChannelFunc_ =
        loader_->FindTheFunc<VendorSimSecureElementOpenLogicalChannelT>(SIM_OPEN_LOGICAL_SYMBOL);
    vendorSimSecureElementOpenBasicChannelFunc_ =
        loader_->FindTheFunc<VendorSimSecureElementOpenBasicChannelT>(SIM_OPEN_BASIC_SYMBOL);
    vendorSimSecureElementCloseChannelFunc_ =
        loader_->FindTheFunc<VendorSimSecureElementCloseChannelT>(SIM_CLOSE_SYMBOL);
    vendorSimSecureElementTransmitFunc_ = loader_->FindTheFunc<VendorSimSecureElementTransmitT>(SIM_TRANS_SYMBOL);
    g_initFuncFlag = true;
    HDF_LOGE("SimSeVendorAdaptions::InitFunc exit!");
}

#define SIM_FUNCTION_INVOKE_RETURN(func, ...) \
    if (g_initFuncFlag == false) {           \
        InitFunc();                          \
    }                                        \
    if (func) {                              \
        return func(__VA_ARGS__);            \
    }                                        \
    HDF_LOGE("func is null!");               \
    return SIM_SECURE_ELEMENT_RET_LOAD_FAIL

int SimSeVendorAdaptions::VendorSimSecureElementInit()
{
    HDF_LOGE("SimSeVendorAdaptions::VendorSimSecureElementInit %{public}x", g_initFuncFlag);
    SIM_FUNCTION_INVOKE_RETURN(vendorSimSecureElementInitFunc_);
}

int SimSeVendorAdaptions::VendorSimSecureElementUninit()
{
    HDF_LOGI("SimSeVendorAdaptions::VendorSimSecureElementUninit");
    std::lock_guard<std::mutex> guard(g_callbackMutex);
    RemoveSecureElementDeathRecipient(g_callbackV1_0);
    SIM_FUNCTION_INVOKE_RETURN(vendorSimSecureElementUninitFunc_);
}

int SimSeVendorAdaptions::VendorSimSecureElementGetAtr(uint8_t *rsp, uint32_t *rspLen)
{
    SIM_FUNCTION_INVOKE_RETURN(vendorSimSecureElementGetAtrFunc_, rsp, rspLen);
}

int SimSeVendorAdaptions::VendorSimSecureElementOpenLogicalChannel(
    const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response, uint32_t *channelNum, int *status)
{
    uint8_t arrAid[RES_BUFFER_MAX_LENGTH];
    uint32_t aidLen = aid.size();
    uint8_t rsp[RES_BUFFER_MAX_LENGTH];
    uint32_t rspLen = 0;
    uint32_t i;
    int ret;
    if (aidLen > RES_BUFFER_MAX_LENGTH) {
        HDF_LOGE("SimSeVendorAdaptions::VendorSimSecureElementOpenLogicalChannel invalid param %{public}x",
            aidLen);
        return SIM_SECURE_ELEMENT_RET_CONTEXT_FAIL;
    }
    for (i = 0; i < aidLen; i++) {
        arrAid[i] = aid[i];
    }
    if (g_initFuncFlag == false) {
        InitFunc();
    }
    if (vendorSimSecureElementOpenLogicalChannelFunc_) {
        ret = vendorSimSecureElementOpenLogicalChannelFunc_(arrAid, aidLen, p2, rsp, &rspLen, channelNum, status);
        if (!ret && rspLen) {
            response.resize(rspLen);
            for (i = 0; i < rspLen; i++) {
                response.push_back(rsp[i]);
            }
        }
        return ret;
    }
    return SIM_SECURE_ELEMENT_RET_LOAD_FAIL;
}

int SimSeVendorAdaptions::VendorSimSecureElementOpenBasicChannel(
    uint8_t *aid, uint32_t len, uint8_t *rsp, uint32_t *rspLen, int *status)
{
    SIM_FUNCTION_INVOKE_RETURN(vendorSimSecureElementOpenBasicChannelFunc_, aid, len, rsp, rspLen, status);
}

int SimSeVendorAdaptions::VendorSimSecureElementCloseChannel(uint32_t channelNum, int *status)
{
    SIM_FUNCTION_INVOKE_RETURN(vendorSimSecureElementCloseChannelFunc_, channelNum, status);
}

int SimSeVendorAdaptions::VendorSimSecureElementTransmit(
    uint8_t *cmd, uint32_t cmdLen, uint8_t *rsp, uint32_t *rspLen, int *status)
{
    SIM_FUNCTION_INVOKE_RETURN(vendorSimSecureElementTransmitFunc_, cmd, cmdLen, rsp, rspLen, status);
}

int32_t SimSeVendorAdaptions::init(
    const sptr<OHOS::HDI::SecureElement::SimSecureElement::V1_0::ISecureElementCallback>& clientCallback,
    OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status)
{
    HDF_LOGI("SimSeVendorAdaptions:%{public}s!", __func__);
    if (clientCallback == nullptr) {
        HDF_LOGE("init failed, clientCallback is null");
        status = SecureElementStatus::SE_NULL_POINTER_ERROR;
        return HDF_ERR_INVALID_PARAM;
    }
    g_openedChannelCount = 0;
    int ret = VendorSimSecureElementInit();
    if (ret != SIM_SECURE_ELEMENT_RET_OK) {
        HDF_LOGE("VendorSimSecureElementInit failed ret %{public}u", ret);
        status = SecureElementStatus::SE_GENERAL_ERROR;
        return HDF_ERR_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> guard(g_callbackMutex);
    g_callbackV1_0 = clientCallback;
    g_callbackV1_0->OnSeStateChanged(true);
    AddSecureElementDeathRecipient(g_callbackV1_0);
    status = SecureElementStatus::SE_SUCCESS;
    return HDF_SUCCESS;
}

int32_t SimSeVendorAdaptions::getAtr(std::vector<uint8_t>& response)
{
    HDF_LOGI("SimSeVendorAdaptions:%{public}s!", __func__);
    uint8_t res[RES_BUFFER_MAX_LENGTH] = {0};
    uint32_t resLen = RES_BUFFER_MAX_LENGTH;
    int ret = VendorSimSecureElementGetAtr(res, &resLen);
    if (ret != SIM_SECURE_ELEMENT_RET_OK) {
        HDF_LOGE("getAtr failed ret %{public}u", ret);
        return HDF_SUCCESS;
    }
    for (uint32_t i = 0; i < resLen; i++) {
        response.push_back(res[i]);
    }
    return HDF_SUCCESS;
}

int32_t SimSeVendorAdaptions::isSecureElementPresent(bool& present)
{
    HDF_LOGI("SimSeVendorAdaptions:%{public}s!", __func__);
    present = vendorSimSecureElementIsCardPresentFunc_();
    return HDF_SUCCESS;
}

int32_t SimSeVendorAdaptions::openLogicalChannel(const std::vector<uint8_t>& aid, uint8_t p2,
    std::vector<uint8_t>& response, uint8_t& channelNumber, SecureElementStatus& status)
{
    int tmpStatus;
    HDF_LOGI("SimSeVendorAdaptions:%{public}s!", __func__);
    if (aid.empty()) {
        HDF_LOGE("aid is null");
        status = SecureElementStatus::SE_ILLEGAL_PARAMETER_ERROR;
        return HDF_ERR_INVALID_PARAM;
    }
    uint8_t res[RES_BUFFER_MAX_LENGTH] = {0};
    uint32_t resLen = RES_BUFFER_MAX_LENGTH;
    int ret = VendorSimSecureElementOpenLogicalChannel(aid, p2, response, (uint32_t *)&channelNumber, &tmpStatus);
    HDF_LOGE("VendorSimSecureElementOpenLogicalChannel ret %{public}u, tmpStatus = %{public}d", ret, tmpStatus);
    if (ret != SIM_SECURE_ELEMENT_RET_OK) {
        HDF_LOGE("openLogicalChannel failed ret %{public}u, tmpStatus = %{public}d", ret, tmpStatus);
        if (g_openedChannelCount == 0) {
            HDF_LOGI("openLogicalChannel: g_openedChannelCount = %{public}d, Uninit", g_openedChannelCount);
            VendorSimSecureElementUninit();
        }
        return HDF_SUCCESS;
    }
    status = (SecureElementStatus)tmpStatus;
    resLen = response.size();
    for (uint32_t i = 0; i < resLen; i++) {
        response.push_back(res[i]);
    }
    if (ret == SIM_SECURE_ELEMENT_RET_OK && resLen >= SW1_OFFSET &&
        channelNumber < MAX_CHANNEL_NUM - 1 && !g_openedChannels[channelNumber]) {
        if ((response[resLen - SW1_OFFSET] == 0x90 && response[resLen - SW2_OFFSET] == 0x00)
            || response[resLen - SW2_OFFSET] == 0x62 || response[resLen - SW2_OFFSET] == 0x63) {
            g_openedChannels[channelNumber] = true;
            g_openedChannelCount++;
        }
    }
    return HDF_SUCCESS;
}

int32_t SimSeVendorAdaptions::openBasicChannel(const std::vector<uint8_t>& aid, uint8_t p2,
    std::vector<uint8_t>& response, SecureElementStatus& status)
{
    int tmpStatus;
    HDF_LOGI("SimSeVendorAdaptions:%{public}s!", __func__);
    if (aid.empty()) {
        HDF_LOGE("aid is null");
        status = SecureElementStatus::SE_ILLEGAL_PARAMETER_ERROR;
        return HDF_ERR_INVALID_PARAM;
    }
    uint8_t res[RES_BUFFER_MAX_LENGTH] = {0};
    uint32_t resLen = RES_BUFFER_MAX_LENGTH;
    int ret = VendorSimSecureElementOpenBasicChannel(
        (uint8_t *)&aid[0], aid.size(), res, &resLen, &tmpStatus);
    if (ret != SIM_SECURE_ELEMENT_RET_OK) {
        HDF_LOGE("openBasicChannel failed ret %{public}u, tmpStatus = %{public}d", ret, tmpStatus);
        if (g_openedChannelCount == 0) {
            HDF_LOGI("openBasicChannel failed: g_openedChannelCount = %{public}d, Uninit", g_openedChannelCount);
            VendorSimSecureElementUninit();
        }
        return HDF_SUCCESS;
    }
    status = (SecureElementStatus)tmpStatus;
    resLen = response.size();
    for (uint32_t i = 0; i < resLen; i++) {
        response.push_back(res[i]);
    }
    if (ret == SIM_SECURE_ELEMENT_RET_OK && resLen >= SW1_OFFSET && !g_openedChannels[0]) {
        if (response[resLen - SW1_OFFSET] == 0x90 && response[resLen - SW2_OFFSET] == 0x00) {
            g_openedChannels[0] = true;
            g_openedChannelCount++;
        }
    }
    return HDF_SUCCESS;
}

int32_t SimSeVendorAdaptions::closeChannel(uint8_t channelNumber, SecureElementStatus& status)
{
    int tmpStatus;
    HDF_LOGI("SimSeVendorAdaptions:%{public}s!", __func__);
    int ret = VendorSimSecureElementCloseChannel(channelNumber, &tmpStatus);
    status = (SecureElementStatus)tmpStatus;
    if (ret != SIM_SECURE_ELEMENT_RET_OK) {
        HDF_LOGE("closeChannel failed ret %{public}u, tmpStatus = %{public}d", ret, tmpStatus);
        return HDF_SUCCESS;
    }
    HDF_LOGI("closeChannel: channelNumber = %{public}d", channelNumber);
    if (channelNumber < MAX_CHANNEL_NUM - 1 && g_openedChannels[channelNumber]) {
        g_openedChannels[channelNumber] = false;
        g_openedChannelCount--;
    }
    if (g_openedChannelCount == 0) {
        HDF_LOGI("closeChannel: g_openedChannelCount = %{public}d, Uninit", g_openedChannelCount);
        VendorSimSecureElementUninit();
    }
    return HDF_SUCCESS;
}

int32_t SimSeVendorAdaptions::transmit(const std::vector<uint8_t>& command, std::vector<uint8_t>& response,
    SecureElementStatus& status)
{
    int tmpStatus;
    HDF_LOGI("SimSeVendorAdaptions:%{public}s!", __func__);
    uint8_t res[RES_BUFFER_MAX_LENGTH] = {0};
    uint32_t resLen = RES_BUFFER_MAX_LENGTH;
    int ret = VendorSimSecureElementTransmit(
        (uint8_t *)&command[0], command.size(), res, &resLen, &tmpStatus);
    if (ret != SIM_SECURE_ELEMENT_RET_OK) {
        HDF_LOGE("transmit failed ret %{public}u, tmpStatus = %{public}d", ret, tmpStatus);
        return HDF_SUCCESS;
    }
    status = (SecureElementStatus)tmpStatus;
    for (uint32_t i = 0; i < resLen; i++) {
        response.push_back(res[i]);
    }
    return HDF_SUCCESS;
}

int32_t SimSeVendorAdaptions::reset(SecureElementStatus& status)
{
    HDF_LOGI("SimSeVendorAdaptions:%{public}s!", __func__);
    HDF_LOGE("reset is not support");
    status = SecureElementStatus::SE_SUCCESS;
    return HDF_SUCCESS;
}

void SimSeVendorAdaptions::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    HDF_LOGI("SimSeVendorAdaptions::OnRemoteDied");
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    for (size_t i = 0; i < MAX_CHANNEL_NUM; i++) {
        if (g_openedChannels[i]) {
            closeChannel(i, status);
            HDF_LOGI("OnRemoteDied, close channel [%{public}zu], status = %{public}d", i, status);
        }
    }
    std::lock_guard<std::mutex> guard(g_callbackMutex);
    g_callbackV1_0 = nullptr;
}

int32_t SimSeVendorAdaptions::AddSecureElementDeathRecipient(const sptr<ISecureElementCallback> &callbackObj)
{
    if (callbackObj == nullptr) {
        HDF_LOGE("SimSeVendorAdaptions AddSecureElementDeathRecipient callbackObj is nullptr");
        return HDF_FAILURE;
    }
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<ISecureElementCallback>(callbackObj);
    bool result = remote->AddDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("SimSeVendorAdaptions AddDeathRecipient failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SimSeVendorAdaptions::RemoveSecureElementDeathRecipient(const sptr<ISecureElementCallback> &callbackObj)
{
    if (callbackObj == nullptr) {
        HDF_LOGE("SimSeVendorAdaptions callbackObj is nullptr!");
        return HDF_FAILURE;
    }
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<ISecureElementCallback>(callbackObj);
    bool result = remote->RemoveDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("SimSeVendorAdaptions RemoveDeathRecipient failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
}
}
} // SecureElement
} // HDI
} // OHOS