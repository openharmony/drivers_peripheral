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

#include "secure_element_ca_proxy.h"

#define HDF_LOG_TAG hdf_se

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD000305

namespace OHOS {
namespace HDI {
namespace SecureElement {
SecureElementCaProxy::SecureElementCaProxy()
{
    InitFunc();
}

SecureElementCaProxy::DynamicLoad::DynamicLoad(const std::string &lib) : libPath_(lib) {}

SecureElementCaProxy::DynamicLoad::~DynamicLoad()
{
    (void)CloseLib();
}

bool SecureElementCaProxy::DynamicLoad::LoadLib()
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

bool SecureElementCaProxy::DynamicLoad::CloseLib()
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

void SecureElementCaProxy::InitFunc()
{
    if (!loader_) {
        loader_ = std::make_unique<DynamicLoad>(LIB_NAME);
        if (!loader_->LoadLib()) {
            return;
        }
    }
    vendorSecureElementCaOnStartFunc_ = loader_->FindTheFunc<VendorSecureElementCaOnStartT>(CA_ON_START_SYMBOL);
    vendorSecureElementCaInitFunc_ = loader_->FindTheFunc<VendorSecureElementCaInitT>(CA_INIT_SYMBOL);
    vendorSecureElementCaUninitFunc_ = loader_->FindTheFunc<VendorSecureElementCaUninitT>(CA_UNINIT_SYMBOL);
    vendorSecureElementCaGetAtrFunc_ = loader_->FindTheFunc<VendorSecureElementCaGetAtrT>(CA_GET_ATR_SYMBOL);
    vendorSecureElementCaOpenLogicalChannelFunc_ =
        loader_->FindTheFunc<VendorSecureElementCaOpenLogicalChannelT>(CA_OPEN_LOGICAL_SYMBOL);
    vendorSecureElementCaOpenBasicChannelFunc_ =
        loader_->FindTheFunc<VendorSecureElementCaOpenBasicChannelT>(CA_OPEN_BASIC_SYMBOL);
    vendorSecureElementCaCloseChannelFunc_ =
        loader_->FindTheFunc<VendorSecureElementCaCloseChannelT>(CA_CLOSE_SYMBOL);
    vendorSecureElementCaTransmitFunc_ = loader_->FindTheFunc<VendorSecureElementCaTransmitT>(CA_TRANS_SYMBOL);
}

#define CA_FUNCTION_INVOKE_RETURN(func, ...) \
    if (func) {                              \
        return func(__VA_ARGS__);            \
    }                                        \
    HDF_LOGE("func is null!");               \
    return SECURE_ELEMENT_CA_RET_LOAD_FAIL

int SecureElementCaProxy::VendorSecureElementCaOnStart() const
{
    CA_FUNCTION_INVOKE_RETURN(vendorSecureElementCaOnStartFunc_);
}

int SecureElementCaProxy::VendorSecureElementCaInit() const
{
    CA_FUNCTION_INVOKE_RETURN(vendorSecureElementCaInitFunc_);
}

int SecureElementCaProxy::VendorSecureElementCaUninit() const
{
    CA_FUNCTION_INVOKE_RETURN(vendorSecureElementCaUninitFunc_);
}

int SecureElementCaProxy::VendorSecureElementCaGetAtr(uint8_t *rsp, uint32_t *rspLen) const
{
    CA_FUNCTION_INVOKE_RETURN(vendorSecureElementCaGetAtrFunc_, rsp, rspLen);
}

int SecureElementCaProxy::VendorSecureElementCaOpenLogicalChannel(
    uint8_t *aid, uint32_t len, uint8_t p2, uint8_t *rsp, uint32_t *rspLen, uint32_t *channelNum) const
{
    CA_FUNCTION_INVOKE_RETURN(vendorSecureElementCaOpenLogicalChannelFunc_, aid, len, p2, rsp, rspLen, channelNum);
}

int SecureElementCaProxy::VendorSecureElementCaOpenBasicChannel(
    uint8_t *aid, uint32_t len, uint8_t *rsp, uint32_t *rspLen) const
{
    CA_FUNCTION_INVOKE_RETURN(vendorSecureElementCaOpenBasicChannelFunc_, aid, len, rsp, rspLen);
}

int SecureElementCaProxy::VendorSecureElementCaCloseChannel(uint32_t channelNum) const
{
    CA_FUNCTION_INVOKE_RETURN(vendorSecureElementCaCloseChannelFunc_, channelNum);
}

int SecureElementCaProxy::VendorSecureElementCaTransmit(
    uint8_t *cmd, uint32_t cmdLen, uint8_t *rsp, uint32_t *rspLen) const
{
    CA_FUNCTION_INVOKE_RETURN(vendorSecureElementCaTransmitFunc_, cmd, cmdLen, rsp, rspLen);
}

}  // SecureElement
}  // HDI
}  // OHOS