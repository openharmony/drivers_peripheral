/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "connected_nfc_tag_impl.h"
#include <mutex>
#include <hdf_base.h>
#include <hdf_log.h>
#include <iproxy_broker.h>
#include "v1_1/connected_nfc_tag_service.h"
#include "connected_nfc_tag_vendor_adapter.h"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD000307
#define HDF_LOG_TAG NFCTAG_IMPL

namespace OHOS {
namespace HDI {
namespace ConnectedNfcTag {
namespace V1_1 {

static sptr<OHOS::HDI::ConnectedNfcTag::V1_1::IConnectedNfcTagCallback> g_callbackV1_1 = nullptr;
static std::mutex g_callbackMutex {};
static const int MAX_NDEF_LEN = 256;

static int EventCallback(uint8_t event, uint8_t *buff, uint32_t buffLen)
{
    std::lock_guard<std::mutex> guard(g_callbackMutex);
    if (g_callbackV1_1 != nullptr && buff != nullptr && buffLen > 0) {
        std::vector<uint8_t> data(buff, buff + buffLen);
        g_callbackV1_1->OnChipEvent((ConnectedNfcTagEvent)event, data);
    }
    return 0;
}

extern "C" IConnectedNfcTag *ConnectedNfcTagImplGetInstance(void)
{
    return new (std::nothrow) ConnectedNfcTagImpl();
}

ConnectedNfcTagImpl::ConnectedNfcTagImpl()
{
    remoteDeathRecipient_ =
        new RemoteDeathRecipient(std::bind(&ConnectedNfcTagImpl::OnRemoteDied, this, std::placeholders::_1));
}

ConnectedNfcTagImpl::~ConnectedNfcTagImpl()
{
    std::lock_guard<std::mutex> guard(g_callbackMutex);
    if (callbackObj_ != nullptr) {
        RemoveDeathRecipient(callbackObj_);
        callbackObj_ = nullptr;
    }
    g_callbackV1_1 = nullptr;
}

int32_t ConnectedNfcTagImpl::RegisterCallBack(
    const sptr<OHOS::HDI::ConnectedNfcTag::V1_1::IConnectedNfcTagCallback>& callbackObj)
{
    HDF_LOGI("%{public}s", __func__);

    {
        std::lock_guard<std::mutex> lock(g_callbackMutex);
        if (callbackObj_ != nullptr) {
            RemoveDeathRecipient(callbackObj_);
            callbackObj_ = nullptr;
            g_callbackV1_1 = nullptr;
        }
    }
    if (callbackObj == nullptr) {
        HDF_LOGW("%{public}s: callbackObj NULL", __func__);
    } else {
        callbackObj_ = callbackObj;
        g_callbackV1_1 = callbackObj;
        AddDeathRecipient(callbackObj_);
    }
    
    if (callbackObj == nullptr) {
        return adapter.RegisterCallBack(nullptr);
    }
    return adapter.RegisterCallBack(EventCallback);
}

int32_t ConnectedNfcTagImpl::Init()
{
    HDF_LOGI("%{public}s", __func__);
    return adapter.Init();
}

int32_t ConnectedNfcTagImpl::Uninit()
{
    HDF_LOGI("%{public}s", __func__);
    return adapter.UnInit();
}
int32_t ConnectedNfcTagImpl::ReadNdefData(std::vector<uint8_t> &ndefData)
{
    HDF_LOGI("%{public}s", __func__);
    return adapter.ReadNdefData(ndefData);
}

int32_t ConnectedNfcTagImpl::WriteNdefData(const std::vector<uint8_t>& ndefData)
{
    HDF_LOGI("%{public}s, size = %{public}lu", __func__, ndefData.size());
    if (ndefData.empty()) {
        HDF_LOGE("%{public}s: ndefData empty", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (ndefData.size() > MAX_NDEF_LEN) {
        HDF_LOGE("%{public}s: ndefData size exceeds MAX_NDEF_LEN", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return adapter.WriteNdefData(ndefData);
}

int32_t ConnectedNfcTagImpl::ReadNdefTag(std::string &ndefData)
{
    HDF_LOGW("%{public}s !!!deprecated!!!", __func__);
    return -1;
}

int32_t ConnectedNfcTagImpl::WriteNdefTag(const std::string &ndefData)
{
    HDF_LOGW("%{public}s !!!deprecated!!!", __func__);
    return -1;
}

void ConnectedNfcTagImpl::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    HDF_LOGW("%{public}s: callback process died, cleaning up", __func__);
    {
        std::lock_guard<std::mutex> guard(g_callbackMutex);
        if (callbackObj_ != nullptr) {
            RemoteDeathRecipient(callbackObj_);
            callbackObj_ = nullptr;
        }
        g_callbackV1_1 == nullptr;
    }
    adapter.RegisterCallBack(nullptr);
}

int32_t ConnectedNfcTagImpl::AddDeathRecipient(
    const sptr<OHOS::HDI::ConnectedNfcTag::V1_1::IConnectedNfcTagCallback>& callbackObj)
{
    if (callbackObj ==  nullptr) {
        HDF_LOGE("%{public}s: callbackObj nullptr", __func__);
        return HDF_FAILURE;
    }
    const stpr<IRemoteObject> &remote =
        OHOS::HDI::hdi_objcast<OHOS::HDI::ConnectedNfcTag::V1_1::IConnectedNfcTagCallback>(callbackObj);
    if (remote == nullptr) {
        HDF_LOGE("%{public}s: remote nullptr", __func__);
        return HDF_FAILURE;
    }
    bool result = remote->AddDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("%{public}s: AddDeathRecipient failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ConnectedNfcTagImpl::RemoveDeathRecipient(
    const sptr<OHOS::HDI::ConnectedNfcTag::V1_1::IConnectedNfcTagCallback>& callbackObj)
{
    if (callbackObj == nullptr) {
        HDF_LOGE("%{public}s: callbackObj nullptr", __func__);
        return HDF_FAILURE;
    }
    const stpr<IRemoteObject> &remote =
        OHOS::HDI::hdi_objcast<OHOS::HDI::ConnectedNfcTag::V1_1::IConnectedNfcTagCallback>(callbackObj);
    if (remote == nullptr) {
        HDF_LOGE("%{public}s: remote nullptr", __func__);
        return HDF_FAILURE;
    }
    bool result = remote->RemoveDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("%{public}s: RemoveDeathRecipient failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;    
}

}  // namespace V1_1
}  // namespace ConnectedNfcTag
}  // namespace HDI
}  // namespace OHOS
