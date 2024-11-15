/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "nfc_impl.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <iproxy_broker.h>
#include <vector>
#include "nfc_vendor_adaptions.h"

#define HDF_LOG_TAG hdf_nfc_dal

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD000306

namespace OHOS {
namespace HDI {
namespace Nfc {
namespace V1_1 {
static sptr<INfcCallback> g_callbackV1_1 = nullptr;

static void EventCallback(unsigned char event, unsigned char status)
{
    if (g_callbackV1_1 != nullptr) {
        g_callbackV1_1->OnEvent((NfcEvent)event, (NfcStatus)status);
    }
}

static void DataCallback(uint16_t len, uint8_t *data)
{
    if (g_callbackV1_1 != nullptr) {
        std::vector<uint8_t> vec(data, data + len / sizeof(uint8_t));
        g_callbackV1_1->OnData(vec);
    }
}

extern "C" INfcInterface *NfcInterfaceImplGetInstance(void)
{
    using OHOS::HDI::Nfc::V1_1::NfcImpl;
    NfcImpl *service = new (std::nothrow) NfcImpl();
    if (service == nullptr) {
        return nullptr;
    }
    return service;
}

NfcImpl::NfcImpl()
{
    remoteDeathRecipient_ =
        new RemoteDeathRecipient(std::bind(&NfcImpl::OnRemoteDied, this, std::placeholders::_1));
}

NfcImpl::~NfcImpl()
{
    if (callbacks_ != nullptr) {
        RemoveNfcDeathRecipient(callbacks_);
        callbacks_ = nullptr;
    }
}

int32_t NfcImpl::Open(const sptr<INfcCallback> &callbackObj, NfcStatus &status)
{
    if (callbackObj == nullptr) {
        HDF_LOGE("Open, callback is nullptr!");
        return HDF_ERR_INVALID_PARAM;
    }
    g_callbackV1_1 = callbackObj;

    int ret = adaptor_.VendorOpen(EventCallback, DataCallback);
    if (ret == 0) {
        callbacks_ = callbackObj;
        AddNfcDeathRecipient(callbacks_);
        status = NfcStatus::OK;
        return HDF_SUCCESS;
    }
    status = NfcStatus::FAILED;
    return HDF_FAILURE;
}

int32_t NfcImpl::CoreInitialized(const std::vector<uint8_t> &data, NfcStatus &status)
{
    if (data.empty()) {
        HDF_LOGE("CoreInitialized, data is nullptr!");
        return HDF_ERR_INVALID_PARAM;
    }
    int ret = adaptor_.VendorCoreInitialized(data.size(), (uint8_t *)&data[0]);
    if (ret == 0) {
        status = NfcStatus::OK;
        return HDF_SUCCESS;
    }
    status = NfcStatus::FAILED;
    return HDF_FAILURE;
}

int32_t NfcImpl::Prediscover(NfcStatus &status)
{
    int ret = adaptor_.VendorPrediscover();
    if (ret == 0) {
        status = NfcStatus::OK;
        return HDF_SUCCESS;
    }
    status = NfcStatus::FAILED;
    return HDF_FAILURE;
}

int32_t NfcImpl::Write(const std::vector<uint8_t> &data, NfcStatus &status)
{
    if (data.empty()) {
        HDF_LOGE("Write, data is nullptr!");
        return HDF_ERR_INVALID_PARAM;
    }
    int ret = adaptor_.VendorWrite(data.size(), (uint8_t *)&data[0]);
    if (ret == 0) {
        status = NfcStatus::OK;
        return HDF_SUCCESS;
    }
    status = NfcStatus::FAILED;
    return HDF_FAILURE;
}

int32_t NfcImpl::ControlGranted(NfcStatus &status)
{
    int ret = adaptor_.VendorControlGranted();
    if (ret == 0) {
        status = NfcStatus::OK;
        return HDF_SUCCESS;
    }
    status = NfcStatus::FAILED;
    return HDF_FAILURE;
}

int32_t NfcImpl::PowerCycle(NfcStatus &status)
{
    int ret = adaptor_.VendorPowerCycle();
    if (ret == 0) {
        status = NfcStatus::OK;
        return HDF_SUCCESS;
    }
    status = NfcStatus::FAILED;
    return HDF_FAILURE;
}

int32_t NfcImpl::Close(NfcStatus &status)
{
    int ret = adaptor_.VendorClose(false);
    g_callbackV1_1 = nullptr;
    if (callbacks_ != nullptr) {
        RemoveNfcDeathRecipient(callbacks_);
        callbacks_ = nullptr;
    }
    if (ret == 0) {
        status = NfcStatus::OK;
        return HDF_SUCCESS;
    }
    status = NfcStatus::FAILED;
    return HDF_FAILURE;
}

int32_t NfcImpl::Ioctl(NfcCommand cmd, const std::vector<uint8_t> &data, NfcStatus &status)
{
    if (data.empty()) {
        HDF_LOGE("Ioctl, data is nullptr!");
        return HDF_ERR_INVALID_PARAM;
    }
    int ret = adaptor_.VendorIoctl(data.size(), (uint8_t *)&data[0]);
    if (ret == 0) {
        status = NfcStatus::OK;
        return HDF_SUCCESS;
    }
    status = NfcStatus::FAILED;
    return HDF_FAILURE;
}

int32_t NfcImpl::IoctlWithResponse(NfcCommand cmd, const std::vector<uint8_t> &data,
    std::vector<uint8_t> &response, NfcStatus &status)
{
    if (data.empty()) {
        HDF_LOGE("NfcImpl::IoctlWithResponse, data is nullptr!");
        return HDF_ERR_INVALID_PARAM;
    }
    int ret = adaptor_.VendorIoctlWithResponse(cmd, (void*)&data[0], data.size(), response);
    if (ret == 0) {
        status = NfcStatus::OK;
        return HDF_SUCCESS;
    }
    status = NfcStatus::FAILED;
    return HDF_FAILURE;
}

int32_t NfcImpl::GetVendorConfig(NfcVendorConfig &config, NfcStatus &status)
{
    if (adaptor_.VendorGetConfig(config) != HDF_SUCCESS) {
        HDF_LOGE("GetConfig, fail to get vendor config!");
        status = NfcStatus::FAILED;
        return HDF_FAILURE;
    }
    status = NfcStatus::OK;
    return HDF_SUCCESS;
}

int32_t NfcImpl::DoFactoryReset(NfcStatus &status)
{
    int ret = adaptor_.VendorFactoryReset();
    if (ret == 0) {
        status = NfcStatus::OK;
        return HDF_SUCCESS;
    }
    status = NfcStatus::FAILED;
    return HDF_FAILURE;
}

int32_t NfcImpl::Shutdown(NfcStatus &status)
{
    int ret = adaptor_.VendorShutdownCase();
    if (ret == 0) {
        status = NfcStatus::OK;
        return HDF_SUCCESS;
    }
    status = NfcStatus::FAILED;
    return HDF_FAILURE;
}

void NfcImpl::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    callbacks_ = nullptr;
    NfcStatus status = NfcStatus::FAILED;
    int32_t ret = Close(status);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("OnRemoteDied, Close failed, status(%{public}d)!", status);
    }
}

int32_t NfcImpl::AddNfcDeathRecipient(const sptr<INfcCallback> &callbackObj)
{
    if (callbackObj == nullptr) {
        HDF_LOGE("AddNfcDeathRecipient callbackobj nullptr");
        return HDF_FAILURE;
    }
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<INfcCallback>(callbackObj);
    if (remote == nullptr) {
        HDF_LOGE("AddNfcDeathRecipient remote nullptr");
        return HDF_FAILURE;
    }
    bool result = remote->AddDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("NfcImpl AddDeathRecipient failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t NfcImpl::RemoveNfcDeathRecipient(const sptr<INfcCallback> &callbackObj)
{
    if (callbackObj == nullptr) {
        HDF_LOGE("RemoveNfcDeathRecipient callbackobj nullptr");
        return HDF_FAILURE;
    }
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<INfcCallback>(callbackObj);
    if (remote == nullptr) {
        HDF_LOGE("RemoveNfcDeathRecipient remote nullptr");
        return HDF_FAILURE;
    }
    bool result = remote->RemoveDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("NfcImpl RemoveDeathRecipient failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
} // V1_1
} // Nfc
} // HDI
} // OHOS
