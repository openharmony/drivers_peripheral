/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define HDF_LOG_TAG hdf_nfc_dal

namespace OHOS {
namespace HDI {
namespace Nfc {
namespace NfcCore {
namespace V1_0 {
extern "C" INfcInterface *NfcImplGetInstance(void)
{
    using OHOS::HDI::Nfc::NfcCore::V1_0::NfcImpl;
    NfcImpl *service = new (std::nothrow) NfcImpl();
    if (service == nullptr) {
        return nullptr;
    }
    return service;
}

int32_t NfcImpl::Open(const sptr<INfcCallback> &callbackObj, NfcStatus &status)
{
    if (callbackObj == nullptr) {
        HDF_LOGE("%{public}s: callback is nullptr!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s: vendor hal adaptor not available", __func__);
    return HDF_SUCCESS;
}

int32_t NfcImpl::CoreInitialized(const sptr<INfcCallback> &callbackObj, NfcStatus &status)
{
    if (callbackObj == nullptr) {
        HDF_LOGE("%{public}s: callback is nullptr!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s: vendor hal adaptor not available", __func__);
    return HDF_SUCCESS;
}

int32_t NfcImpl::Prediscover(NfcStatus &status)
{
    HDF_LOGI("%{public}s: vendor hal adaptor not available", __func__);
    return HDF_SUCCESS;
}

int32_t NfcImpl::Write(const std::vector<uint8_t> &data, NfcStatus &status)
{
    if (data.empty()) {
        HDF_LOGE("%{public}s: data is nullptr!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s: vendor hal adaptor not available", __func__);
    return HDF_SUCCESS;
}

int32_t NfcImpl::ControlGranted(NfcStatus &status)
{
    HDF_LOGI("%{public}s: vendor hal adaptor not available", __func__);
    return HDF_SUCCESS;
}

int32_t NfcImpl::PowerCycle(NfcStatus &status)
{
    HDF_LOGI("%{public}s: vendor hal adaptor not available", __func__);
    return HDF_SUCCESS;
}

int32_t NfcImpl::Close(NfcStatus &status)
{
    HDF_LOGI("%{public}s: vendor hal adaptor not available", __func__);
    return HDF_SUCCESS;
}

int32_t NfcImpl::Ioctl(NfcCommand cmd, const std::vector<uint8_t> &data, NfcStatus &status)
{
    if (data.empty()) {
        HDF_LOGE("%{public}s: data is nullptr!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s: vendor hal adaptor not available", __func__);
    return HDF_SUCCESS;
}
} // V1_0
} // NfcCore
} // Nfc
} // HDI
} // OHOS
