/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "nfc_vendor_adaptions.h"
#include <dlfcn.h>
#include <fstream>
#include <hdf_base.h>
#include <hdf_log.h>
#include <iostream>
#include <string>

#define HDF_LOG_TAG hdf_nfc_dal

using namespace std;

namespace OHOS {
namespace HDI {
namespace Nfc {
static string GetNfcHalSoName(string chipType)
{
    string nfcHalSoName = NFC_HAL_SO_PREFIX + chipType + NFC_HAL_SO_SUFFIX;
    return nfcHalSoName;
}

string NfcVendorAdaptions::GetChipType(void)
{
    string nfcChipType = "";
    nfcExtHandle = dlopen(VENDOR_NFC_EXT_SERVICE_LIB.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (nfcExtHandle == nullptr) {
        HDF_LOGE("%{public}s: fail to get nfc ext service handle.", __func__);
        return nfcChipType;
    }
    nfcExtInf.getNfcChipType = reinterpret_cast<const char* (*)()>
        (dlsym(nfcExtHandle, EXT_GET_CHIP_TYPE_FUNC_NAME.c_str()));
    nfcExtInf.getNfcHalFuncNameSuffix = reinterpret_cast<const char* (*)(const char*)>
        (dlsym(nfcExtHandle, EXT_GET_SUFFIX_FUNC_NAME.c_str()));

    if (nfcExtInf.getNfcChipType == nullptr || nfcExtInf.getNfcHalFuncNameSuffix == nullptr) {
        HDF_LOGE("%{public}s: fail to init func ptr.", __func__);
        return nfcChipType;
    }
    nfcChipType = string(nfcExtInf.getNfcChipType());
    return nfcChipType;
}

string NfcVendorAdaptions::GetNfcHalFuncNameSuffix(string chipType)
{
    string suffix = DEFAULT_FUNC_NAME_SUFFIX;
    if (nfcExtInf.getNfcHalFuncNameSuffix != nullptr) {
        suffix = string(nfcExtInf.getNfcHalFuncNameSuffix(chipType.c_str()));
    }
    return suffix;
}

void NfcVendorAdaptions::ResetNfcInterface(void)
{
    nfcHalHandle = nullptr;
    nfcHalInf.nfcHalOpen = nullptr;
    nfcHalInf.nfcHalWrite = nullptr;
    nfcHalInf.nfcHalCoreInitialized = nullptr;
    nfcHalInf.nfcHalPrediscover = nullptr;
    nfcHalInf.nfcHalClose = nullptr;
    nfcHalInf.nfcHalControlGranted = nullptr;
    nfcHalInf.nfcHalPowerCycle = nullptr;
    nfcHalInf.nfcHalIoctl = nullptr;
    nfcExtHandle = nullptr;
    nfcExtInf.getNfcChipType = nullptr;
    nfcExtInf.getNfcHalFuncNameSuffix = nullptr;
}

int8_t NfcVendorAdaptions::InitNfcHalInterfaces(string nfcHalSoName, string suffix)
{
    if (nfcHalHandle == nullptr) {
        nfcHalHandle = dlopen(nfcHalSoName.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    }
    if (nfcHalHandle == nullptr) {
        HDF_LOGE("%{public}s: invalid input path, opening default hal lib", __func__);
        nfcHalSoName = NFC_HAL_SO_DEFAULT_NAME;
        suffix = DEFAULT_FUNC_NAME_SUFFIX;
        nfcHalHandle = dlopen(nfcHalSoName.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    }
    if (nfcHalHandle == nullptr) {
        HDF_LOGE("%{public}s: fail to open hal path.", __func__);
        return HDF_FAILURE;
    }

    nfcHalInf.nfcHalOpen = reinterpret_cast<int (*)(nfc_stack_callback_t *, nfc_stack_data_callback_t *)>
        (dlsym(nfcHalHandle, (HAL_OPEN_FUNC_NAME + suffix).c_str()));

    nfcHalInf.nfcHalWrite = reinterpret_cast<int (*)(uint16_t, const uint8_t *)>
        (dlsym(nfcHalHandle, (HAL_WRITE_FUNC_NAME + suffix).c_str()));

    nfcHalInf.nfcHalCoreInitialized = reinterpret_cast<int (*)(uint16_t, uint8_t *)>
        (dlsym(nfcHalHandle, (HAL_CORE_INIT_FUNC_NAME + suffix).c_str()));

    nfcHalInf.nfcHalPrediscover = reinterpret_cast<int (*)()>
        (dlsym(nfcHalHandle, (HAL_PRE_DISC_FUNC_NAME + suffix).c_str()));

    nfcHalInf.nfcHalClose = reinterpret_cast<int (*)(bool)>
        (dlsym(nfcHalHandle, (HAL_CLOSE_FUNC_NAME + suffix).c_str()));

    nfcHalInf.nfcHalControlGranted = reinterpret_cast<int (*)()>
        (dlsym(nfcHalHandle, (HAL_CTRL_GRANTED_FUNC_NAME + suffix).c_str()));

    nfcHalInf.nfcHalPowerCycle = reinterpret_cast<int (*)()>
        (dlsym(nfcHalHandle, (HAL_POWER_CYCLE_FUNC_NAME + suffix).c_str()));

    nfcHalInf.nfcHalIoctl = reinterpret_cast<int (*)(long, void *)>
        (dlsym(nfcHalHandle, (HAL_IOCTL_FUNC_NAME + suffix).c_str()));

    if (nfcHalInf.nfcHalOpen == nullptr || nfcHalInf.nfcHalWrite == nullptr ||
        nfcHalInf.nfcHalCoreInitialized == nullptr || nfcHalInf.nfcHalPrediscover == nullptr ||
        nfcHalInf.nfcHalClose == nullptr || nfcHalInf.nfcHalControlGranted == nullptr ||
        nfcHalInf.nfcHalPowerCycle == nullptr || nfcHalInf.nfcHalIoctl == nullptr) {
        HDF_LOGE("%{public}s: fail to init func ptr.", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: init nfc hal inf successfully.", __func__);
    return HDF_SUCCESS;
}

NfcVendorAdaptions::NfcVendorAdaptions()
{
    ResetNfcInterface();
}

NfcVendorAdaptions::~NfcVendorAdaptions() {}

int NfcVendorAdaptions::VendorOpen(nfc_stack_callback_t *p_cback, nfc_stack_data_callback_t *p_data_cback)
{
    if (nfcHalHandle == nullptr) {
        string chipType = GetChipType();
        string nfcHalSoName = GetNfcHalSoName(chipType);
        string nfcHalFuncNameSuffix = GetNfcHalFuncNameSuffix(chipType);
        if (InitNfcHalInterfaces(nfcHalSoName, nfcHalFuncNameSuffix) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fail to init hal inf.", __func__);
            return HDF_FAILURE;
        }
    }

    if (nfcHalInf.nfcHalOpen == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    if (p_cback == nullptr || p_data_cback == nullptr) {
        HDF_LOGE("%{public}s: input param null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalOpen(p_cback, p_data_cback);
    return ret;
}

int NfcVendorAdaptions::VendorCoreInitialized(uint16_t core_init_rsp_len, uint8_t *p_core_init_rsp_params)
{
    if (nfcHalInf.nfcHalCoreInitialized == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    if (p_core_init_rsp_params == nullptr) {
        HDF_LOGE("%{public}s: input param null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalCoreInitialized(core_init_rsp_len, p_core_init_rsp_params);
    return ret;
}

int NfcVendorAdaptions::VendorWrite(uint16_t data_len, const uint8_t *p_data)
{
    if (nfcHalInf.nfcHalWrite == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    if (p_data == nullptr) {
        HDF_LOGE("%{public}s: input param null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalWrite(data_len, p_data);
    return ret;
}

int NfcVendorAdaptions::VendorPrediscover(void)
{
    if (nfcHalInf.nfcHalPrediscover == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalPrediscover();
    return ret;
}

int NfcVendorAdaptions::VendorClose(bool bShutdown)
{
    if (nfcHalInf.nfcHalClose == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalClose(bShutdown);
    return ret;
}

int NfcVendorAdaptions::VendorControlGranted(void)
{
    if (nfcHalInf.nfcHalControlGranted == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalControlGranted();
    return ret;
}

int NfcVendorAdaptions::VendorPowerCycle(void)
{
    if (nfcHalInf.nfcHalPowerCycle == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalPowerCycle();
    return ret;
}

int NfcVendorAdaptions::VendorIoctl(long arg, void *p_data)
{
    if (nfcHalInf.nfcHalIoctl == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    if (p_data == nullptr) {
        HDF_LOGE("%{public}s: input param null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalIoctl(arg, p_data);
    return ret;
}
} // Nfc
} // HDI
} // OHOS