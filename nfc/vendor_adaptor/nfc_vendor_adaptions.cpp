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
#include <mutex>
#include <iostream>
#include <pthread.h>
#include <string>
#include "securec.h"

#define HDF_LOG_TAG hdf_nfc_dal

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD000306
std::mutex g_openMutex;
using namespace std;
namespace OHOS {
namespace HDI {
namespace Nfc {
static string GetNfcHalSoName(const std::string &chipType)
{
    string nfcHalSoName = NFC_HAL_SO_PREFIX + chipType + NFC_HAL_SO_SUFFIX;
    return nfcHalSoName;
}

int NfcVendorAdaptions::GetNfcStatus(void)
{
    int nfcStatus = NFC_STATUS_OPEN;
    nfcExtHandle = dlopen(VENDOR_NFC_EXT_SERVICE_LIB.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (nfcExtHandle == nullptr) {
        HDF_LOGE("%{public}s: fail to get nfc ext service handle.", __func__);
        return NFC_STATUS_CLOSE;
    }
    nfcExtInf.getNfcStatus = reinterpret_cast<int (*)()>
        (dlsym(nfcExtHandle, EXT_GET_NFC_STATUS_FUNC_NAME.c_str()));

    if (nfcExtInf.getNfcStatus == nullptr) {
        HDF_LOGE("%{public}s: fail to init func ptr.", __func__);
        dlclose(nfcExtHandle);
        nfcExtHandle = nullptr;
        return NFC_STATUS_CLOSE;
    }
    nfcStatus = nfcExtInf.getNfcStatus();
    dlclose(nfcExtHandle);
    nfcExtHandle = nullptr;
    HDF_LOGE("%{public}s: status %{public}d.", __func__, nfcStatus);
    return nfcStatus;
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
        dlclose(nfcExtHandle);
        nfcExtHandle = nullptr;
        return nfcChipType;
    }
    nfcChipType = string(nfcExtInf.getNfcChipType());
    dlclose(nfcExtHandle);
    nfcExtHandle = nullptr;
    return nfcChipType;
}

void NfcVendorAdaptions::CheckFirmwareUpdate(void)
{
    nfcExtHandle = dlopen(VENDOR_NFC_EXT_SERVICE_LIB.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (nfcExtHandle == nullptr) {
        HDF_LOGE("%{public}s: fail to get nfc ext service handle.", __func__);
        return;
    }
    nfcExtInf.checkFirmwareUpdate = reinterpret_cast<void (*)()>
        (dlsym(nfcExtHandle, EXT_SET_FW_UPDATE_CONFIG_FUNC_NAME.c_str()));
    if (nfcExtInf.checkFirmwareUpdate == nullptr) {
        HDF_LOGE("%{public}s: fail to init func ptr.", __func__);
        dlclose(nfcExtHandle);
        nfcExtHandle = nullptr;
        return;
    }
    nfcExtInf.checkFirmwareUpdate();
    dlclose(nfcExtHandle);
    nfcExtHandle = nullptr;
}

string NfcVendorAdaptions::GetNfcHalFuncNameSuffix(const std::string &chipType)
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
    nfcHalInf.nfcHalGetConfig = nullptr;
    nfcHalInf.nfcHalFactoryReset = nullptr;
    nfcHalInf.nfcHalShutdownCase = nullptr;
    nfcHalInf.nfcHalMinOpen = nullptr;
    nfcHalInf.nfcHalMinClose = nullptr;
    nfcExtHandle = nullptr;
    nfcExtInf.getNfcChipType = nullptr;
    nfcExtInf.getNfcStatus = nullptr;
    nfcExtInf.getNfcHalFuncNameSuffix = nullptr;
}

void* NfcVendorAdaptions::DoHalPreOpen(void* arg)
{
    NFCSTATUS status = HDF_SUCCESS;
    if (arg == nullptr) {
        return nullptr;
    }
    NfcVendorAdaptions *mVendorAdapter = static_cast<NfcVendorAdaptions*>(arg);
    HDF_LOGI("%{public}s: enter.", __func__);
    mVendorAdapter->isNfcPreDone = true;
    if (mVendorAdapter->nfcHalInf.nfcHalMinOpen == nullptr ||
        mVendorAdapter->nfcHalInf.nfcHalMinClose == nullptr) {
        HDF_LOGE("%{public}s: function is null", __func__);
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(g_openMutex);
    status = mVendorAdapter->nfcHalInf.nfcHalMinOpen(true);
    if (status != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: nfcHalMinOpen is fail", __func__);
        return nullptr;
    }
    status = mVendorAdapter->nfcHalInf.nfcHalMinClose();
    if (status != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: nfcHalMinClose is fail", __func__);
        return nullptr;
    }
    HDF_LOGI("%{public}s: exit.", __func__);
    return nullptr;
}

void NfcVendorAdaptions::HalPreOpen(void)
{
    int ret = HDF_SUCCESS;
    int nfcStatus = NFC_STATUS_OPEN;
    pthread_t pthread;
    HDF_LOGI("%{public}s: enter.", __func__);
    nfcStatus = GetNfcStatus();
    if (!isNfcPreDone && (nfcStatus != NFC_STATUS_OPEN)) {
        ret = pthread_create(&pthread, nullptr, NfcVendorAdaptions::DoHalPreOpen, this);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: pthread_create is fail", __func__);
        }
    }
    HDF_LOGI("%{public}s: exit.", __func__);
}

int8_t NfcVendorAdaptions::PreInitNfcHalInterfaces(string nfcHalSoName, string suffix)
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
    return HDF_SUCCESS;
}

int8_t NfcVendorAdaptions::InitNfcHalInterfaces(string nfcHalSoName, string suffix)
{
    int8_t ret = PreInitNfcHalInterfaces(nfcHalSoName, suffix);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    nfcHalInf.nfcHalOpen = reinterpret_cast<int (*)(NfcStackCallbackT *, NfcStackDataCallbackT *)>
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

    nfcHalInf.nfcHalGetConfig = reinterpret_cast<void (*)(V1_1::NfcVendorConfig &)>
        (dlsym(nfcHalHandle, (HAL_GET_CONFIG_FUNC_NAME + suffix).c_str()));

    nfcHalInf.nfcHalFactoryReset = reinterpret_cast<void (*)()>
        (dlsym(nfcHalHandle, (HAL_FACTORY_RESET_FUNC_NAME + suffix).c_str()));

    nfcHalInf.nfcHalShutdownCase = reinterpret_cast<int (*)()>
        (dlsym(nfcHalHandle, (HAL_SHUTDOWN_CASE_FUNC_NAME + suffix).c_str()));

    nfcHalInf.nfcHalMinOpen = reinterpret_cast<NFCSTATUS (*)(bool)>
        (dlsym(nfcHalHandle, (HAL_MIN_OPEN_FUNC_NAME + suffix).c_str()));

    nfcHalInf.nfcHalMinClose = reinterpret_cast<NFCSTATUS (*)()>
        (dlsym(nfcHalHandle, (HAL_MIN_CLOSE_FUNC_NAME + suffix).c_str()));

    if (nfcHalInf.nfcHalOpen == nullptr || nfcHalInf.nfcHalWrite == nullptr ||
        nfcHalInf.nfcHalCoreInitialized == nullptr || nfcHalInf.nfcHalPrediscover == nullptr ||
        nfcHalInf.nfcHalClose == nullptr || nfcHalInf.nfcHalControlGranted == nullptr ||
        nfcHalInf.nfcHalPowerCycle == nullptr || nfcHalInf.nfcHalIoctl == nullptr ||
        nfcHalInf.nfcHalGetConfig == nullptr || nfcHalInf.nfcHalFactoryReset == nullptr ||
        nfcHalInf.nfcHalShutdownCase == nullptr) {
        HDF_LOGE("%{public}s: fail to init func ptr.", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: init nfc hal inf successfully.", __func__);
    return HDF_SUCCESS;
}

NfcVendorAdaptions::NfcVendorAdaptions()
{
    ResetNfcInterface();
    if (nfcHalHandle == nullptr) {
        CheckFirmwareUpdate();
        string chipType = GetChipType();
        string nfcHalSoName = GetNfcHalSoName(chipType);
        string nfcHalFuncNameSuffix = GetNfcHalFuncNameSuffix(chipType);
        if (InitNfcHalInterfaces(nfcHalSoName, nfcHalFuncNameSuffix) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fail to init hal inf.", __func__);
        }
        HalPreOpen();
    }
}

NfcVendorAdaptions::~NfcVendorAdaptions() {}

int NfcVendorAdaptions::VendorOpen(NfcStackCallbackT *pCback, NfcStackDataCallbackT *pDataCback)
{
    if (nfcHalInf.nfcHalOpen == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    if (pCback == nullptr || pDataCback == nullptr) {
        HDF_LOGE("%{public}s: input param null.", __func__);
        return HDF_FAILURE;
    }
    std::lock_guard<std::mutex> lock(g_openMutex);
    int ret = nfcHalInf.nfcHalOpen(pCback, pDataCback);
    return ret;
}

int NfcVendorAdaptions::VendorCoreInitialized(uint16_t coreInitRspLen, uint8_t *pCoreInitRspParams)
{
    if (nfcHalInf.nfcHalCoreInitialized == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    if (pCoreInitRspParams == nullptr) {
        HDF_LOGE("%{public}s: input param null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalCoreInitialized(coreInitRspLen, pCoreInitRspParams);
    return ret;
}

int NfcVendorAdaptions::VendorWrite(uint16_t dataLen, const uint8_t *pData)
{
    if (nfcHalInf.nfcHalWrite == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    if (pData == nullptr) {
        HDF_LOGE("%{public}s: input param null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalWrite(dataLen, pData);
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

int NfcVendorAdaptions::VendorIoctl(long arg, void *pData)
{
    if (nfcHalInf.nfcHalIoctl == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    if (pData == nullptr) {
        HDF_LOGE("%{public}s: input param null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalIoctl(arg, pData);
    return ret;
}

int NfcVendorAdaptions::VendorIoctlWithResponse(long arg, void *pData, uint16_t dataLen, std::vector<uint8_t> &pRetVal)
{
    if (nfcHalInf.nfcHalIoctl == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    if (pData == nullptr) {
        HDF_LOGE("%{public}s: input param null.", __func__);
        return HDF_FAILURE;
    }
    if (arg == VENDOR_GET_HISTORY_NCI_CMD) {
        HDF_LOGI("%{public}s: getting history nci from vendor!", __func__);
        return VendorGetHistoryNci(pData, dataLen, pRetVal);
    }
    if (dataLen < VENDOR_IOCTL_INPUT_MIN_LEN || dataLen > VENDOR_IOCTL_TOTAL_LEN) {
        HDF_LOGE("%{public}s: dataLen is invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    uint8_t inOutData[VENDOR_IOCTL_TOTAL_LEN] = { 0 };
    if (memcpy_s(inOutData, VENDOR_IOCTL_TOTAL_LEN, pData, VENDOR_IOCTL_INOUT_DATA_LEN) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s pData failed.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalIoctl(arg, inOutData);
    if (ret == HDF_SUCCESS) {
        uint8_t* pTmp = inOutData;
        int i;
        for (i = 0; i <= pTmp[VENDOR_IOCTL_OUTPUT_LEN_INDEX]; i++) {
            pRetVal.push_back(pTmp[VENDOR_IOCTL_OUTPUT_LEN_INDEX + i]);
        }
    }
    return ret;
}

int NfcVendorAdaptions::VendorGetHistoryNci(void *pData, uint16_t dataLen, std::vector<uint8_t> &pRetVal)
{
    if (dataLen != VENDOR_IOCTL_INPUT_DATA_LEN) {
        HDF_LOGE("%{public}s: input param data len err.", __func__);
        return HDF_FAILURE;
    }
    std::vector<uint8_t> inOutData(VENDOR_IOCTL_TOTAL_LENGTH, 0);
    if (memcpy_s(&inOutData[0], inOutData.size(), pData, dataLen) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s pData failed.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalIoctl(VENDOR_GET_HISTORY_NCI_CMD, &inOutData[0]);
    if (ret == HDF_SUCCESS) {
        for (uint16_t i = 0; i < VENDOR_IOCTL_OUTPUT_DATA_LEN; i++) {
            pRetVal.push_back(inOutData[VENDOR_IOCTL_OUTPUT_DATA_START_INDEX + i]);
        }
    }
    return ret;
}

int NfcVendorAdaptions::VendorGetConfig(V1_1::NfcVendorConfig &config)
{
    HDF_LOGD("%{public}s: start.", __func__);
    if (nfcHalInf.nfcHalGetConfig == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    nfcHalInf.nfcHalGetConfig(config);
    return HDF_SUCCESS;
}

int NfcVendorAdaptions::VendorFactoryReset(void)
{
    HDF_LOGD("%{public}s: start.", __func__);
    if (nfcHalInf.nfcHalFactoryReset == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    nfcHalInf.nfcHalFactoryReset();
    return HDF_SUCCESS;
}

int NfcVendorAdaptions::VendorShutdownCase(void)
{
    HDF_LOGD("%{public}s: start.", __func__);
    if (nfcHalInf.nfcHalShutdownCase == nullptr) {
        HDF_LOGE("%{public}s: Function null.", __func__);
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalShutdownCase();
    return ret;
}
} // Nfc
} // HDI
} // OHOS