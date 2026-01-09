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
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include "securec.h"
#include "hisysevent.h"
#include "string_ex.h"
#include "parameter.h"

#define HDF_LOG_TAG hdf_nfc_dal

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD000306

const int32_t PRIORITY = -20;
const uint8_t PARAM_SPLIT_PART = 2;
const uint16_t PROPERTY_VALUE_MAX = 64;

using namespace std;
namespace OHOS {
namespace HDI {
namespace Nfc {
std::mutex g_openMutex;
enum BootloaderRecoverStatus : uint16_t {
    BOOTLOADER_STATUS_RECOVER_SUCCESS = 1,
    BOOTLOADER_STATUS_RECOVER_FAILED,
};
template<typename... Types>
static void WriteEvent(const std::string& eventType, OHOS::HiviewDFX::HiSysEvent::EventType type, Types... args)
{
    int ret = HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURE_ELEMENT, eventType, type, args...);
    if (ret != 0) {
        HDF_LOGE("Write event fail: %{public}s", eventType.c_str());
    } else {
        HDF_LOGI("WriteEvent success!");
    }
}

static void WriteBootloaderHiSysEvent(uint16_t errorCode)
{
    const uint8_t bootloaderStatusType = 200; /* 100 ~ 199 for CA to TA hisysevent */
    WriteEvent("ACCESS_SE_FAILED", OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
               "CHANNEL_TYPE", bootloaderStatusType,
               "ERROR_CODE", errorCode);
    HDF_LOGI("WriteBootloaderHiSysEvent value:%{public}d", errorCode);
}

static string GetNfcHalSoName(const std::string &chipType)
{
    string nfcHalSoName = NFC_HAL_SO_PREFIX + chipType + NFC_HAL_SO_SUFFIX;
    return nfcHalSoName;
}

string NfcVendorAdaptions::GetChipType(void)
{
    string nfcChipType = "";
    nfcExtHandle = dlopen(VENDOR_NFC_EXT_SERVICE_LIB.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (nfcExtHandle == nullptr) {
        HDF_LOGE("GetChipType: fail to get nfc ext service handle.");
        return nfcChipType;
    }
    nfcExtInf.getNfcChipType = reinterpret_cast<const char* (*)()>
        (dlsym(nfcExtHandle, EXT_GET_CHIP_TYPE_FUNC_NAME.c_str()));
    nfcExtInf.getNfcHalFuncNameSuffix = reinterpret_cast<const char* (*)(const char*)>
        (dlsym(nfcExtHandle, EXT_GET_SUFFIX_FUNC_NAME.c_str()));

    if (nfcExtInf.getNfcChipType == nullptr || nfcExtInf.getNfcHalFuncNameSuffix == nullptr) {
        HDF_LOGE("GetChipType: fail to init func ptr.");
        return nfcChipType;
    }
    nfcChipType = string(nfcExtInf.getNfcChipType());
    return nfcChipType;
}

void NfcVendorAdaptions::CheckFirmwareUpdate(void)
{
    nfcExtHandle = dlopen(VENDOR_NFC_EXT_SERVICE_LIB.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (nfcExtHandle == nullptr) {
        HDF_LOGE("CheckFirmwareUpdate: fail to get nfc ext service handle.");
        return;
    }
    nfcExtInf.checkFirmwareUpdate = reinterpret_cast<void (*)()>
        (dlsym(nfcExtHandle, EXT_SET_FW_UPDATE_CONFIG_FUNC_NAME.c_str()));
    if (nfcExtInf.checkFirmwareUpdate == nullptr) {
        HDF_LOGE("CheckFirmwareUpdate: fail to init func ptr.");
        dlclose(nfcExtHandle);
        nfcExtHandle = nullptr;
        return;
    }
    nfcExtInf.checkFirmwareUpdate();
    dlclose(nfcExtHandle);
    nfcExtHandle = nullptr;
}

void NfcVendorAdaptions::UpdateNfcOpenStatus(const std::string &status)
{
    nfcExtHandle = dlopen(VENDOR_NFC_EXT_SERVICE_LIB.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (nfcExtHandle == nullptr) {
        HDF_LOGE("UpdateNfcOpenStatus: fail to get nfc ext service handle.");
        return;
    }
    nfcExtInf.updateNfcOpenStatus = reinterpret_cast<void (*)(const char*, int)>
        (dlsym(nfcExtHandle, EXT_UPDATE_NFC_OPEN_STATUS.c_str()));
    if (nfcExtInf.updateNfcOpenStatus == nullptr) {
        HDF_LOGE("UpdateNfcOpenStatus: fail to init func ptr.");
        dlclose(nfcExtHandle);
        nfcExtHandle = nullptr;
        return;
    }
    nfcExtInf.updateNfcOpenStatus(status.c_str(), status.length());
    HDF_LOGI("UpdateNfcOpenStatus: status [%{public}s].", status.c_str());
    dlclose(nfcExtHandle);
    nfcExtHandle = nullptr;
}

/*
** true : NFC in bootloader status
** false : NFC in normal status
*/
bool NfcVendorAdaptions::CheckNfcBootloaderStatus(void)
{
    nfcExtHandle = dlopen(VENDOR_NFC_EXT_SERVICE_LIB.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (nfcExtHandle == nullptr) {
        HDF_LOGE("CheckNfcBootloaderStatus: fail to get nfc ext service handle.");
        return false;
    }
    nfcExtInf.checkNfcBootloaderStatus = reinterpret_cast<int (*)()>
        (dlsym(nfcExtHandle, EXT_CHECK_NFC_BOOTLOADER_STATUS.c_str()));
    if (nfcExtInf.checkNfcBootloaderStatus == nullptr) {
        HDF_LOGE("CheckNfcBootloaderStatus: fail to init func ptr.");
        dlclose(nfcExtHandle);
        nfcExtHandle = nullptr;
        return false;
    }
    if (nfcExtInf.checkNfcBootloaderStatus() == 0) {
        dlclose(nfcExtHandle);
        nfcExtHandle = nullptr;
        HDF_LOGE("CheckNfcBootloaderStatus: NFC in bootloader status");
        return true;
    }
    dlclose(nfcExtHandle);
    nfcExtHandle = nullptr;
    HDF_LOGI("CheckNfcBootloaderStatus: NFC in normal status");
    return false;
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
    nfcExtInf.getNfcHalFuncNameSuffix = nullptr;
}

void* NfcVendorAdaptions::DoHalPreOpen(void* arg)
{
    NFCSTATUS status = HDF_SUCCESS;
    if (arg == nullptr) {
        return nullptr;
    }
    NfcVendorAdaptions *mVendorAdapter = static_cast<NfcVendorAdaptions*>(arg);
    HDF_LOGI("DoHalPreOpen: enter.");
    mVendorAdapter->isNfcPreDone = true;
    if (mVendorAdapter->nfcHalInf.nfcHalMinOpen == nullptr ||
        mVendorAdapter->nfcHalInf.nfcHalMinClose == nullptr) {
        HDF_LOGE("DoHalPreOpen: function is null");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(g_openMutex);
    if (mVendorAdapter->CheckNfcBootloaderStatus()) {
        mVendorAdapter->UpdateNfcOpenStatus(NFC_OPENING_STATUS);
        status = mVendorAdapter->nfcHalInf.nfcHalMinOpen(true);
        if (status != HDF_SUCCESS) {
            HDF_LOGE("DoHalPreOpen: nfcHalMinOpen is fail");
            mVendorAdapter->UpdateNfcOpenStatus(NFC_CLOSE_STATUS);
            WriteBootloaderHiSysEvent(BOOTLOADER_STATUS_RECOVER_FAILED);
            return nullptr;
        }
        status = mVendorAdapter->nfcHalInf.nfcHalMinClose();
        if (status != HDF_SUCCESS) {
            HDF_LOGE("DoHalPreOpen: nfcHalMinClose is fail");
            mVendorAdapter->UpdateNfcOpenStatus(NFC_OPEN_STATUS);
            WriteBootloaderHiSysEvent(BOOTLOADER_STATUS_RECOVER_FAILED);
            return nullptr;
        }
        mVendorAdapter->UpdateNfcOpenStatus(NFC_CLOSE_STATUS);
        WriteBootloaderHiSysEvent(BOOTLOADER_STATUS_RECOVER_SUCCESS);
    }
    HDF_LOGI("DoHalPreOpen: exit.");
    return nullptr;
}

void NfcVendorAdaptions::HalPreOpen(void)
{
    int ret = HDF_SUCCESS;
    pthread_t pthread;
    HDF_LOGI("HalPreOpen: enter.");
    if (!isNfcPreDone) {
        ret = pthread_create(&pthread, nullptr, NfcVendorAdaptions::DoHalPreOpen, this);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("HalPreOpen: pthread_create is fail");
        }
    }
    HDF_LOGI("HalPreOpen: exit.");
}

int8_t NfcVendorAdaptions::PreInitNfcHalInterfaces(string nfcHalSoName, string suffix)
{
    if (nfcHalHandle == nullptr) {
        nfcHalHandle = dlopen(nfcHalSoName.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    }
    if (nfcHalHandle == nullptr) {
        HDF_LOGE("PreInitNfcHalInterfaces: invalid input path, opening default hal lib");
        nfcHalSoName = NFC_HAL_SO_DEFAULT_NAME;
        suffix = DEFAULT_FUNC_NAME_SUFFIX;
        nfcHalHandle = dlopen(nfcHalSoName.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    }
    if (nfcHalHandle == nullptr) {
        HDF_LOGE("PreInitNfcHalInterfaces: fail to open hal path.");
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
        HDF_LOGE("InitNfcHalInterfaces: fail to init func ptr.");
        return HDF_FAILURE;
    }
    HDF_LOGI("InitNfcHalInterfaces: init nfc hal inf successfully.");
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
            HDF_LOGE("InitNfcHalInterfaces: fail to init hal inf.");
        }
        HalPreOpen();
    }
}

NfcVendorAdaptions::~NfcVendorAdaptions() {}

void NfcVendorAdaptions::SetPriority()
{
    if (setpriority(PRIO_PROCESS, 0, PRIORITY) != 0) {
        HDF_LOGE("setpriority err %{public}s", strerror(errno));
        return;
    }
    HDF_LOGE("setpriority succeed.");
}

int NfcVendorAdaptions::VendorOpen(NfcStackCallbackT *pCback, NfcStackDataCallbackT *pDataCback)
{
    if (nfcHalInf.nfcHalOpen == nullptr) {
        HDF_LOGE("InitNfcHalInterfaces: Function null.");
        return HDF_FAILURE;
    }
    if (pCback == nullptr || pDataCback == nullptr) {
        HDF_LOGE("InitNfcHalInterfaces: input param null.");
        return HDF_FAILURE;
    }
    std::lock_guard<std::mutex> lock(g_openMutex);
    SetPriority();
    CheckFirmwareUpdate();
    int ret = nfcHalInf.nfcHalOpen(pCback, pDataCback);
    return ret;
}

int NfcVendorAdaptions::VendorCoreInitialized(uint16_t coreInitRspLen, uint8_t *pCoreInitRspParams)
{
    if (nfcHalInf.nfcHalCoreInitialized == nullptr) {
        HDF_LOGE("VendorCoreInitialized: Function null.");
        return HDF_FAILURE;
    }
    if (pCoreInitRspParams == nullptr) {
        HDF_LOGE("VendorCoreInitialized: input param null.");
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalCoreInitialized(coreInitRspLen, pCoreInitRspParams);
    return ret;
}

int NfcVendorAdaptions::VendorWrite(uint16_t dataLen, const uint8_t *pData)
{
    if (nfcHalInf.nfcHalWrite == nullptr) {
        HDF_LOGE("VendorWrite: Function null.");
        return HDF_FAILURE;
    }
    if (pData == nullptr) {
        HDF_LOGE("VendorWrite: input param null.");
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalWrite(dataLen, pData);
    return ret;
}

int NfcVendorAdaptions::VendorPrediscover(void)
{
    if (nfcHalInf.nfcHalPrediscover == nullptr) {
        HDF_LOGE("VendorPrediscover: Function null.");
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalPrediscover();
    return ret;
}

int NfcVendorAdaptions::VendorClose(bool bShutdown)
{
    if (nfcHalInf.nfcHalClose == nullptr) {
        HDF_LOGE("VendorClose: Function null.");
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalClose(bShutdown);
    return ret;
}

int NfcVendorAdaptions::VendorControlGranted(void)
{
    if (nfcHalInf.nfcHalControlGranted == nullptr) {
        HDF_LOGE("VendorControlGranted: Function null.");
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalControlGranted();
    return ret;
}

int NfcVendorAdaptions::VendorPowerCycle(void)
{
    if (nfcHalInf.nfcHalPowerCycle == nullptr) {
        HDF_LOGE("VendorPowerCycle: Function null.");
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalPowerCycle();
    return ret;
}

int NfcVendorAdaptions::VendorIoctl(long arg, void *pData)
{
    if (nfcHalInf.nfcHalIoctl == nullptr) {
        HDF_LOGE("VendorIoctl: Function null.");
        return HDF_FAILURE;
    }
    if (pData == nullptr) {
        HDF_LOGE("VendorIoctl: input param null.");
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalIoctl(arg, pData);
    return ret;
}

int NfcVendorAdaptions::VendorIoctlWithResponse(long arg, void *pData, uint16_t dataLen, std::vector<uint8_t> &pRetVal)
{
    if (nfcHalInf.nfcHalIoctl == nullptr) {
        HDF_LOGE("VendorIoctlWithResponse: Function null.");
        return HDF_FAILURE;
    }
    if (pData == nullptr) {
        HDF_LOGE("VendorIoctlWithResponse: input param null.");
        return HDF_FAILURE;
    }
    if (arg == VENDOR_GET_HISTORY_NCI_CMD) {
        HDF_LOGI("VendorIoctlWithResponse: getting history nci from vendor!");
        return VendorGetHistoryNci(pData, dataLen, pRetVal);
    }
    if (dataLen < VENDOR_IOCTL_INPUT_MIN_LEN || dataLen > VENDOR_IOCTL_TOTAL_LEN) {
        HDF_LOGE("VendorIoctlWithResponse: dataLen is invalid!");
        return HDF_ERR_INVALID_PARAM;
    }
    uint8_t inOutData[VENDOR_IOCTL_TOTAL_LEN] = { 0 };
    if (memcpy_s(inOutData, VENDOR_IOCTL_TOTAL_LEN, pData, VENDOR_IOCTL_INOUT_DATA_LEN) != EOK) {
        HDF_LOGE("VendorIoctlWithResponse: memcpy_s pData failed.");
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
        HDF_LOGE("VendorGetHistoryNci: input param data len err.");
        return HDF_FAILURE;
    }
    std::vector<uint8_t> inOutData(VENDOR_IOCTL_TOTAL_LENGTH, 0);
    if (memcpy_s(&inOutData[0], inOutData.size(), pData, dataLen) != EOK) {
        HDF_LOGE("VendorGetHistoryNci: memcpy_s pData failed.");
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
    HDF_LOGD("VendorGetConfig: start.");
    if (nfcHalInf.nfcHalGetConfig == nullptr) {
        HDF_LOGE("VendorGetConfig: Function null.");
        return HDF_FAILURE;
    }
    nfcHalInf.nfcHalGetConfig(config);
    return HDF_SUCCESS;
}

int NfcVendorAdaptions::VendorFactoryReset(void)
{
    HDF_LOGD("VendorFactoryReset: start.");
    if (nfcHalInf.nfcHalFactoryReset == nullptr) {
        HDF_LOGE("VendorFactoryReset: Function null.");
        return HDF_FAILURE;
    }
    nfcHalInf.nfcHalFactoryReset();
    return HDF_SUCCESS;
}

int NfcVendorAdaptions::VendorShutdownCase(void)
{
    HDF_LOGD("VendorShutdownCase: start.");
    if (nfcHalInf.nfcHalShutdownCase == nullptr) {
        HDF_LOGE("VendorShutdownCase: Function null.");
        return HDF_FAILURE;
    }
    int ret = nfcHalInf.nfcHalShutdownCase();
    return ret;
}

bool NfcVendorAdaptions::VendorIoctlExt(long arg, const std::vector<uint8_t> &data, std::vector<uint8_t> &response)
{
    HDF_LOGI("cmd=0x%{public}lx", arg);
    switch (arg) {
        case VENDOR_NFC_IOCTL_SET_SYS_PARAM:
            return SetNfcParam(data, response);
        case VENDOR_NFC_IOCTL_GET_SYS_PARAM:
            return GetNfcParam(data, response);
        default:
            HDF_LOGE("unknown cmd.");
    }
    return false;
}
 
static bool GetNfcParamStr(const std::string &paramName, std::string &paramValue)
{
    char param[PROPERTY_VALUE_MAX] = {0};
    int len = GetParameter(paramName.c_str(), "", param, PROPERTY_VALUE_MAX);
    if (len > 0) {
        HDF_LOGI("%{public}s = %{public}s", paramName.c_str(), param);
        paramValue = std::string(param);
        return true;
    }
    HDF_LOGE("failed to get param");
    return false;
}
 
static void SetNfcParamStr(const std::string &paramName, const std::string &paramValue)
{
    HDF_LOGI("set %{public}s as %{public}s", paramName.c_str(), paramValue.c_str());
    SetParameter(paramName.c_str(), paramValue.c_str());
}
 
bool NfcVendorAdaptions::GetNfcParam(const std::vector<uint8_t> &param, std::vector<uint8_t> &value)
{
    std::string paramStr(param.begin(), param.end());
    std::string valueStr = "";
    bool ret = GetNfcParamStr(paramStr, valueStr);
    value = std::vector<uint8_t>(valueStr.begin(), valueStr.end());
    return ret;
}
 
bool NfcVendorAdaptions::SetNfcParam(const std::vector<uint8_t> &param, const std::vector<uint8_t> &value)
{
    std::string paramStr(param.begin(), param.end());
    std::vector<std::string> paramVec {};
    SplitStr(paramStr, "|", paramVec);
    if (paramVec.size() != PARAM_SPLIT_PART) {
        HDF_LOGE("invalid input param");
        return false;
    }
    SetNfcParamStr(paramVec[0], paramVec[1]);
    return true;
}
} // Nfc
} // HDI
} // OHOS