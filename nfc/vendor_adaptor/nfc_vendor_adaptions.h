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
#ifndef NFC_VENDOR_ADAPTIONS_H
#define NFC_VENDOR_ADAPTIONS_H

#include <cstdint>
#include <string>
#include "infc_vendor.h"

namespace OHOS {
namespace HDI {
namespace Nfc {
const std::string NFC_HAL_SO_DEFAULT_NAME = "libnfc_hdiimpl.z.so";
const std::string VENDOR_NFC_EXT_SERVICE_LIB = "libvendor_ext_nfc_service.z.so";

const std::string EXT_GET_CHIP_TYPE_FUNC_NAME = "GetChipType";
const std::string EXT_GET_SUFFIX_FUNC_NAME = "GetNfcHalFuncNameSuffix";
const std::string EXT_SET_FW_UPDATE_CONFIG_FUNC_NAME = "CheckFirmwareUpdate";

const std::string HAL_OPEN_FUNC_NAME = "phNxpNciHal_open";
const std::string HAL_WRITE_FUNC_NAME = "phNxpNciHal_write";
const std::string HAL_CORE_INIT_FUNC_NAME = "phNxpNciHal_core_initialized";
const std::string HAL_PRE_DISC_FUNC_NAME = "phNxpNciHal_pre_discover";
const std::string HAL_CLOSE_FUNC_NAME = "phNxpNciHal_close";
const std::string HAL_CTRL_GRANTED_FUNC_NAME = "phNxpNciHal_control_granted";
const std::string HAL_POWER_CYCLE_FUNC_NAME = "phNxpNciHal_power_cycle";
const std::string HAL_IOCTL_FUNC_NAME = "phNxpNciHal_ioctl";
const std::string HAL_GET_CONFIG_FUNC_NAME = "phNxpNciHal_getVendorConfig_1_2";
const std::string HAL_FACTORY_RESET_FUNC_NAME = "phNxpNciHal_do_factory_reset";
const std::string HAL_SHUTDOWN_CASE_FUNC_NAME = "phNxpNciHal_configDiscShutdown";
const std::string DEFAULT_FUNC_NAME_SUFFIX = "";

const std::string NFC_HAL_SO_PREFIX = "libnfc_hal_impl_";
const std::string NFC_HAL_SO_SUFFIX = ".z.so";
const unsigned int VENDOR_IOCTL_TOTAL_LEN = 256;
const unsigned int VENDOR_IOCTL_INOUT_DATA_LEN = 128;
const unsigned int VENDOR_IOCTL_OUTPUT_LEN_INDEX = 128;
const unsigned int VENDOR_IOCTL_OUTPUT_START_INDEX = 129;
const unsigned int VENDOR_IOCTL_INPUT_LEN_INDEX = 0;
const unsigned int VENDOR_IOCTL_INPUT_START_INDEX = 1;
const unsigned int VENDOR_IOCTL_INPUT_MIN_LEN = 128;

const unsigned int VENDOR_IOCTL_INPUT_DATA_LEN = 288;
const unsigned int VENDOR_IOCTL_OUTPUT_DATA_START_INDEX = 288;
const unsigned int VENDOR_IOCTL_OUTPUT_DATA_LEN = 4128;
const unsigned int VENDOR_IOCTL_TOTAL_LENGTH = VENDOR_IOCTL_INPUT_DATA_LEN + VENDOR_IOCTL_OUTPUT_DATA_LEN;
const long VENDOR_GET_HISTORY_NCI_CMD = 112;

struct NfcHalInterface {
    int (*nfcHalOpen)(NfcStackCallbackT *pCback, NfcStackDataCallbackT *pDataCback);
    int (*nfcHalWrite)(uint16_t dataLen, const uint8_t *pData);
    int (*nfcHalCoreInitialized)(uint16_t coreInitRspLen, uint8_t *pCoreInitRspParams);
    int (*nfcHalPrediscover)(void);
    int (*nfcHalClose)(bool bShutdown);
    int (*nfcHalControlGranted)(void);
    int (*nfcHalPowerCycle)(void);
    int (*nfcHalIoctl)(long arg, void *pData);
    void (*nfcHalGetConfig)(V1_1::NfcVendorConfig &config);
    void (*nfcHalFactoryReset)(void);
    int (*nfcHalShutdownCase)(void);
};

struct NfcExtInterface {
    const char* (*getNfcChipType)(void);
    const char* (*getNfcHalFuncNameSuffix)(const char* chipType);
    void (*checkFirmwareUpdate)(void);
};

class NfcVendorAdaptions : public INfcVendor {
public:
    NfcVendorAdaptions();
    ~NfcVendorAdaptions() override;

    int VendorOpen(NfcStackCallbackT *pCback, NfcStackDataCallbackT *pDataCback) override;
    int VendorWrite(uint16_t dataLen, const uint8_t *pData) override;
    int VendorCoreInitialized(uint16_t coreInitRspLen, uint8_t *pCoreInitRspParams) override;
    int VendorPrediscover(void) override;
    int VendorClose(bool bShutdown) override;
    int VendorControlGranted(void) override;
    int VendorPowerCycle(void) override;
    int VendorIoctl(long arg, void *pData) override;
    int VendorIoctlWithResponse(long arg, void *pData, uint16_t dataLen, std::vector<uint8_t> &pRetVal) override;
    int VendorGetConfig(V1_1::NfcVendorConfig &config) override;
    int VendorFactoryReset(void) override;
    int VendorShutdownCase(void) override;

private:
    std::string GetChipType(void);
    std::string GetNfcHalFuncNameSuffix(const std::string &chipType);
    void ResetNfcInterface(void);
    int8_t InitNfcHalInterfaces(std::string nfcHalSoName, std::string suffix);
    void CheckFirmwareUpdate(void);
    int VendorGetHistoryNci(void *pData, uint16_t dataLen, std::vector<uint8_t> &pRetVal);

    void *nfcHalHandle; // handle of nfc hal so
    NfcHalInterface nfcHalInf;

    void *nfcExtHandle; // handle of nfc ext service
    NfcExtInterface nfcExtInf;
};
} // Nfc
} // HDI
} // OHOS

#endif // NFC_VENDOR_ADAPTIONS_H
