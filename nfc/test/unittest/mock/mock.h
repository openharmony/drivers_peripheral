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
#ifndef MOCK_VENDOR_ADAPTIONS_H
#define MOCK_VENDOR_ADAPTIONS_H

#include <string>
#include "nfc_vendor_adaptions.h"

namespace OHOS {
namespace HDI {
namespace Nfc {
class Mock : public NfcVendorAdaptions {
public:
    int VendorOpen(NfcStackCallbackT *pCback, NfcStackDataCallbackT *pDataCback);
    int VendorWrite(uint16_t dataLen, const uint8_t *pData);
    int VendorCoreInitialized(uint16_t coreInitRspLen, uint8_t *pCoreInitRspParams);
    int VendorPrediscover(void);
    int VendorClose(bool bShutdown);
    int VendorControlGranted(void);
    int VendorPowerCycle(void);
    int VendorIoctl(long arg, void *pData);
    int VendorIoctlWithResponse(long arg, void *pData, uint16_t dataLen, std::vector<uint8_t> &pRetVal);
    int VendorGetConfig(V1_1::NfcVendorConfig &config);
    int VendorFactoryReset(void);
    int VendorShutdownCase(void);

private:
    std::string GetChipType(void);
    std::string GetNfcHalFuncNameSuffix(const std::string &chipType);
    void ResetNfcInterface(void);
    int8_t InitNfcHalInterfaces(std::string nfcHalSoName, std::string suffix);
    void CheckFirmwareUpdate(void);

    void *nfcHalHandle; // handle of nfc hal so
    NfcHalInterface nfcHalInf;

    void *nfcExtHandle; // handle of nfc ext service
    NfcExtInterface nfcExtInf;
};
} // Nfc
} // HDI
} // OHOS

#endif // MOCK_VENDOR_ADAPTIONS_H
