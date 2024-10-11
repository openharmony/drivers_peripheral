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
#ifndef I_NFC_VENDOR_H
#define I_NFC_VENDOR_H

#include "v1_1/nfc_types.h"

typedef uint8_t nfc_event_t;
typedef uint8_t nfc_status_t;

typedef void (NfcStackCallbackT)(nfc_event_t event, nfc_status_t eventStatus);
typedef void (NfcStackDataCallbackT)(uint16_t dataLen, uint8_t *pData);

namespace OHOS {
namespace HDI {
namespace Nfc {
class INfcVendor {
public:
    virtual ~INfcVendor() {}
    virtual int VendorOpen(NfcStackCallbackT *pCback, NfcStackDataCallbackT *pDataCback);
    virtual int VendorWrite(uint16_t dataLen, const uint8_t *pData);
    virtual int VendorCoreInitialized(uint16_t coreInitRspLen, uint8_t *pCoreInitRspParams);
    virtual int VendorPrediscover(void);
    virtual int VendorClose(bool bShutdown);
    virtual int VendorControlGranted(void);
    virtual int VendorPowerCycle(void);
    virtual int VendorIoctl(long arg, void *pData);
    virtual int VendorIoctlWithResponse(long arg, void *pData, uint16_t dataLen, std::vector<uint8_t> &pRetVal);
    virtual int VendorGetConfig(V1_1::NfcVendorConfig &config);
    virtual int VendorFactoryReset(void);
    virtual int VendorShutdownCase(void);
};
} // Nfc
} // HDI
} // OHOS
#endif /* I_NFC_VENDOR_H */
