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

#include "infc_vendor.h"

namespace OHOS {
namespace HDI {
namespace Nfc {
class NfcVendorAdaptions : public INfcVendor {
public:
    NfcVendorAdaptions();
    ~NfcVendorAdaptions() override;

    int VendorOpen(nfc_stack_callback_t *p_cback,
                   nfc_stack_data_callback_t *p_data_cback) override;
    int VendorWrite(uint16_t data_len, const uint8_t *p_data) override;
    int VendorCoreInitialized(uint16_t core_init_rsp_len,
                              uint8_t *p_core_init_rsp_params) override;
    int VendorPrediscover(void) override;
    int VendorClose(bool bShutdown) override;
    int VendorControlGranted(void) override;
    int VendorPowerCycle(void) override;
    int VendorIoctl(long arg, void *p_data) override;
};
} // Nfc
} // HDI
} // OHOS

#endif // NFC_VENDOR_ADAPTIONS_H
