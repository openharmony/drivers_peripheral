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
#include "phNxpNciHal_Adaptation.h"

#define HDF_LOG_TAG hdf_nfc_dal

namespace OHOS {
namespace HDI {
namespace Nfc {
NfcVendorAdaptions::NfcVendorAdaptions() {}

NfcVendorAdaptions::~NfcVendorAdaptions() {}

int NfcVendorAdaptions::VendorOpen(nfc_stack_callback_t *p_cback,
                                   nfc_stack_data_callback_t *p_data_cback)
{
    return phNxpNciHal_open(*p_cback, *p_data_cback);
}

int NfcVendorAdaptions::VendorCoreInitialized(uint16_t core_init_rsp_len,
                                              uint8_t *p_core_init_rsp_params)
{
    return phNxpNciHal_core_initialized(core_init_rsp_len, p_core_init_rsp_params);
}

int NfcVendorAdaptions::VendorWrite(uint16_t data_len, const uint8_t *p_data)
{
    return phNxpNciHal_write(data_len, p_data);
}

int NfcVendorAdaptions::VendorPrediscover(void)
{
    return phNxpNciHal_pre_discover();
}

int NfcVendorAdaptions::VendorClose(bool bShutdown)
{
    return phNxpNciHal_close(bShutdown);
}

int NfcVendorAdaptions::VendorControlGranted(void)
{
    return phNxpNciHal_control_granted();
}

int NfcVendorAdaptions::VendorPowerCycle(void)
{
    return phNxpNciHal_power_cycle();
}

int NfcVendorAdaptions::VendorIoctl(long arg, void *p_data)
{
    return phNxpNciHal_ioctl(arg, p_data);
}
} // Nfc
} // HDI
} // OHOS