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
#include "mock.h"

namespace OHOS {
namespace HDI {
namespace Nfc {
NfcVendorAdaptions::NfcVendorAdaptions()
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
    nfcExtHandle = nullptr;
    nfcExtInf.getNfcChipType = nullptr;
    nfcExtInf.getNfcHalFuncNameSuffix = nullptr;
}

NfcVendorAdaptions::~NfcVendorAdaptions() {}

int NfcVendorAdaptions::VendorOpen(NfcStackCallbackT *pCback, NfcStackDataCallbackT *pDataCback)
{
    return 0;
}

int NfcVendorAdaptions::VendorWrite(uint16_t dataLen, const uint8_t *pData)
{
    return 0;
}

int NfcVendorAdaptions::VendorCoreInitialized(uint16_t coreInitRspLen, uint8_t *pCoreInitRspParams)
{
    return 0;
}

int NfcVendorAdaptions::VendorPrediscover(void)
{
    return -1;
}

int NfcVendorAdaptions::VendorClose(bool bShutdown)
{
    return 0;
}

int NfcVendorAdaptions::VendorControlGranted(void)
{
    return -1;
}

int NfcVendorAdaptions::VendorPowerCycle(void)
{
    return 0;
}

int NfcVendorAdaptions::VendorIoctl(long arg, void *pData)
{
    return 0;
}

int NfcVendorAdaptions::VendorIoctlWithResponse(long arg, void *pData, uint16_t dataLen, std::vector<uint8_t> &pRetVal)
{
    return 0;
}

int NfcVendorAdaptions::VendorGetConfig(V1_1::NfcVendorConfig &config)
{
    return -1;
}

int NfcVendorAdaptions::VendorFactoryReset(void)
{
    return -1;
}

int NfcVendorAdaptions::VendorShutdownCase(void)
{
    return 0;
}

std::string NfcVendorAdaptions::GetChipType(void)
{
    return "";
}

std::string NfcVendorAdaptions::GetNfcHalFuncNameSuffix(const std::string &chipType)
{
    return "";
}

void NfcVendorAdaptions::ResetNfcInterface(void)
{
    return;
}

int8_t NfcVendorAdaptions::InitNfcHalInterfaces(std::string nfcHalSoName, std::string suffix)
{
    return 0;
}

void NfcVendorAdaptions::CheckFirmwareUpdate(void)
{
    return;
}
} // Nfc
} // HDI
} // OHOS