/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "wifi_vendor_hal_stubs.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {

template <typename>
struct StubFunction;

template <typename R, typename... Args>
struct StubFunction<R (*)(Args...)> {
    static constexpr R Invoke(Args...) { return HAL_NOT_SUPPORTED; }
};
template <typename... Args>
struct StubFunction<void (*)(Args...)> {
    static constexpr void Invoke(Args...) {}
};

template <typename T>
void PopulateStubFor(T* val)
{
    *val = &StubFunction<T>::Invoke;
}

bool InitHalFuncTableWithStubs(WifiHalFn* halFn)
{
    if (halFn == nullptr) {
        return false;
    }
    PopulateStubFor(&halFn->vendorHalInit);
    PopulateStubFor(&halFn->waitDriverStart);
    PopulateStubFor(&halFn->vendorHalExit);
    PopulateStubFor(&halFn->startHalLoop);
    PopulateStubFor(&halFn->wifiGetSupportedFeatureSet);
    PopulateStubFor(&halFn->wifiGetChipFeatureSet);
    PopulateStubFor(&halFn->vendorHalGetIfaces);
    PopulateStubFor(&halFn->vendorHalGetIfName);
    PopulateStubFor(&halFn->vendorHalGetChannelsInBand);
    PopulateStubFor(&halFn->vendorHalCreateIface);
    PopulateStubFor(&halFn->vendorHalDeleteIface);
    PopulateStubFor(&halFn->vendorHalSetRestartHandler);
    PopulateStubFor(&halFn->vendorHalPreInit);
    PopulateStubFor(&halFn->triggerVendorHalRestart);
    PopulateStubFor(&halFn->wifiSetCountryCode);
    PopulateStubFor(&halFn->getChipCaps);
    PopulateStubFor(&halFn->getPowerMode);
    PopulateStubFor(&halFn->setPowerMode);
    PopulateStubFor(&halFn->wifiStartScan);
    PopulateStubFor(&halFn->wifiStartPnoScan);
    PopulateStubFor(&halFn->wifiStopPnoScan);
    PopulateStubFor(&halFn->getScanResults);
    PopulateStubFor(&halFn->enablePowerMode);
    PopulateStubFor(&halFn->getSignalPollInfo);
    PopulateStubFor(&halFn->setDpiMarkRule);
    PopulateStubFor(&halFn->registerIfaceCallBack);
    PopulateStubFor(&halFn->setTxPower);
    PopulateStubFor(&halFn->registerExtIfaceCallBack);
    PopulateStubFor(&halFn->sendCmdToDriver);
    PopulateStubFor(&halFn->sendActionFrame);
    PopulateStubFor(&halFn->registerActionFrameReceiver);
    PopulateStubFor(&halFn->getCoexictenceChannelList);
    PopulateStubFor(&halFn->setProjectionScreenParam);
    return true;
}
    
} // namespace v1_0
} // namespace Chip
} // namespace Wlan
} // namespace HDI
} // namespace OHOS