/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "securec.h"
#include <cstdint>
#include <cstdlib>
#include <memory>
#include "v2_0/chip_controller_stub.h"
#include "../../../chip/hdi_service/wifi.h"

using namespace OHOS::HDI::Wlan::Chip::V2_0;
using namespace std;

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V2_0 {

namespace {
const int32_t REWIND_READ_DATA = 0;
shared_ptr<ChipControllerStub> g_WifiChipController = nullptr;
}

static void WifiChipStubFuzzTest(const uint8_t *data, size_t size)
{
    uint32_t code;
    if (size < sizeof(code)) {
        return;
    }
    if (memcpy_s(&code, sizeof(code), data, sizeof(code)) != EOK) {
        return;
    }

    MessageParcel datas;
    datas.WriteInterfaceToken(IChipController::GetDescriptor());
    datas.WriteBuffer(data, size);
    datas.RewindRead(REWIND_READ_DATA);
    MessageParcel reply;
    MessageOption option;
    if (g_WifiChipController == nullptr) {
        sptr<Wifi> impl = new Wifi();
        impl->Init();
        g_WifiChipController = make_shared<ChipControllerStub>(impl);
    }
    g_WifiChipController->OnRemoteRequest(code, datas, reply, option);
}
} // namespace V1_1
} // namespace Chip
} // namespace Wlan
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::HDI::Wlan::Chip::V2_0::WifiChipStubFuzzTest(data, size);
    return 0;
}
