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

#include "battery_interface_impl.h"
#include "v2_0/battery_interface_proxy.h"
#include "v2_0/battery_interface_stub.h"
#include "v2_0/ibattery_callback.h"
#include "v2_0/types.h"

using namespace OHOS::HDI::Battery::V2_0;
using namespace HDI::Battery;
using namespace std;

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V2_0 {
namespace {
const int32_t REWIND_READ_DATA = 0;
shared_ptr<BatteryInterfaceStub> g_fuzzService = nullptr;
const uint32_t BATTERY_INTERFACE_STUB_FUNC_MAX_SIZE = 22;
} // namespace

static void BatteryStubFuzzTest(const uint8_t *data, size_t size)
{
    uint32_t code;
    if (size < sizeof(code)) {
        return;
    }
    if (memcpy_s(&code, sizeof(code), data, sizeof(code)) != EOK) {
        return;
    }

    MessageParcel datas;
    datas.WriteInterfaceToken(IBatteryInterface::GetDescriptor());
    datas.WriteBuffer(data, size);
    datas.RewindRead(REWIND_READ_DATA);
    MessageParcel reply;
    MessageOption option;
    if (g_fuzzService == nullptr) {
        sptr<BatteryInterfaceImpl> impl = new BatteryInterfaceImpl();
        impl->Init();
        g_fuzzService = make_shared<BatteryInterfaceStub>(impl);
    }
    for (code = CMD_BATTERY_INTERFACE_GET_VERSION; code < BATTERY_INTERFACE_STUB_FUNC_MAX_SIZE; code++) {
        g_fuzzService->OnRemoteRequest(code, datas, reply, option);
    }
}
} // namespace V2_0
} // namespace Battery
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::HDI::Battery::V2_0::BatteryStubFuzzTest(data, size);
    return 0;
}
