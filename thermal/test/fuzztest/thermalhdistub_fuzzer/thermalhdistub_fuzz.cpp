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

#include "thermal_interface_impl.h"
#include "v1_1/ithermal_callback.h"
#include "v1_1/ithermal_interface.h"
#include "v1_1/thermal_interface_stub.h"
#include "v1_1/thermal_types.h"

using namespace OHOS::HDI;
using namespace OHOS::HDI::Thermal::V1_1;
using namespace std;

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
namespace {
const int32_t REWIND_READ_DATA = 0;
shared_ptr<ThermalInterfaceStub> g_fuzzService = nullptr;
const uint32_t THERMAL_INTERFACE_STUB_FUNC_MAX_SIZE = 10;
} // namespace

static void ThermalStubFuzzTest(const uint8_t *data, size_t size)
{
    uint32_t code;
    if (size < sizeof(code)) {
        return;
    }
    if (memcpy_s(&code, sizeof(code), data, sizeof(code)) != EOK) {
        return;
    }

    MessageParcel datas;
    datas.WriteInterfaceToken(IThermalInterface::GetDescriptor());
    datas.WriteBuffer(data, size);
    datas.RewindRead(REWIND_READ_DATA);
    MessageParcel reply;
    MessageOption option;
    if (g_fuzzService == nullptr) {
        g_fuzzService = make_shared<ThermalInterfaceStub>(new ThermalInterfaceImpl());
    }
    for (code = CMD_THERMAL_INTERFACE_GET_VERSION; code < THERMAL_INTERFACE_STUB_FUNC_MAX_SIZE; code++) {
        g_fuzzService->OnRemoteRequest(code, datas, reply, option);
    }
}
} // namespace V1_1
} // namespace Thermal
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::HDI::Thermal::V1_1::ThermalStubFuzzTest(data, size);
    return 0;
}
