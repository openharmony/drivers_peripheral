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

#include "power_interface_impl.h"
#include "v1_2/ipower_interface.h"
#include "v1_2/power_interface_stub.h"
#include "v1_2/power_types.h"

using namespace OHOS::HDI;
using namespace OHOS::HDI::Power::V1_2;
using namespace std;

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_2 {
class PowerFuzzTest {
public:
    PowerFuzzTest()
    {
        impl_ = new PowerInterfaceImpl();
        impl_->SuspendBlock("PowerStubFuzzTest"); // Prevent device sleep
    }
    ~PowerFuzzTest()
    {
        impl_->SuspendUnblock("PowerStubFuzzTest");
    }
    sptr<PowerInterfaceImpl> GetImpl() const
    {
        return impl_;
    }

private:
    sptr<PowerInterfaceImpl> impl_ = nullptr;
};
namespace {
const int32_t REWIND_READ_DATA = 0;
shared_ptr<PowerInterfaceStub> g_fuzzService = nullptr;
shared_ptr<PowerFuzzTest> g_fuzzTest = nullptr;
const uint32_t POWER_INTERFACE_STUB_FUNC_MAX_SIZE = 15;
} // namespace

static void PowerStubFuzzTest(const uint8_t *data, size_t size)
{
    uint32_t code;
    if (size < sizeof(code)) {
        return;
    }
    if (memcpy_s(&code, sizeof(code), data, sizeof(code)) != EOK) {
        return;
    }

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    if (g_fuzzService == nullptr) {
        g_fuzzTest = make_shared<PowerFuzzTest>();
        g_fuzzService = make_shared<PowerInterfaceStub>(g_fuzzTest->GetImpl());
    }
    for (code = CMD_POWER_INTERFACE_GET_VERSION; code < POWER_INTERFACE_STUB_FUNC_MAX_SIZE; code++) {
        // Filter force sleep calls
        if (CMD_POWER_INTERFACE_FORCE_SUSPEND == code) {
            continue;
        }
        datas.WriteInterfaceToken(IPowerInterface::GetDescriptor());
        datas.WriteBuffer(data, size);
        datas.RewindRead(REWIND_READ_DATA);
        g_fuzzService->OnRemoteRequest(code, datas, reply, option);
    }
}
} // namespace V1_2
} // namespace Power
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::HDI::Power::V1_2::PowerStubFuzzTest(data, size);
    return 0;
}
