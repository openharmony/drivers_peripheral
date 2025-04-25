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

#include "securec.h"
#include <cstdint>
#include <cstdlib>
#include <memory>

#include "power_interface_impl.h"
#include "v1_3/ipower_interface.h"
#include "v1_3/power_interface_stub.h"
#include "running_lock_impl.h"
#include "refbase.h"

using namespace OHOS::HDI;
using namespace OHOS::HDI::Power::V1_3;
using namespace std;

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_3 {
constexpr int32_t DEFAULT_TIMEOUT_FOR_TEST_MS = 100;

class PowerFuzzTest {
public:
    PowerFuzzTest()
    {
        impl_ = sptr<PowerInterfaceImpl>::MakeSptr();
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
shared_ptr<PowerInterfaceStub> g_fuzzService = nullptr;
shared_ptr<PowerFuzzTest> g_fuzzTest = nullptr;
const uint32_t POWER_INTERFACE_STUB_FUNC_MAX_SIZE = 18;
} // namespace

static void PowerHdiFuzzTest(const uint8_t *data, size_t size)
{
    uint32_t code;
    if (size < sizeof(code)) {
        return;
    }
    if (memcpy_s(&code, sizeof(code), data, sizeof(code)) != EOK) {
        return;
    }
    OHOS::HDI::Power::V1_3::IPowerInterface::Get(true);

    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    if (g_fuzzService == nullptr) {
        g_fuzzTest = make_shared<PowerFuzzTest>();
        g_fuzzService = make_shared<PowerInterfaceStub>(g_fuzzTest->GetImpl());
    }
    for (code = CMD_POWER_INTERFACE_GET_VERSION; code < POWER_INTERFACE_STUB_FUNC_MAX_SIZE; code++) {
        g_fuzzService->OnRemoteRequest(code, datas, reply, option);
    }
    RunningLockImpl::SetDefaultTimeOutMs(DEFAULT_TIMEOUT_FOR_TEST_MS);
    RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE);
    RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE);
    RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION);
    RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO);
    RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT);
    RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION);
    RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BUTT);
    RunningLockImpl::GetRunningLockTagInner(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE);
    RunningLockImpl::GetRunningLockTagInner(RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION);
    RunningLockImpl::GetRunningLockTagInner(RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO);
    RunningLockImpl::GetRunningLockTagInner(RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT);
    RunningLockImpl::GetRunningLockTagInner(RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION);
    RunningLockImpl::GetRunningLockTagInner(RunningLockType::RUNNINGLOCK_BACKGROUND_TASK);
    RunningLockImpl::GetRunningLockTagInner(RunningLockType::RUNNINGLOCK_BUTT);
    RunningLockImpl::Clean();
}
} // namespace V1_3
} // namespace Power
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::HDI::Power::V1_3::PowerHdiFuzzTest(data, size);
    return 0;
}
