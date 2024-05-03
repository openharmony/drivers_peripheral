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

#include "pin_auth_interface_service_fuzzer.h"
#include "parcel.h"
#include "iam_logger.h"
#include "pin_auth_hdi.h"

#undef LOG_TAG
#define LOG_TAG "PIN_AUTH_HDI"

namespace OHOS {
namespace HDI {
namespace PinAuth {
namespace {

PinAuthInterfaceService g_pinAuthInterFaceService;

void FuzzGetExecutorList(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<sptr<HdiICollector>> collectors;
    std::vector<sptr<HdiIVerifier>> verifiers;
    std::vector<sptr<HdiIAllInOneExecutor>> allInOneExecutors;
    g_pinAuthInterFaceService.GetExecutorList(allInOneExecutors, verifiers, collectors);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzGetExecutorList);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzGetExecutorList
};

void PinAuthInterfaceServiceFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}

} // namespace
} // namespace PinAuth
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::HDI::PinAuth::PinAuthInterfaceServiceFuzzTest(data, size);
    return 0;
}
