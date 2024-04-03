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

#include "all_in_one_executor_stub_fuzzer.h"

#include "iam_logger.h"

#include "all_in_one_executor_impl.h"
#include "face_auth_hdi.h"

#undef LOG_TAG
#define LOG_TAG "FACE_AUTH_HDI"

#undef private

namespace OHOS {
namespace HDI {
namespace FaceAuth {
namespace {
constexpr uint32_t EXECUTOR_STUB_CODE_MIN = 0;
constexpr uint32_t EXECUTOR_STUB_CODE_MAX = 14;
constexpr uint32_t EXECUTOR_STUB_CODE_MIN_V1_1 = 11;
const std::u16string EXECUTOR_STUB_TOKEN_V1_0 = u"ohos.hdi.face_auth.v1_0.IAllInOneExecutor";
const std::u16string EXECUTOR_STUB_TOKEN_V1_1 = u"ohos.hdi.face_auth.v2_0.IAllInOneExecutor";

bool FaceAuthHdiStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        IAM_LOGE("%{public}s:rawData is null.", __func__);
        return false;
    }
    AllInOneExecutorImpl *serviceImpl = new (std::nothrow) AllInOneExecutorImpl();
    if (serviceImpl == nullptr) {
        IAM_LOGE("%{public}s:get serviceImpl failed.", __func__);
        return false;
    }
    sptr<AllInOneExecutorStub> executorStub = new AllInOneExecutorStub(serviceImpl);
    if (executorStub == nullptr) {
        IAM_LOGE("%{public}s:new executorStub failed.", __func__);
        return false;
    }

    for (uint32_t code = EXECUTOR_STUB_CODE_MIN; code < EXECUTOR_STUB_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        std::u16string EXECUTOR_STUB_TOKEN;
        if (code < EXECUTOR_STUB_CODE_MIN_V1_1) {
            EXECUTOR_STUB_TOKEN = EXECUTOR_STUB_TOKEN_V1_0;
        } else {
            EXECUTOR_STUB_TOKEN = EXECUTOR_STUB_TOKEN_V1_1;
        }
        // Sync
        data.WriteInterfaceToken(EXECUTOR_STUB_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)executorStub->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(EXECUTOR_STUB_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)executorStub->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}
} // namespace
} // namespace FaceAuth
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::HDI::FaceAuth::FaceAuthHdiStubFuzzTest(data, size);
    return 0;
}
