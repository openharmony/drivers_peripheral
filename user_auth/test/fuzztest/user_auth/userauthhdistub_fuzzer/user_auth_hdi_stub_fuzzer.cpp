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

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_logger.h"

#include "v1_1/user_auth_interface_service.h"
#include "v1_1/user_auth_interface_stub.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_USER_AUTH_HDI

#undef private

using namespace OHOS::HDI::UserAuth::V1_1;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t USER_AUTH_HDI_CODE_MIN = 0;
constexpr uint32_t USER_AUTH_HDI_CODE_MAX = 25;
constexpr uint32_t USER_AUTH_HDI_CODE_MIN_V1_1 = 22;
const std::u16string USER_AUTH_HDI_INTERFACE_TOKEN_V1_0 = u"ohos.hdi.user_auth.v1_0.IUserAuthInterface";
const std::u16string USER_AUTH_HDI_INTERFACE_TOKEN_V1_1 = u"ohos.hdi.user_auth.v1_1.IUserAuthInterface";

bool UserAuthHdiStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        IAM_LOGE("%{public}s:rawData is null.", __func__);
        return false;
    }
    sptr<OHOS::HDI::UserAuth::V1_1::IUserAuthInterface> serviceImpl =
        OHOS::HDI::UserAuth::V1_1::IUserAuthInterface::Get(true);
    if (serviceImpl == nullptr) {
        IAM_LOGE("%{public}s:IUserAuthInterface::Get() failed.", __func__);
        return false;
    }
    sptr<OHOS::HDI::UserAuth::V1_1::UserAuthInterfaceStub> userAuthInterfaceStub =
        new OHOS::HDI::UserAuth::V1_1::UserAuthInterfaceStub(serviceImpl);
    if (userAuthInterfaceStub == nullptr) {
        IAM_LOGE("%{public}s:new UserAuthInterfaceStub failed.", __func__);
        return false;
    }

    for (uint32_t code = USER_AUTH_HDI_CODE_MIN; code < USER_AUTH_HDI_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        std::u16string USER_AUTH_HDI_INTERFACE_TOKEN;
        if (code < USER_AUTH_HDI_CODE_MIN_V1_1) {
            USER_AUTH_HDI_INTERFACE_TOKEN = USER_AUTH_HDI_INTERFACE_TOKEN_V1_0;
        } else {
            USER_AUTH_HDI_INTERFACE_TOKEN = USER_AUTH_HDI_INTERFACE_TOKEN_V1_1;
        }
        // Sync
        data.WriteInterfaceToken(USER_AUTH_HDI_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)userAuthInterfaceStub->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(USER_AUTH_HDI_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)userAuthInterfaceStub->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}
} // namespace
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::UserIam::UserAuth::UserAuthHdiStubFuzzTest(data, size);
    return 0;
}
