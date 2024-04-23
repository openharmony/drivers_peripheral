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

#include "face_auth_interface_stub_fuzzer.h"

#include "iam_logger.h"

#include "face_auth_hdi.h"

#undef LOG_TAG
#define LOG_TAG "FACE_AUTH_IMPL"

#undef private

namespace OHOS {
namespace HDI {
namespace FaceAuth {
namespace {
constexpr uint32_t FACE_AUTH_INTERFACE_STUB_CODE_MIN = 0;
constexpr uint32_t FACE_AUTH_INTERFACE_STUB_CODE_MAX = 3;
constexpr uint32_t FACE_AUTH_INTERFACE_STUB_CODE_MIN_V1_1 = 2;
const std::u16string FACE_AUTH_INTERFACE_STUB_TOKEN_V1_0 = u"ohos.hdi.face_auth.v1_0.IFaceAuthInterface";
const std::u16string FACE_AUTH_INTERFACE_STUB_TOKEN_V1_1 = u"ohos.hdi.face_auth.v2_0.IFaceAuthInterface";

bool FaceAuthInterfaceStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        IAM_LOGE("%{public}s:rawData is null.", __func__);
        return false;
    }
    sptr<IFaceAuthInterface> serviceImpl = IFaceAuthInterface::Get(true);
    if (serviceImpl == nullptr) {
        IAM_LOGE("%{public}s:get serviceImpl failed.", __func__);
        return false;
    }
    sptr<FaceAuthInterfaceStub> faceAuthInterfaceStub = new FaceAuthInterfaceStub(serviceImpl);
    if (faceAuthInterfaceStub == nullptr) {
        IAM_LOGE("%{public}s:new IFaceAuthInterfaceStub failed.", __func__);
        return false;
    }

    for (uint32_t code = FACE_AUTH_INTERFACE_STUB_CODE_MIN; code < FACE_AUTH_INTERFACE_STUB_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        std::u16string FACE_AUTH_INTERFACE_STUB_TOKEN;
        if (code < FACE_AUTH_INTERFACE_STUB_CODE_MIN_V1_1) {
            FACE_AUTH_INTERFACE_STUB_TOKEN = FACE_AUTH_INTERFACE_STUB_TOKEN_V1_0;
        } else {
            FACE_AUTH_INTERFACE_STUB_TOKEN = FACE_AUTH_INTERFACE_STUB_TOKEN_V1_1;
        }
        // Sync
        data.WriteInterfaceToken(FACE_AUTH_INTERFACE_STUB_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)faceAuthInterfaceStub->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(FACE_AUTH_INTERFACE_STUB_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)faceAuthInterfaceStub->OnRemoteRequest(code, data, reply, optionAsync);
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
    OHOS::HDI::FaceAuth::FaceAuthInterfaceStubFuzzTest(data, size);
    return 0;
}
