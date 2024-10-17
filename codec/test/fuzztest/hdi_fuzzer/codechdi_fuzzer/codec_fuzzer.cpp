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

#include "codec_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include "hdf_log.h"
#include "v3_0/codec_component_manager_stub.h"

using namespace OHOS::HDI::Codec::V3_0;

extern "C" __attribute__((visibility("default"))) int dlclose(void* handle)
{
    return 0;
}

namespace OHOS {
constexpr size_t THRESHOLD = 10;
constexpr int32_t OFFSET = 4;
const std::u16string CODEC_INTERFACE_TOKEN = u"ohos.hdi.codec.V3_0.ICodecComponentManager";
#define CMD_CODEC_COMPONENT_MANAGER_GREATE_COMPONENT 3

uint32_t Convert2Uint32(const uint8_t* ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    /*
     * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
     * and the third digit no left
     */
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }
    uint32_t code = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;
    size = size - OFFSET;

    MessageParcel data;
    data.WriteInterfaceToken(CODEC_INTERFACE_TOKEN);
    data.WriteBuffer(rawData, size);
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<ICodecComponentManager> g_codecComponentManager = ICodecComponentManager::Get(true);
    if (g_codecComponentManager == nullptr) {
        HDF_LOGE("%{public}s:ICodecComponentManager::Get failed.", __func__);
        return false;
    }
    sptr<CodecComponentManagerStub> codecComponentManager = new CodecComponentManagerStub(g_codecComponentManager);
    if (codecComponentManager == nullptr) {
        HDF_LOGE("%{public}s:new codecComponentManager failed.", __func__);
        return false;
    }
    int32_t ret = codecComponentManager->OnRemoteRequest(code, data, reply, option);
    if (ret != HDF_SUCCESS) {
        return false;
    }

    if (code == CMD_CODEC_COMPONENT_MANAGER_GREATE_COMPONENT) {
        uint32_t componentId = 0;
        if (!reply.ReadUint32(componentId)) {
            HDF_LOGE("%{public}s:read componentId failed!", __func__);
            return false;
        }
        ret = g_codecComponentManager->DestroyComponent(componentId);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: DestroyComponent failed\n", __func__);
            return false;
        }
    }

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

