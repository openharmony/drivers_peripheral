/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <iostream>
#include "hdf_log.h"
#include "codec_fuzzer.h"
#include "codec_component_manager_service.h"

using namespace OHOS;

extern "C" __attribute__((visibility("default"))) int dlclose(void* handle)
{
    return 0;
}

namespace OHOS {
constexpr size_t THRESHOLD = 10;
constexpr uint32_t OFFSET = 4;
const std::u16string CODEC_INTERFACE_TOKEN = u"ohos.hdi.codec_service";

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

bool CodecFuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < OFFSET) {
        HDF_LOGE("%{public}s: Failed to obtain rawData", __func__);
        return false;
    }
    uint32_t code = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;
    size = size - OFFSET;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    if (data == nullptr) {
        HDF_LOGE("%{public}s: Failed to obtain data", __func__);
        return false;
    }

    HdfSbufWriteBuffer(data, CODEC_INTERFACE_TOKEN.c_str(), CODEC_INTERFACE_TOKEN.length());
    HdfSbufWriteBuffer(data, rawData, size);

    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (reply == nullptr) {
        HDF_LOGE("%{public}s: Failed to obtain reply", __func__);
        HdfSbufRecycle(data);
        return false;
    }

    CodecComponentManagerSerivce *service = nullptr;

    service = CodecComponentManagerSerivceGet();
    if (service == nullptr) {
        HDF_LOGE("%{public}s:CodecComponentManagerSerivceGet failed.", __func__);
        HdfSbufRecycle(data);
        HdfSbufRecycle(reply);
        return false;
    }

    service->stub.OnRemoteRequest((struct CodecComponentManager *)(&service->stub.interface), code, data, reply);

    OmxComponentManagerSeriveRelease(service);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    OHOS::CodecFuzzTest(data, size);
    return 0;
}
