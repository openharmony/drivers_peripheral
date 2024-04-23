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

#include "face_auth_interface_service_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iconsumer_surface.h"

#include "iam_logger.h"

#include "face_auth_interface_service.h"
#include "refbase.h"

#undef LOG_TAG
#define LOG_TAG "FACE_AUTH_IMPL"

#undef private

namespace OHOS {
namespace HDI {
namespace FaceAuth {
namespace {
FaceAuthInterfaceService g_faceAuthInterfaceService;
void FuzzGetExecutorList(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<sptr<IAllInOneExecutor>> executorList;
    g_faceAuthInterfaceService.GetExecutorList(executorList);
    IAM_LOGI("end");
}

void FuzzSetBufferProducer(Parcel &parcel)
{
    IAM_LOGI("begin");
    sptr<IBufferProducer> bufferProducer = nullptr;
    if (parcel.ReadBool()) {
        auto surface = IConsumerSurface::Create();
        if (surface == nullptr) {
            IAM_LOGE("CreateSurfaceAsConsumer fail");
            return;
        }
        bufferProducer = surface->GetProducer();
    }
    sptr<BufferProducerSequenceable> producerSequenceable =
        new (std::nothrow) BufferProducerSequenceable(bufferProducer);
    g_faceAuthInterfaceService.SetBufferProducer(producerSequenceable);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzGetExecutorList);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzGetExecutorList,
    FuzzSetBufferProducer,
};

void FaceAuthInterfaceServiceFuzzTest(const uint8_t *data, size_t size)
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
} // namespace FaceAuth
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::HDI::FaceAuth::FaceAuthInterfaceServiceFuzzTest(data, size);
    return 0;
}
