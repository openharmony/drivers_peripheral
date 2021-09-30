/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HDI_ALLOCATOR_SERVICE_STUB_V1_0_H
#define HDI_ALLOCATOR_SERVICE_STUB_V1_0_H

#include <iremote_stub.h>
#include <message_option.h>
#include <message_parcel.h>
#include "display_gralloc.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace V1_0 {

enum {
    CMD_ALLOCATOR_ALLOCMEM = 0,
    CMD_ALLOCATOR_FREE,
    CMD_ALLOCATOR_MMAP,
    CMD_ALLOCATOR_UNMAP,
    CMD_ALLOCATOR_INVALIDDATE,
};

class AllocatorServiceStub {
public:
    AllocatorServiceStub();
    virtual ~AllocatorServiceStub();
    int32_t AllocMem(MessageParcel &data, MessageParcel &reply, MessageOption &option) const;

    int32_t OnRemoteRequest(int cmdId, MessageParcel &data, MessageParcel &reply, MessageOption &option) const;

private:
    GrallocFuncs *grallocFuncs_;
};

} // namespace V1_0
} // namespace Display
} // namespace HDI
} // namespace OHOS

void *AllocatorServiceStubInstance();

void AllocatorServiceStubRelease(void *obj);

int32_t AllocatorServiceOnRemoteRequest(void *stub, int cmdId, struct HdfSBuf &data, struct HdfSBuf &reply);

#endif // HDI_ALLOCATOR_SERVICE_STUB_V1_0_H
