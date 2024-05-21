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

#ifndef OHOS_HDI_DISPLAY_BUFFER_V1_0_ALLOCATOR_SERVICE_H
#define OHOS_HDI_DISPLAY_BUFFER_V1_0_ALLOCATOR_SERVICE_H

#include "idisplay_buffer_vdi.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/iallocator.h"
#include <mutex>

namespace OHOS {
namespace HDI {
namespace Display {
namespace Buffer {
namespace V1_0 {
class AllocatorService : public IAllocator {
public:
    AllocatorService();
    virtual ~AllocatorService();
    int32_t AllocMem(const AllocInfo& info, sptr<NativeBuffer>& handle) override;

private:
    int32_t LoadVdi();
    void TimeBegin(struct timeval *firstTimeStamp);
    int32_t TimeEnd(const char *func, int32_t time, struct timeval firstTimeStamp);
    void WriteAllocPidToDma(int32_t fd);
    void FreeMemVdi(BufferHandle* handle);
    std::mutex mutex_;
    void *libHandle_;
    IDisplayBufferVdi *vdiImpl_;
    CreateDisplayBufferVdiFunc createVdi_;
    DestroyDisplayBufferVdiFunc destroyVdi_;
};
} // namespace V1_0
} // namespace Buffer
} // namespace Display
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_DISPLAY_BUFFER_V1_0_ALLOCATOR_SERVICE_H
