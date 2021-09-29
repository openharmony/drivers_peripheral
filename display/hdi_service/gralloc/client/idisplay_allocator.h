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

#ifndef HDI_IDISPLAY_ALLOCATOR_V1_0_H 
#define HDI_IDISPLAY_ALLOCATOR_V1_0_H

#include "iservmgr_hdi.h"
#include "hdf_log.h"
#include "display_type.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace V1_0 {

class IDisplayAllocator: public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Display.Gralloc.IAllocator.V1_0");
    virtual ~IDisplayAllocator() {}
    virtual int32_t AllocMem(const AllocInfo &info, BufferHandle *&handle) = 0;
    static sptr<IDisplayAllocator> Get(const char *serviceName);
};

} // namespace V1_0
} // namespace Display
} // namespace HDI
} // namespace OHOS

#endif // HDI_IDISPLAY_ALLOCATOR_V1_0_H
