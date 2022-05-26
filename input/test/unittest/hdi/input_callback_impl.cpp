/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "input_callback_impl.h"
#include <hdf_base.h>

namespace OHOS {
namespace HDI {
namespace Input {
namespace V1_0 {
int32_t InputCallbackImpl::EventPkgCallback(const std::vector<EventPackage>& pkgs, uint32_t count,
    uint32_t devIndex)
{
    if (pkgs.empty()) {
        printf("%s: event packages are null\n", __func__);
        return HDF_FAILURE;
    }
    for (uint32_t i = 0; i < count; i++) {
        printf("%s: pkgs[%u] = 0x%x, 0x%x, %d\n", __func__, i, pkgs[i].type, pkgs[i].code, pkgs[i].value);
    }
    return HDF_SUCCESS;
}

int32_t InputCallbackImpl::HotPlugCallback(const HotPlugEvent& event)
{
    return HDF_SUCCESS;
}
} // V1_0
} // Input
} // HDI
} // OHOS
