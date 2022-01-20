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

#include "power_hdi_callback_service.h"
#include <hdf_base.h>

namespace hdi {
namespace power {
namespace v1_0 {
int32_t PowerHdiCallbackService::OnSuspend()
{
    return HDF_SUCCESS;
}

int32_t PowerHdiCallbackService::OnWakeup()
{
    return HDF_SUCCESS;
}
} // v1_0
} // power
} // hdi
