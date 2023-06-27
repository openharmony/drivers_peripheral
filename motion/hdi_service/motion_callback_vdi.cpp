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

#include "motion_callback_vdi.h"

namespace OHOS {
namespace HDI {
namespace Motion {
namespace V1_1 {

int32_t MotionCallbackVdi::OnDataEventVdi(const HdfMotionEventVdi& eventVdi)
{
    struct HdfMotionEvent event;

    if (motionCallback_ == nullptr) {
        HDF_LOGE("%{public}s motionCallback_ is NULL", __func__);
        return HDF_FAILURE;
    }

    event.motion = eventVdi.motion;
    event.result = eventVdi.result;
    event.status = eventVdi.status;
    event.datalen = eventVdi.datalen;
    event.data = eventVdi.data;

    int32_t ret = motionCallback_->OnDataEvent(event);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s OnDataEvent failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

sptr<IRemoteObject> MotionCallbackVdi::HandleCallbackDeath()
{
    sptr<IRemoteObject> remote = OHOS::HDI::hdi_objcast<IMotionCallback>(motionCallback_);

    return remote;
}
} // V1_1
} // Motion
} // HDI
} // OHOS
