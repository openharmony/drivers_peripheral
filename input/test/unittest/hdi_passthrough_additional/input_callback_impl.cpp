/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "input_uhdf_log.h"

namespace OHOS {
namespace HDI {
namespace Input {
namespace V1_0 {
InputCallbackImpl::InputCallbackImpl(const wptr<IInputInterfaces> &inputInterfaces,
    const wptr<InputCallbackImpl> &otherCallback) : inputInterfaces_(inputInterfaces),
    reportCallback_(otherCallback)
{}

int32_t InputCallbackImpl::EventPkgCallback(const std::vector<EventPackage> &pkgs, uint32_t devIndex)
{
    if (pkgs.empty()) {
        HDF_LOGE("%s: event packages are null\n", __func__);
        return HDF_FAILURE;
    }
    for (uint32_t i = 0; i < pkgs.size(); i++) {
        printf("%s: pkgs[%u] = 0x%x, 0x%x, %d\n", __func__, i, pkgs[i].type, pkgs[i].code, pkgs[i].value);
    }
    return HDF_SUCCESS;
}

int32_t InputCallbackImpl::HotPlugCallback(const HotPlugEvent &event)
{
    if (event.devIndex == 0) {
        return HDF_FAILURE;
    }

    int32_t ret;
    HDF_LOGI("%s: status = %d devId= %d type = %d", __func__, event.status, event.devIndex, event.devType);

    if (event.status == 0) {
        ret = inputInterfaces_->OpenInputDevice(event.devIndex);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: open device[%u] failed, ret %d", __func__, event.devIndex, ret);
            return HDF_FAILURE;
        }

        ret  = inputInterfaces_->RegisterReportCallback(event.devIndex, reportCallback_.GetRefPtr());
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: register callback failed for device[%d], ret %d", __func__, event.devIndex, ret);
            return HDF_FAILURE;
        }
    } else {
        ret = inputInterfaces_->UnregisterReportCallback(event.devIndex);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: unregister callback failed, ret %d", __func__, ret);
            return HDF_FAILURE;
        }

        ret = inputInterfaces_->CloseInputDevice(event.devIndex);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: close device failed, ret %d", __func__, ret);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}
} // V1_0
} // Input
} // HDI
} // OHOS
