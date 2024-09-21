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

#ifndef OHOS_HDI_INPUT_V1_0_INPUTCALLBACKIMPL_H
#define OHOS_HDI_INPUT_V1_0_INPUTCALLBACKIMPL_H

#include "v1_0/iinput_callback.h"
#include "input_interfaces_impl.h"

namespace OHOS {
namespace HDI {
namespace Input {
namespace V1_0 {
class InputCallbackImpl : public IInputCallback {
public:
    InputCallbackImpl(const wptr<IInputInterfaces> &inputInterfaces, const wptr<InputCallbackImpl> &otherCallback);
    virtual ~InputCallbackImpl() = default;
    int32_t EventPkgCallback(const std::vector<EventPackage> &pkgs, uint32_t devIndex) override;
    int32_t HotPlugCallback(const HotPlugEvent &event) override;
private:
    wptr<IInputInterfaces> inputInterfaces_;
    wptr<IInputCallback> reportCallback_;
};
} // V1_0
} // Input
} // HDI
} // OHOS

#endif // OHOS_HDI_INPUT_V1_0_INPUTCALLBACKSERVICE_H