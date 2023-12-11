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

#ifndef INPUT_INTERFACE_IMPLEMENT_H
#define INPUT_INTERFACE_IMPLEMENT_H

#include "hdf_log.h"
#include "input_type.h"
#include "input_interface_reporter.h"
#include "input_interface_device_info.h"

namespace OHOS {
namespace Input {
class InputIfImpl {
public:
    InputIfImpl() = default;
    virtual ~InputIfImpl();
    InputIfImpl(const InputIfImpl &other) = delete;
    InputIfImpl(InputIfImpl &&other) = delete;
    InputIfImpl &operator=(const InputIfImpl &other) = delete;
    InputIfImpl &operator=(InputIfImpl &&other) = delete;
    RetStatus Init(void);
    RetStatus RegisterReportCallback(InputEventCb *callback);
    RetStatus UnregisterReportCallback();

private:
    std::shared_ptr<InputIfReporter> reporterSptr_ {nullptr};
    std::shared_ptr<DeviceInfo> deviceInfoSptr_ {nullptr};
};
}
}
#endif // INPUT_INTERFACE_IMPLEMENT_H