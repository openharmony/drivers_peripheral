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

#include "input_interface_implement.h"
#include <memory>
#include "hdf_log.h"
#include "input_interface_device_info.h"
#include "input_interface_reporter.h"

#define HDF_LOG_TAG InputIfImpl

namespace OHOS {
namespace Input {
using namespace std;
RetStatus InputIfImpl::Init()
{
    reporterSptr_ = std::make_shared<InputIfReporter>();
    if (reporterSptr_ == nullptr) {
        HDF_LOGE("input interface init reporter failed");
        return INPUT_NOMEM;
    }
    deviceInfoSptr_ = std::make_shared<DeviceInfo>(reporterSptr_);
    if (deviceInfoSptr_ == nullptr) {
        HDF_LOGE("input interface init device info failed");
        return INPUT_NOMEM;
    }
    return deviceInfoSptr_->Init();
}

InputIfImpl::~InputIfImpl()
{
    deviceInfoSptr_->Stop();
}

RetStatus InputIfImpl::RegisterReportCallback(InputEventCb *callback)
{
    return reporterSptr_->RegisterReportCallback(callback);
}

RetStatus InputIfImpl::UnregisterReportCallback()
{
    return reporterSptr_->UnregisterReportCallback();
}
}
}
