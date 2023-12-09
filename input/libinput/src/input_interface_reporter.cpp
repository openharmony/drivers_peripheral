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

#include "input_interface_reporter.h"
#include "hdf_log.h"

#define HDF_LOG_TAG InputIfReporterTag

namespace OHOS {
namespace Input {

RetStatus InputIfReporter::RegisterReportCallback(InputEventCb *callback)
{
    HDF_LOGI("register report callback");

    if (callback == nullptr) {
        HDF_LOGE("param callback is wrong");
        return INPUT_FAILURE;
    }

    std::lock_guard<std::mutex> guard(eventCbMtx_);
    eventCb = callback;
    return INPUT_SUCCESS;
}

RetStatus InputIfReporter::UnregisterReportCallback()
{
    HDF_LOGI("unregister report callback");
    std::lock_guard<std::mutex> guard(eventCbMtx_);
    eventCb = nullptr;
    return INPUT_SUCCESS;
}

RetStatus InputIfReporter::ReportEvent(const IfInputEvent *eventBuf, int eventNum)
{
    if (eventBuf == nullptr) {
        HDF_LOGE("eventBuf is null.");
        return INPUT_FAILURE;
    }

    std::lock_guard<std::mutex> guard(eventCbMtx_);
    if (eventCb == nullptr) {
        return INPUT_SUCCESS;
    }
    eventCb->EventCallback(&eventBuf, eventNum);
    return INPUT_SUCCESS;
}
}
}
