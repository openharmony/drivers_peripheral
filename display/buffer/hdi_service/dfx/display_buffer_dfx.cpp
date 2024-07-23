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

#include "display_buffer_dfx.h"
#include <hdf_log.h>

#define TIME_1000 1000
#define TIME_10 10
#define HICOLLIE_TIMEOUT 5

namespace OHOS {
namespace HDI {
namespace Display {
namespace Buffer {
namespace V1_0 {
DisplayBufferDfx::DisplayBufferDfx(std::string name)
    : dfxName_(name),
    timeId_(0),
    flag_(false)
{
}

DisplayBufferDfx::~DisplayBufferDfx()
{
    if (timeId_ != 0) {
        CancelTimer();
    }
    if (flag_) {
        TimeEnd();
    }
}

void DisplayBufferDfx::SetTimer()
{
#ifdef DISPLAY_HICOLLIE_ENABLE
    timeId_ = HiviewDFX::XCollie::GetInstance().SetTimer(dfxName_, HICOLLIE_TIMEOUT, nullptr, nullptr,
        HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY);
#endif
}

void DisplayBufferDfx::CancelTimer()
{
#ifdef DISPLAY_HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timeId_);
#endif
}

void DisplayBufferDfx::TimeBegin()
{
    gettimeofday(&beginTimeStamp, nullptr);
    flag_ = true;
}

void DisplayBufferDfx::TimeEnd()
{
    gettimeofday(&endTimeStamp, nullptr);
    int32_t runTime = (int32_t)((endTimeStamp.tv_sec - beginTimeStamp.tv_sec) * TIME_1000 +
        (endTimeStamp.tv_usec - beginTimeStamp.tv_usec) / TIME_1000);
    if (runTime > TIME_10) {
        HDF_LOGW("run %{public}s over time, [%{public}d]ms", dfxName_.c_str(), runTime);
    }
    flag_ = false;
}
} // namespace V1_0
} // namespace Buffer
} // namespace Display
} // namespace HDI
} // namespace OHOS