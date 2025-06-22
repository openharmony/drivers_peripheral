/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "stream_statistics.h"
#include <sstream>

namespace OHOS::Camera {
StreamStatistics::StreamStatistics()
{
    Clear();
}

StreamStatistics::StreamStatistics(int32_t streamId)
{
    streamId_ = streamId;
    Clear();
}

StreamStatistics::~StreamStatistics() {}

void StreamStatistics::SetStreamId(int32_t streamId)
{
    streamId_ = streamId;
}

void StreamStatistics::RequestBufferSuccess()
{
    requestBufferSuccessCount_++;
}

void StreamStatistics::RequestBufferFail()
{
    requestBufferFailCount_++;
}

void StreamStatistics::FlushBufferSuccess()
{
    flushBufferSuccessCount_++;
}

void StreamStatistics::FlushBufferFail()
{
    flushBufferFailCount_++;
}

void StreamStatistics::CancelBufferSuccess()
{
    cancelBufferSuccessCount_++;
}

void StreamStatistics::CancelBufferFail()
{
    cancelBufferFailCount_++;
}

void StreamStatistics::Clear()
{
    requestBufferSuccessCount_ = 0;
    requestBufferFailCount_ = 0;
    flushBufferSuccessCount_ = 0;
    flushBufferFailCount_ = 0;
    cancelBufferSuccessCount_ = 0;
    cancelBufferFailCount_ = 0;
}

void StreamStatistics::CalculateFps(int interval)
{
    if (interval > 0) {
        fpsValue_ = (requestBufferSuccessCount_ - lastRequestBufferCount_) / interval;
        lastRequestBufferCount_ = requestBufferSuccessCount_;
    } else {
        return;
    }
}

void StreamStatistics::DumpStats(int interval)
{
    if (clock_gettime(CLOCK_MONOTONIC, &timestamp_) != 0) {
        CAMERA_LOGE("clock_gettime error");
        return;
    }

    if (lastOutputTime_ == 0) {
        lastOutputTime_ = timestamp_.tv_sec;
        return;
    }

    if (timestamp_.tv_sec - lastOutputTime_ > interval) {
        CalculateFps(timestamp_.tv_sec - lastOutputTime_);
        std::stringstream ss;
        ss << "streamId:" << streamId_ << ", buf status(suc/fail) req:" << requestBufferSuccessCount_ <<
            "/" << requestBufferFailCount_ << ", flush:" <<flushBufferSuccessCount_ << "/" <<
            flushBufferFailCount_ <<", cancel:" << cancelBufferSuccessCount_ << "/" <<
            cancelBufferFailCount_ << ", fps:" << fpsValue_;
        streamInfo_ = ss.str();
        CAMERA_LOGI("%{public}s", streamInfo_.c_str());
        lastOutputTime_ = timestamp_.tv_sec;
    }
}

void StreamStatistics::CancelBufferResult(int32_t ret)
{
    if (ret != 0) {
        CancelBufferFail();
    } else {
        CancelBufferSuccess();
    }
}

void StreamStatistics::FlushBufferResult(int32_t ret)
{
    if (ret != 0) {
        FlushBufferFail();
    } else {
        FlushBufferSuccess();
    }
}

void StreamStatistics::RequestBufferResult(OHOS::SurfaceError sfError)
{
    if (sfError != OHOS::SURFACE_ERROR_OK) {
        RequestBufferFail();
    } else {
        RequestBufferSuccess();
    }
}

void StreamStatistics::RequestBufferResult(OHOS::SurfaceBuffer *sbuffer)
{
    if (sbuffer == nullptr) {
        RequestBufferFail();
    } else {
        RequestBufferSuccess();
    }
}
} // end namespace OHOS::Camera
