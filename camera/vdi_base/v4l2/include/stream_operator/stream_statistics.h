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

#ifndef STREAM_STATISTICS_H
#define STREAM_STATISTICS_H

#include <cstdint>
#include <string>
#include "surface.h"
#include "surface_type.h"
#include "display_format.h"
#include "camera.h"

namespace OHOS::Camera {
class StreamStatistics {
public:
    StreamStatistics();
    StreamStatistics(int32_t streamId);
    ~StreamStatistics();
    void SetStreamId(int32_t streamId);
    void RequestBufferSuccess();
    void RequestBufferFail();
    void RequestBufferResult(OHOS::SurfaceError sfError);
    void RequestBufferResult(OHOS::SurfaceBuffer *sbuffer);
    void FlushBufferSuccess();
    void FlushBufferFail();
    void FlushBufferResult(int32_t ret);
    void CancelBufferSuccess();
    void CancelBufferFail();
    void CancelBufferResult(int32_t ret);
    void Clear();
    void DumpStats(int interval = 0);
    void CalculateFps(int interval);

private:
    int32_t streamId_;
    uint32_t requestBufferSuccessCount_;
    uint32_t lastRequestBufferCount_ = 0;
    uint32_t requestBufferFailCount_;
    uint32_t flushBufferSuccessCount_;
    uint32_t flushBufferFailCount_;
    uint32_t cancelBufferSuccessCount_;
    uint32_t cancelBufferFailCount_;
    uint32_t fpsValue_;
    uint64_t lastOutputTime_ = 0;
    std::string streamInfo_;
    timespec timestamp_ = {0, 0};
};
} // end namespace OHOS::Camera
#endif // STREAM_STATISTICS_H
