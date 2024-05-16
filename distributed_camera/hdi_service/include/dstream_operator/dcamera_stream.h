/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_CAMERA_STREAM_H
#define DISTRIBUTED_CAMERA_STREAM_H

#include "surface.h"
#include "dimage_buffer.h"
#include "dbuffer_manager.h"

#include "v1_1/dcamera_types.h"
#include "v1_0/types.h"

namespace OHOS {
namespace DistributedHardware {
using namespace std;
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::HDI::DistributedCamera::V1_1;
class DCameraStream {
public:
    DCameraStream() = default;
    ~DCameraStream() = default;
    DCameraStream(const DCameraStream &other) = delete;
    DCameraStream(DCameraStream &&other) = delete;
    DCameraStream &operator=(const DCameraStream &other) = delete;
    DCameraStream &operator=(DCameraStream &&other) = delete;

public:
    DCamRetCode InitDCameraStream(const StreamInfo &info);
    DCamRetCode GetDCameraStreamInfo(shared_ptr<StreamInfo> &info);
    DCamRetCode SetDCameraBufferQueue(const OHOS::sptr<BufferProducerSequenceable> &producer);
    DCamRetCode ReleaseDCameraBufferQueue();
    DCamRetCode GetDCameraStreamAttribute(StreamAttribute &attribute);
    DCamRetCode GetDCameraBuffer(DCameraBuffer &buffer);
    DCamRetCode ReturnDCameraBuffer(const DCameraBuffer &buffer);
    DCamRetCode FinishCommitStream();
    bool HasBufferQueue();
    void DoCapture();
    void CancelCaptureWait();

private:
    DCamRetCode InitDCameraBufferManager();
    DCamRetCode GetNextRequest();
    DCamRetCode CheckRequestParam();
    void SetSurfaceBuffer(OHOS::sptr<OHOS::SurfaceBuffer>& surfaceBuffer, const DCameraBuffer &buffer);
    DCamRetCode CancelDCameraBuffer();
    DCamRetCode FlushDCameraBuffer(const DCameraBuffer &buffer);
    uint64_t GetVideoTimeStamp();
    DCamRetCode SurfaceBufferToDImageBuffer(OHOS::sptr<OHOS::SurfaceBuffer> &surfaceBuffer,
        OHOS::sptr<OHOS::SyncFence> &syncFence);

private:
    int32_t index_ = -1;
    int dcStreamId_;
    shared_ptr<StreamInfo> dcStreamInfo_ = nullptr;
    StreamAttribute dcStreamAttribute_;
    shared_ptr<DBufferManager> dcStreamBufferMgr_ = nullptr;
    OHOS::sptr<OHOS::Surface> dcStreamProducer_ = nullptr;
    map<shared_ptr<DImageBuffer>, tuple<OHOS::sptr<OHOS::SurfaceBuffer>, int>> bufferConfigMap_;
    condition_variable cv_;
    int captureBufferCount_ = 0;
    bool isBufferMgrInited_ = false;
    bool isCancelBuffer_ = false;
    bool isCancelCapture_ = false;
    mutex requestMutex_;
    mutex bufferQueueMutex_;
    mutex lockSync_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // DISTRIBUTED_CAMERA_STREAM_H