/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HOS_CAMERA_V4L2_BUFFER_H
#define HOS_CAMERA_V4L2_BUFFER_H

#include <mutex>
#include <map>
#include <cstring>
#ifdef V4L2_EMULATOR
#include <queue>
#endif
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <memory>
#include "v4l2_common.h"
#if defined(V4L2_UTEST) || defined (V4L2_MAIN_TEST)
#include "v4l2_temp.h"
#else
#include <stream.h>
#include <camera.h>
#endif

namespace OHOS::Camera {
struct AdapterBuff {
    void* start;
    uint32_t length;
    uint32_t offset;
    void* userBufPtr;
    int32_t heapfd;
    int32_t dmafd;
};
class HosV4L2Buffers : public std::enable_shared_from_this<HosV4L2Buffers> {
    // hide construct function
    HosV4L2Buffers(enum v4l2_memory memType, enum v4l2_buf_type bufferType);
public:
    static std::shared_ptr<HosV4L2Buffers> CreateHosV4L2Buffers(enum v4l2_memory memType,
        enum v4l2_buf_type bufferType)
    {
        struct HosV4L2BuffersHelper : public HosV4L2Buffers {
            HosV4L2BuffersHelper(enum v4l2_memory memType, enum v4l2_buf_type bufferType)
                : HosV4L2Buffers(memType, bufferType) {}
        };
        // online code commit rule requires using std::make_shared
        return std::make_shared<HosV4L2BuffersHelper>(memType, bufferType);
    }

    virtual ~HosV4L2Buffers();

    RetCode V4L2ReqBuffers(int fd, int unsigned buffCont);
    RetCode V4L2ReleaseBuffers(int fd);

    RetCode V4L2QueueBuffer(int fd, const std::shared_ptr<FrameSpec>& frameSpec);
    RetCode V4L2DequeueBuffer(int fd);

    RetCode V4L2AllocBuffer(int fd, const std::shared_ptr<FrameSpec>& frameSpec);

    void SetV4L2BuffersCallback(BufCallback cb);

    RetCode Flush(int fd);

private:
    RetCode SetAdapterBuffer(int fd, struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec);
    RetCode SetDmabufOn(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec);
    void MakeInqueueBuffer(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec);
    void SetInqueueBuffer(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec);
    void SetMmapInqueueBuffer(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec);
    void SetDmaInqueueBuffer(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec);

private:
    BufCallback dequeueBuffer_;

    using FrameMap = std::map<unsigned int, std::shared_ptr<FrameSpec>>;
    std::map<int, FrameMap> queueBuffers_;

    using AdapterBuffer = struct AdapterBuff;
    std::map<uint32_t, AdapterBuffer> adapterBufferMap_;

    std::mutex bufferLock_;

    enum v4l2_memory memoryType_;
    enum v4l2_buf_type bufferType_;

    uint32_t buffLong_ = 0;
#ifdef V4L2_EMULATOR
    RetCode SetAndPushBuffer(int fd, const std::shared_ptr<FrameSpec>& frameSpec, v4l2_buffer buf);
    std::queue<uint64_t> queuedBuffers_;
    int availableBuffers_;
#endif
};
} // namespace OHOS::Camera
#endif // HOS_CAMERA_V4L2_BUFFER_H
