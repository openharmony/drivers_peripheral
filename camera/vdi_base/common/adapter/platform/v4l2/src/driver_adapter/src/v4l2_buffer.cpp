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

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/dma-heap.h>
#include <linux/dma-buf.h>
#include <chrono>
#ifndef V4L2_MAIN_TEST
#include "ibuffer.h"
#endif
#include "securec.h"
#include "v4l2_buffer.h"
#include "camera_dump.h"
#define NOLOG
#include "TimeOutExecutor.h"

#ifdef V4L2_EMULATOR
#include <sys/ioctl.h>

#define PARAM_MANAGER_DEBUG_LOG
#include "device/hmos_emulator/hardware/dcodec/include/ParamManager.h"

#define IOC_GET_CAMERA_ID _IOR('V', 105, int)
#define IOC_QUEUE_BUFFER _IOWR('V', 106, uint64_t)
#define IOC_DEQUEUE_BUFFER _IOW('V', 107, int)
#define IOC_REQUEST_BUFFER _IOR('V', 108, int)

#define CAMERA_FUN_GET_CAMERA_COUNT 1
#define CAMERA_FUN_START_STREAM 2
#define CAMERA_FUN_STOP_STREAM 3
#define CAMERA_FUN_QUEUE_BUFFER 4
#define CAMERA_FUN_QUEUE_BUFFER_HW 5
#define CAMERA_FUN_GET_PROP 6
#define CAMERA_FUN_MAXID CAMERA_FUN_GET_PROP

#define EXPRESS_CAMERA_DEVICE_ID ((uint64_t)80)
#endif

using namespace OHOS::TIMEOUTEXECUTOR;

namespace OHOS::Camera {
const std::string DMA_BUF_FILE_NAME = "/dev/dma_heap/system";

RetCode ioctlWrapper(int fd, uint32_t buffCont, uint32_t buffType, uint32_t memoryType)
{
    CAMERA_LOGD("Enter function:  %{public}s\n", __FUNCTION__);
    CAMERA_LOGD("Parameters[buffCont: %{public}d, buffType: %{public}d, memoryType: %{public}d]\n",
        buffCont, buffType, memoryType);

    struct v4l2_requestbuffers req = {};
    req.count = buffCont;
    req.type = buffType;
    req.memory = memoryType;

#ifdef V4L2_EMULATOR
    if (req.count != buffCont) {
        CAMERA_LOGE("error Insufficient buffer memory on \n");
        return RC_ERROR;
    }
#else
    if (ioctl(fd, VIDIOC_REQBUFS, &req) < 0) {
        CAMERA_LOGE("does not support memory mapping %{public}s\n", strerror(errno));
        return RC_ERROR;
    }

    if (req.count != buffCont) {
        CAMERA_LOGE("error Insufficient buffer memory on \n");

        req.count = 0;
        req.type = buffType;
        req.memory = memoryType;

        // Insufficient buffer memory, release rollback memory
        if (ioctl(fd, VIDIOC_REQBUFS, &req) < 0) {
            CAMERA_LOGE("V4L2ReqBuffers does not release buffer %{public}s\n", strerror(errno));
            return RC_ERROR;
        }
        return RC_ERROR;
    }
#endif
    return RC_OK;
}

#ifdef V4L2_EMULATOR
HosV4L2Buffers::HosV4L2Buffers(enum v4l2_memory memType, enum v4l2_buf_type bufferType)
    : memoryType_(memType), bufferType_(bufferType), availableBuffers_(0)
{
}
#else
HosV4L2Buffers::HosV4L2Buffers(enum v4l2_memory memType, enum v4l2_buf_type bufferType)
    : memoryType_(memType), bufferType_(bufferType)
{
}
#endif
HosV4L2Buffers::~HosV4L2Buffers() {}

RetCode HosV4L2Buffers::V4L2ReqBuffers(int fd, int unsigned buffCont)
{
    RetCode result = RC_OK;
    TimeOutExecutor<decltype(ioctlWrapper)> executor(ioctlWrapper);
    auto executeRet = executor.Execute(result, fd, buffCont, bufferType_, memoryType_);
    if (TimeOutExecutor<decltype(ioctlWrapper)>::TIMEOUT == executeRet) {
        CAMERA_LOGE("request buffer timeout, max waittime: %{public}d ms\n", executor.GetTimeOut());
        return RC_ERROR;
    }

    // executeRet is SUCCESS
    CAMERA_LOGI("request buffer execute successful. \n");
    return result;
}

#ifdef V4L2_EMULATOR
RetCode HosV4L2Buffers::SetAndPushBuffer(int fd, const std::shared_ptr<FrameSpec>& frameSpec, v4l2_buffer buf)
{
    uint64_t id = (uint64_t)buf.index;
    void *addr = frameSpec->buffer_->GetVirAddress();
    uint32_t len = frameSpec->buffer_->GetSize();
    frameSpec->buffer_->SetBufferStatus(CAMERA_BUFFER_STATUS_OK);

    CAMERA_LOGI("express_camera queue buffer id %" PRIx64
    " addr %p len %d framespec %p streamId %d, status %d, format %d, curformat %d",
    id, addr, len, frameSpec.get(), frameSpec->buffer_->GetStreamId(), frameSpec->buffer_->GetBufferStatus(),
    frameSpec->buffer_->GetFormat(),  frameSpec->buffer_->GetCurFormat());

    if (addr == NULL || len == 0) {
        return RC_ERROR;
    }
 
    ParamManager mgr(EXPRESS_CAMERA_DEVICE_ID, CAMERA_FUN_QUEUE_BUFFER, false);
    mgr.addParam64(id);
    mgr.addPtr(addr, len);

    constexpr int CaptureStreamId = 2;
    if (frameSpec->buffer_->GetStreamId() == CaptureStreamId) {
        constexpr int SleepTimeUs = 50000;
        usleep(SleepTimeUs); // 50ms delay
    }
    int ret = mgr.ioctl(fd, IOC_QUEUE_BUFFER);
    if (ret < 0) {
        CAMERA_LOGE("HosV4L2Buffers::V4L2QueueBuffer: IOC_QUEUE_BUFFER Failed: %d", ret);
        return RC_ERROR;
    }
    std::lock_guard<std::mutex> l(bufferLock_);
    queuedBuffers_.push(buf.index);
    return RC_OK;
}
#endif

RetCode HosV4L2Buffers::V4L2QueueBuffer(int fd, const std::shared_ptr<FrameSpec>& frameSpec)
{
    struct v4l2_buffer buf = {};
    struct v4l2_plane planes[1] = {};
    CAMERA_LOGI("HosV4L2Buffers V4L2QueueBuffer in fd: %{public}d\n", fd);
    if (frameSpec == nullptr) {
        CAMERA_LOGE("V4L2QueueBuffer: frameSpec is NULL\n");
        return RC_ERROR;
    }
    if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        buf.m.planes = planes;
    }

    MakeInqueueBuffer(buf, frameSpec);

#ifdef V4L2_EMULATOR
    RetCode rc = SetAndPushBuffer(fd, frameSpec, buf);
    if (rc == RC_ERROR) {
        return RC_ERROR;
    }
#else
    std::lock_guard<std::mutex> l(bufferLock_);
    int rc = ioctl(fd, VIDIOC_QBUF, &buf);
    if (rc < 0) {
        CAMERA_LOGE("ioctl VIDIOC_QBUF failed: %{public}s\n", strerror(errno));
        return RC_ERROR;
    }
#endif

    auto itr = queueBuffers_.find(fd);
    if (itr != queueBuffers_.end()) {
        itr->second[buf.index] = frameSpec;
        CAMERA_LOGI("insert frameMap fd = %{public}d buf.index = %{public}d\n", fd, buf.index);
    } else {
        FrameMap frameMap;
        frameMap.insert(std::make_pair(buf.index, frameSpec));
        queueBuffers_.insert(std::make_pair(fd, frameMap));
        CAMERA_LOGI("insert fd = %{public}d buf.index = %{public}d\n", fd, buf.index);
    }

    return RC_OK;
}

void HosV4L2Buffers::MakeInqueueBuffer(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec)
{
    CAMERA_LOGI("HosV4L2Buffers::MakeInqueueBuffer in.");

    buf.index = (uint32_t)frameSpec->buffer_->GetIndex();
    buf.type = bufferType_;
    buf.memory = memoryType_;

    switch (memoryType_) {
        case V4L2_MEMORY_MMAP:
            SetMmapInqueueBuffer(buf, frameSpec);
            break;
        case V4L2_MEMORY_USERPTR:
            SetInqueueBuffer(buf, frameSpec);
            break;
        case V4L2_MEMORY_OVERLAY:
            break;
        case V4L2_MEMORY_DMABUF:
            SetDmaInqueueBuffer(buf, frameSpec);
            break;
        default:
            CAMERA_LOGE("It can not be happening - incorrect memoryType\n");
            return;
    }
    return;
}

void HosV4L2Buffers::SetInqueueBuffer(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec)
{
    CAMERA_LOGD("HosV4L2Buffers::SetInqueueBuffer in.");
    if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        buf.m.planes[0].length = frameSpec->buffer_->GetSize();
        buf.m.planes[0].m.userptr = (unsigned long)frameSpec->buffer_->GetVirAddress();
        buf.length = 1;
    } else if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
        buf.length = frameSpec->buffer_->GetSize();
        buf.m.userptr = (unsigned long)frameSpec->buffer_->GetVirAddress();
    }
    return;
}

void HosV4L2Buffers::SetMmapInqueueBuffer(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec)
{
    CAMERA_LOGD("HosV4L2Buffers::SetMmapInqueueBuffer in.");
    if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        buf.m.planes[0].length = adapterBufferMap_[buf.index].length;
        buf.m.planes[0].m.mem_offset = adapterBufferMap_[buf.index].offset;
        buf.length = 1;
    } else if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
        buf.length = adapterBufferMap_[buf.index].length;
        buf.m.offset = adapterBufferMap_[buf.index].offset;
    }
    return;
}

void HosV4L2Buffers::SetDmaInqueueBuffer(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec)
{
    CAMERA_LOGD("HosV4L2Buffers::SetDmaInqueueBuffer in.");
    if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        buf.length = 1;
        buf.m.planes[0].length = adapterBufferMap_[buf.index].length;
        buf.m.planes[0].m.fd = adapterBufferMap_[buf.index].dmafd;
    } else if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
        buf.length = adapterBufferMap_[buf.index].length;
        buf.m.fd = adapterBufferMap_[buf.index].dmafd;
    }
    return;
}

RetCode HosV4L2Buffers::V4L2DequeueBuffer(int fd)
{
    struct v4l2_buffer buf = {};
    struct v4l2_plane planes[1] = {};
    buf.type = bufferType_;
    buf.memory = memoryType_;
    if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        buf.m.planes = planes;
        buf.length = 1;
    }
#ifdef V4L2_EMULATOR
    constexpr int SleepTimeUs = 10000;
    usleep(SleepTimeUs); // 10ms delay
    int buf_cnt = 0;
    int err = ioctl(fd, IOC_REQUEST_BUFFER, &buf_cnt);
    if (err < 0) {
        CAMERA_LOGE("IOC_REQUEST_BUFFER failed: %d\n", err);
        return RC_ERROR;
    }
 
    availableBuffers_ += buf_cnt;
    if (availableBuffers_ <= 0) {
        // host did not finish drawing the previous frame:
        // either the host is very busy, or the host camera framerate is low
        CAMERA_LOGD("no buffer to display.");
        return RC_OK;
    }

    availableBuffers_ -= 1;
    if (queuedBuffers_.size() == 0) {
        CAMERA_LOGE("error! received buffer not in queued buffer list!");
        return RC_ERROR;
    } else {
        std::lock_guard<std::mutex> l(bufferLock_);
        buf.index = (uint32_t)queuedBuffers_.front();
        queuedBuffers_.pop();
    }
    CAMERA_LOGI("express_camera request buffer idx %d queue size %lu buf_cnt %d",
        buf.index, queuedBuffers_.size(), buf_cnt);
#else
    CAMERA_LOGI("ioctl VIDIOC_DQBUF fd: %{public}d\n", fd);
    int rc = ioctl(fd, VIDIOC_DQBUF, &buf);
    if (rc < 0) {
        CAMERA_LOGE("ioctl VIDIOC_DQBUF failed: %{public}s\n", strerror(errno));
        return RC_ERROR;
    }
#endif
    if (memoryType_ == V4L2_MEMORY_MMAP || memoryType_ == V4L2_MEMORY_DMABUF) {
        if (adapterBufferMap_[buf.index].userBufPtr && adapterBufferMap_[buf.index].start) {
            if (adapterBufferMap_[buf.index].length > buffLong_) {
                CAMERA_LOGE("ERROR: BufferMap length error");
                return RC_ERROR;
            }
            (void)memcpy_s(adapterBufferMap_[buf.index].userBufPtr, adapterBufferMap_[buf.index].length,
                adapterBufferMap_[buf.index].start, adapterBufferMap_[buf.index].length);
        }
    }
    std::lock_guard<std::mutex> l(bufferLock_);
    auto IterMap = queueBuffers_.find(fd);
    if (IterMap == queueBuffers_.end()) {
        CAMERA_LOGE("std::map queueBuffers_ no fd\n");
        return RC_ERROR;
    }
    auto& bufferMap = IterMap->second;
    auto Iter = bufferMap.find(buf.index);
    if (Iter == bufferMap.end()) {
        CAMERA_LOGE("V4L2DequeueBuffer buf.index == %{public}d is not find in FrameMap\n", buf.index);
        return RC_ERROR;
    }
    if (dequeueBuffer_ == nullptr) {
        CAMERA_LOGE("V4L2DequeueBuffer buf.index == %{public}d no callback\n", buf.index);
        bufferMap.erase(Iter);
        return RC_ERROR;
    }
    CameraDumper& dumper = CameraDumper::GetInstance();
    dumper.DumpBuffer("DQBuffer", ENABLE_DQ_BUFFER_DUMP, Iter->second->buffer_);
    dequeueBuffer_(Iter->second);
    bufferMap.erase(Iter);
    return RC_OK;
}

RetCode HosV4L2Buffers::V4L2AllocBuffer(int fd, const std::shared_ptr<FrameSpec>& frameSpec)
{
    struct v4l2_buffer buf = {};
    struct v4l2_plane planes[1] = {};
    CAMERA_LOGI("V4L2AllocBuffer enter fd %{public}d\n", fd);

    if (frameSpec == nullptr) {
        CAMERA_LOGE("V4L2AllocBuffer frameSpec is NULL\n");
        return RC_ERROR;
    }

    buf.type = bufferType_;
    buf.memory = memoryType_;
    buf.index = (uint32_t)frameSpec->buffer_->GetIndex();
    if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        buf.m.planes = planes;
        buf.length = 1;
    }
#ifndef V4L2_EMULATOR
    if (ioctl(fd, VIDIOC_QUERYBUF, &buf) < 0) {
        CAMERA_LOGE("error: ioctl VIDIOC_QUERYBUF failed: %{public}s\n", strerror(errno));
        return RC_ERROR;
    }
#endif
    CAMERA_LOGI("buf.length = %{public}d frameSpec->buffer_->GetSize() = %{public}d buf.index = %{public}d\n",
        buf.length, frameSpec->buffer_->GetSize(), buf.index);
    if (buf.length > frameSpec->buffer_->GetSize()) {
        CAMERA_LOGE("RROR:user buff < V4L2 buf.length\n");
        return RC_ERROR;
    }
    buffLong_ = frameSpec->buffer_->GetSize();
    if (memoryType_ == V4L2_MEMORY_MMAP || memoryType_ == V4L2_MEMORY_DMABUF) {
        return SetAdapterBuffer(fd, buf, frameSpec);
    }
    return RC_OK;
}

RetCode HosV4L2Buffers::SetAdapterBuffer(int fd, struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec)
{
    CAMERA_LOGI("HosV4L2Buffers::SetAdapterBuffer in.");
    int32_t ret = 0;
    int32_t index = (uint32_t)frameSpec->buffer_->GetIndex();

    auto findIf = adapterBufferMap_.find(index);
    if (findIf == adapterBufferMap_.end()) {
        AdapterBuffer adapterBuffer = {nullptr, 0, 0, nullptr, 0, 0};
        adapterBufferMap_.insert(std::make_pair(index, adapterBuffer));
    }

    adapterBufferMap_[index].userBufPtr = frameSpec->buffer_->GetVirAddress();

    switch (memoryType_) {
        case V4L2_MEMORY_MMAP:
            CAMERA_LOGI("HosV4L2Buffers::SetAdapterBuffer V4L2_MEMORY_MMAP.");
            if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
                adapterBufferMap_[index].length = buf.m.planes[0].length;
                adapterBufferMap_[index].offset = buf.m.planes[0].m.mem_offset;
            } else if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
                adapterBufferMap_[index].length = buf.length;
                adapterBufferMap_[index].offset = buf.m.offset;
            }
            if (adapterBufferMap_[buf.index].start == nullptr) {
                adapterBufferMap_[buf.index].start = mmap(NULL, adapterBufferMap_[buf.index].length,
                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, adapterBufferMap_[buf.index].offset);
                if (adapterBufferMap_[buf.index].start  == MAP_FAILED) {
                    CAMERA_LOGE("SetAdapterBuffer mmap failed.");
                    return RC_ERROR;
                }
            }
            break;
        case V4L2_MEMORY_DMABUF:
            CAMERA_LOGI("HosV4L2Buffers::SetAdapterBuffer V4L2_MEMORY_DMABUF.");
            if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
                adapterBufferMap_[index].length = buf.m.planes[0].length;
            } else if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
                adapterBufferMap_[index].length = buf.length;
            }
            ret = SetDmabufOn(buf, frameSpec);
            if (ret < 0) {
                CAMERA_LOGE("SetDmabufOn err.\n");
                return RC_ERROR;
            }
            break;
        default:
            CAMERA_LOGE("Incorrect memoryType\n");
            return RC_ERROR;
    }
    CAMERA_LOGI("HosV4L2Buffers::SetAdapterBuffer out.");
    return RC_OK;
}

RetCode HosV4L2Buffers::SetDmabufOn(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec)
{
    CAMERA_LOGI("HosV4L2Buffers::SetDmabufOn in.");
    int32_t ret = 0;
    int32_t index = (uint32_t)frameSpec->buffer_->GetIndex();

    int heapfd = open(DMA_BUF_FILE_NAME.c_str(), O_RDONLY | O_CLOEXEC);
    if (heapfd < 0) {
        CAMERA_LOGE("heapfd open err.\n");
        return RC_ERROR;
    }
    struct dma_heap_allocation_data data = {
        .len = buf.m.planes[0].length,
        .fd_flags = O_RDWR | O_CLOEXEC,
    };
    ret = ioctl(heapfd, DMA_HEAP_IOCTL_ALLOC, &data);
    if (ret < 0) {
        close(heapfd);
        CAMERA_LOGE("DMA_HEAP_IOCTL_ALLOC err.\n");
        return RC_ERROR;
    }
    adapterBufferMap_[index].heapfd = heapfd;
    adapterBufferMap_[index].dmafd = data.fd;
    adapterBufferMap_[index].start = mmap(NULL, adapterBufferMap_[index].length, PROT_READ | PROT_WRITE,
        MAP_SHARED, adapterBufferMap_[index].dmafd, 0);
    if (adapterBufferMap_[index].start == MAP_FAILED) {
        close(adapterBufferMap_[index].heapfd);
        CAMERA_LOGE("SetDmabufOn dmabuf mmap err.\n");
        return RC_ERROR;
    }
    struct dma_buf_sync sync = {0};
    sync.flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_RW;
    ret = ioctl(adapterBufferMap_[buf.index].dmafd, DMA_BUF_IOCTL_SYNC, &sync);
    if (ret < 0) {
        if (munmap(adapterBufferMap_[index].start, adapterBufferMap_[index].length) < 0) {
            CAMERA_LOGE("SetDmabufOn munmap err.\n");
        }
        close(adapterBufferMap_[index].dmafd);
        close(adapterBufferMap_[index].heapfd);
        CAMERA_LOGE("DMA_BUF_IOCTL_SYNC err.\n");
        return RC_ERROR;
    }
    CAMERA_LOGI("HosV4L2Buffers::SetDmabufOn out.");
    return RC_OK;
}

RetCode HosV4L2Buffers::V4L2ReleaseBuffers(int fd)
{
    CAMERA_LOGI("HosV4L2Buffers::V4L2ReleaseBuffers in fd %{public}d\n", fd);

    std::lock_guard<std::mutex> l(bufferLock_);
    queueBuffers_.erase(fd);

    for (auto &mem : adapterBufferMap_) {
        if (mem.second.dmafd > 0) {
            struct dma_buf_sync sync = {0};
            sync.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_RW;
            int ret = ioctl(mem.second.dmafd, DMA_BUF_IOCTL_SYNC, &sync);
            if (ret < 0) {
                return RC_ERROR;
            }
        }
        if (mem.second.start) {
            if (munmap(mem.second.start, mem.second.length) < 0) {
                return RC_ERROR;
            }
        }
        if (mem.second.dmafd > 0) {
            close(mem.second.dmafd);
        }
        if (mem.second.heapfd > 0) {
            close(mem.second.heapfd);
        }
    }
    adapterBufferMap_.clear();
    return V4L2ReqBuffers(fd, 0);
}

void HosV4L2Buffers::SetV4L2BuffersCallback(BufCallback cb)
{
    CAMERA_LOGD("SetV4L2BuffersCallback::SetCallback OK.");
    dequeueBuffer_ = cb;
}

RetCode HosV4L2Buffers::Flush(int fd)
{
    CAMERA_LOGD("HosV4L2Buffers::Flush\n");
    return RC_OK;
}
} // namespace OHOS::Camera
