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

#include <sys/mman.h>
#include <unistd.h>
#include <linux/dma-heap.h>
#include <linux/dma-buf.h>
#ifndef V4L2_MAIN_TEST
#include "ibuffer.h"
#endif
#include "securec.h"
#include "v4l2_buffer.h"

namespace OHOS::Camera {
const std::string DMA_BUF_FILE_NAME = "/dev/dma_heap/system";
HosV4L2Buffers::HosV4L2Buffers(enum v4l2_memory memType, enum v4l2_buf_type bufferType)
    : memoryType_(memType), bufferType_(bufferType)
{
}

HosV4L2Buffers::~HosV4L2Buffers() {}

RetCode HosV4L2Buffers::V4L2ReqBuffers(int fd, int unsigned buffCont)
{
    struct v4l2_requestbuffers req = {};

    CAMERA_LOGD("V4L2ReqBuffers buffCont %{public}d\n", buffCont);

    req.count = buffCont;
    req.type = bufferType_;
    req.memory = memoryType_;

    if (ioctl(fd, VIDIOC_REQBUFS, &req) < 0) {
        CAMERA_LOGE("does not support memory mapping %{public}s\n", strerror(errno));
        return RC_ERROR;
    }

    if (req.count != buffCont) {
        CAMERA_LOGE("error Insufficient buffer memory on \n");

        req.count = 0;
        req.type = bufferType_;
        req.memory = memoryType_;
        if (ioctl(fd, VIDIOC_REQBUFS, &req) < 0) {
            CAMERA_LOGE("V4L2ReqBuffers does not release buffer	%s\n", strerror(errno));
            return RC_ERROR;
        }

        return RC_ERROR;
    }
    return RC_OK;
}

RetCode HosV4L2Buffers::V4L2QueueBuffer(int fd, const std::shared_ptr<FrameSpec>& frameSpec)
{
    struct v4l2_buffer buf = {};
    struct v4l2_plane planes[1] = {};

    if (frameSpec == nullptr) {
        CAMERA_LOGE("V4L2QueueBuffer: frameSpec is NULL\n");
        return RC_ERROR;
    }
    if (bufferType_ == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
        buf.m.planes = planes;
    }

    MakeInqueueBuffer(buf, frameSpec);

    std::lock_guard<std::mutex> l(bufferLock_);
    int rc = ioctl(fd, VIDIOC_QBUF, &buf);
    if (rc < 0) {
        CAMERA_LOGE("ioctl VIDIOC_QBUF failed: %s\n", strerror(errno));
        return RC_ERROR;
    }

    auto itr = queueBuffers_.find(fd);
    if (itr != queueBuffers_.end()) {
        itr->second[buf.index] = frameSpec;
        CAMERA_LOGD("insert frameMap fd = %{public}d buf.index = %{public}d\n", fd, buf.index);
    } else {
        FrameMap frameMap;
        frameMap.insert(std::make_pair(buf.index, frameSpec));
        queueBuffers_.insert(std::make_pair(fd, frameMap));
        CAMERA_LOGD("insert fd = %{public}d buf.index = %{public}d\n", fd, buf.index);
    }

    return RC_OK;
}

void HosV4L2Buffers::MakeInqueueBuffer(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec)
{
    CAMERA_LOGD("HosV4L2Buffers::MakeInqueueBuffer in.");

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
    int rc = ioctl(fd, VIDIOC_DQBUF, &buf);
    if (rc < 0) {
        CAMERA_LOGE("ioctl VIDIOC_DQBUF failed: %s\n", strerror(errno));
        return RC_ERROR;
    }

    if (memoryType_ == V4L2_MEMORY_MMAP || memoryType_ == V4L2_MEMORY_DMABUF) {
        if (adapterBufferMap_[buf.index].userBufPtr && adapterBufferMap_[buf.index].start) {
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
    dequeueBuffer_(Iter->second);
    bufferMap.erase(Iter);
    return RC_OK;
}

RetCode HosV4L2Buffers::V4L2AllocBuffer(int fd, const std::shared_ptr<FrameSpec>& frameSpec)
{
    struct v4l2_buffer buf = {};
    struct v4l2_plane planes[1] = {};
    CAMERA_LOGD("V4L2AllocBuffer\n");

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

    if (ioctl(fd, VIDIOC_QUERYBUF, &buf) < 0) {
        CAMERA_LOGE("error: ioctl VIDIOC_QUERYBUF failed: %{public}s\n", strerror(errno));
        return RC_ERROR;
    }

    CAMERA_LOGD("buf.length = %{public}d frameSpec->buffer_->GetSize() = %{public}d buf.index = %{public}d\n",
        buf.length, frameSpec->buffer_->GetSize(), buf.index);
    if (buf.length > frameSpec->buffer_->GetSize()) {
        CAMERA_LOGE("RROR:user buff < V4L2 buf.length\n");
        return RC_ERROR;
    }
    if (memoryType_ == V4L2_MEMORY_MMAP || memoryType_ == V4L2_MEMORY_DMABUF) {
        return SetAdapterBuffer(fd, buf, frameSpec);
    }
    return RC_OK;
}

RetCode HosV4L2Buffers::SetAdapterBuffer(int fd, struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec)
{
    CAMERA_LOGD("HosV4L2Buffers::SetAdapterBuffer in.");
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
            CAMERA_LOGD("HosV4L2Buffers::SetAdapterBuffer V4L2_MEMORY_DMABUF.");
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
    CAMERA_LOGD("HosV4L2Buffers::SetAdapterBuffer out.");
    return RC_OK;
}

RetCode HosV4L2Buffers::SetDmabufOn(struct v4l2_buffer &buf, const std::shared_ptr<FrameSpec>& frameSpec)
{
    CAMERA_LOGD("HosV4L2Buffers::SetDmabufOn in.");
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
    return RC_OK;
}

RetCode HosV4L2Buffers::V4L2ReleaseBuffers(int fd)
{
    CAMERA_LOGE("HosV4L2Buffers::V4L2ReleaseBuffers\n");

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

void HosV4L2Buffers::SetCallback(BufCallback cb)
{
    CAMERA_LOGD("HosV4L2Buffers::SetCallback OK.");
    dequeueBuffer_ = cb;
}

RetCode HosV4L2Buffers::Flush(int fd)
{
    CAMERA_LOGD("HosV4L2Buffers::Flush\n");
    return RC_OK;
}
} // namespace OHOS::Camera
