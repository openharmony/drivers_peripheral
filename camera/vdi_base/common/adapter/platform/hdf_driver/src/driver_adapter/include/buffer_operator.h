/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef BUFFER_OPERATOR_H
#define BUFFER_OPERATOR_H

#include "ibuffer.h"

namespace OHOS::Camera {
// using namespace OHOS::Camera;

class MyBuffer : public IBuffer {
public:
    MyBuffer();
    virtual ~MyBuffer();

    int32_t GetIndex() const override;
    uint32_t GetWidth() const override;
    uint32_t GetHeight() const override;
    uint32_t GetStride() const override;
    int32_t GetFormat() const override;
    uint32_t GetSize() const override;
    uint64_t GetUsage() const override;
    void *GetVirAddress() const override;
    uint64_t GetPhyAddress() const override;
    int32_t GetFileDescriptor() const override;
    int32_t GetSourceType() const override;
    uint64_t GetTimestamp() const override;
    uint64_t GetFrameNumber() const override;
    int64_t GetPoolId() const override;
    int32_t GetCaptureId() const override;
    CameraBufferStatus GetBufferStatus() const override;
    int32_t GetSequenceId() const override;
    int32_t GetFenceId() const override;
    EsFrameInfo GetEsFrameInfo() const override;
    int32_t GetEncodeType() const override;
    int32_t GetStreamId() const override;

    void SetIndex(const int32_t index) override;
    void SetWidth(const uint32_t width) override;
    void SetHeight(const uint32_t height) override;
    void SetStride(const uint32_t stride) override;
    void SetFormat(const int32_t format) override;
    void SetSize(const uint32_t size) override;
    void SetUsage(const uint64_t usage) override;
    void SetVirAddress(const void *addr) override;
    void SetPhyAddress(const uint64_t addr) override;
    void SetFileDescriptor(const int32_t fd) override;
    void SetTimestamp(const uint64_t timestamp) override;
    void SetFrameNumber(const uint64_t frameNumber) override;
    void SetPoolId(const int64_t id) override;
    void SetCaptureId(const int32_t id) override;
    void SetBufferStatus(const CameraBufferStatus flag) override;
    void SetSequenceId(const int32_t sequence) override;
    void SetFenceId(const int32_t fence) override;
    void SetEncodeType(const int32_t type) override;
    void SetEsFrameSize(const int32_t frameSize) override;
    void SetEsTimestamp(const int64_t timeStamp) override;
    void SetEsKeyFrame(const int32_t isKey) override;
    void SetEsFrameNum(const int32_t frameNum) override;
    void SetStreamId(const int32_t streamId) override;

    void Free() override;
    bool operator==(const IBuffer &u) override;

private:
    int32_t index_ = -1;
    uint32_t width_ = 0;
    uint32_t height_ = 0;
    uint32_t stride_ = 0;
    uint32_t format_ = CAMERA_FORMAT_INVALID;
    uint32_t size_ = 0;
    uint64_t usage_ = 0;
    void *virAddr_ = nullptr;
    uint64_t phyAddr_ = 0;
    int32_t fd_ = -1;
    int32_t sourceType_ = CAMERA_BUFFER_SOURCE_TYPE_NONE;
    uint64_t frameNumber_ = 0;
    uint64_t timeStamp_ = 0;
    int64_t poolId_ = -1;
    int32_t captureId_ = -1;
    CameraBufferStatus status_ = CAMERA_BUFFER_STATUS_OK;
    int32_t sequenceId_ = -1;
    int32_t fenceId_ = -1;
    int32_t encodeType_ = 0;
    EsFrameInfo esInfo_ = {-1, -1, -1, -1, -1};
    int32_t streamId_ = -1;
    std::mutex l_;
};

MyBuffer::MyBuffer() {}

MyBuffer::~MyBuffer()
{
    Free();
}

int32_t MyBuffer::GetIndex() const
{
    return index_;
}

uint32_t MyBuffer::GetWidth() const
{
    return width_;
}

uint32_t MyBuffer::GetHeight() const
{
    return height_;
}

uint32_t MyBuffer::GetStride() const
{
    return stride_;
}

int32_t MyBuffer::GetFormat() const
{
    return format_;
}

uint32_t MyBuffer::GetSize() const
{
    return size_;
}

uint64_t MyBuffer::GetUsage() const
{
    return usage_;
}

void *MyBuffer::GetVirAddress() const
{
    return virAddr_;
}

uint64_t MyBuffer::GetPhyAddress() const
{
    return phyAddr_;
}

int32_t MyBuffer::GetFileDescriptor() const
{
    return fd_;
}

int32_t MyBuffer::GetSourceType() const
{
    return sourceType_;
}

uint64_t MyBuffer::GetTimestamp() const
{
    return timeStamp_;
}

uint64_t MyBuffer::GetFrameNumber() const
{
    return frameNumber_;
}

int64_t MyBuffer::GetPoolId() const
{
    return poolId_;
}

int32_t MyBuffer::GetCaptureId() const
{
    return captureId_;
}

CameraBufferStatus MyBuffer::GetBufferStatus() const
{
    return status_;
}

int32_t MyBuffer::GetSequenceId() const
{
    return sequenceId_;
}

int32_t MyBuffer::GetFenceId() const
{
    return fenceId_;
}

EsFrameInfo MyBuffer::GetEsFrameInfo() const
{
    return esInfo_;
}

int32_t MyBuffer::GetEncodeType() const
{
    return encodeType_;
}

int32_t MyBuffer::GetStreamId() const
{
    return streamId_;
}

void MyBuffer::SetIndex(const int32_t index)
{
    std::lock_guard<std::mutex> l(l_);
    index_ = index;
    return;
}

void MyBuffer::SetWidth(const uint32_t width)
{
    std::lock_guard<std::mutex> l(l_);
    width_ = width;
    return;
}

void MyBuffer::SetHeight(const uint32_t height)
{
    std::lock_guard<std::mutex> l(l_);
    height_ = height;
    return;
}

void MyBuffer::SetStride(const uint32_t stride)
{
    std::lock_guard<std::mutex> l(l_);
    stride_ = stride;
    return;
}

void MyBuffer::SetFormat(const int32_t format)
{
    std::lock_guard<std::mutex> l(l_);
    format_ = format;
    return;
}

void MyBuffer::SetSize(const uint32_t size)
{
    std::lock_guard<std::mutex> l(l_);
    size_ = size;
    return;
}

void MyBuffer::SetUsage(const uint64_t usage)
{
    std::lock_guard<std::mutex> l(l_);
    usage_ = usage;
    return;
}

void MyBuffer::SetVirAddress(const void *addr)
{
    std::lock_guard<std::mutex> l(l_);
    virAddr_ = const_cast<void*>(addr);
    return;
}

void MyBuffer::SetPhyAddress(const uint64_t addr)
{
    std::lock_guard<std::mutex> l(l_);
    phyAddr_ = addr;
    return;
}

void MyBuffer::SetFileDescriptor(const int32_t fd)
{
    std::lock_guard<std::mutex> l(l_);
    fd_ = fd;
    return;
}

void MyBuffer::SetTimestamp(const uint64_t timeStamp)
{
    std::lock_guard<std::mutex> l(l_);
    timeStamp_ = timeStamp;
    return;
}

void MyBuffer::SetFrameNumber(const uint64_t frameNumber)
{
    std::lock_guard<std::mutex> l(l_);
    frameNumber_ = frameNumber;
    return;
}

void MyBuffer::SetPoolId(const int64_t id)
{
    std::lock_guard<std::mutex> l(l_);
    poolId_ = id;
    return;
}

void MyBuffer::SetCaptureId(const int32_t id)
{
    std::lock_guard<std::mutex> l(l_);
    captureId_ = id;
    return;
}

void MyBuffer::SetBufferStatus(const CameraBufferStatus flag)
{
    std::lock_guard<std::mutex> l(l_);
    status_ = flag;
    return;
}

void MyBuffer::SetSequenceId(const int32_t sequence)
{
    std::lock_guard<std::mutex> l(l_);
    sequenceId_ = sequence;
    return;
}

void MyBuffer::SetFenceId(const int32_t fence)
{
    std::lock_guard<std::mutex> l(l_);
    fenceId_ = fence;
    return;
}

void MyBuffer::SetEsFrameSize(const int32_t frameSize)
{
    std::lock_guard<std::mutex> l(l_);
    esInfo_.size = frameSize;
    return;
}

void MyBuffer::SetEsTimestamp(const int64_t timeStamp)
{
    std::lock_guard<std::mutex> l(l_);
    esInfo_.timestamp = timeStamp;
    return;
}

void MyBuffer::SetEsKeyFrame(const int32_t isKey)
{
    std::lock_guard<std::mutex> l(l_);
    esInfo_.isKey = isKey;
    return;
}

void MyBuffer::SetEsFrameNum(const int32_t frameNum)
{
    std::lock_guard<std::mutex> l(l_);
    esInfo_.frameNum = frameNum;
    return;
}

void MyBuffer::SetEncodeType(const int32_t type)
{
    std::lock_guard<std::mutex> l(l_);
    encodeType_ = type;
    return;
}

void MyBuffer::SetStreamId(const int32_t streamId)
{
    std::lock_guard<std::mutex> l(l_);
    streamId_ = streamId;
    return;
}

void MyBuffer::Free()
{
    index_ = -1;
    width_ = 0;
    height_ = 0;
    stride_ = 0;
    format_ = CAMERA_FORMAT_INVALID;
    size_ = 0;
    usage_ = 0;
    virAddr_ = nullptr;
    phyAddr_ = 0;
    fd_ = -1;

    return;
}

bool MyBuffer::operator==(const IBuffer &u)
{
    if (u.GetSourceType() != sourceType_) {
        return false;
    }

    if (u.GetPhyAddress() == 0 || phyAddr_ == 0) {
        return u.GetVirAddress() == virAddr_;
    }

    return u.GetPhyAddress() == phyAddr_;
}
}

#endif // BUFFER_OPERATOR_H