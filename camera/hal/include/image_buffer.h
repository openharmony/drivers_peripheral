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

#ifndef HOS_CAMERA_IMAGE_BUFFER_H
#define HOS_CAMERA_IMAGE_BUFFER_H

#include "ibuffer.h"
#include <mutex>

namespace OHOS::Camera {
class ImageBuffer : public IBuffer {
public:
    ImageBuffer();
    explicit ImageBuffer(const int32_t source);
    ImageBuffer(const int32_t source,
                const uint32_t width,
                const uint32_t height,
                const uint64_t usage,
                const uint32_t format);

    virtual ~ImageBuffer();

    int32_t GetIndex() const override;
    uint32_t GetWidth() const override;
    uint32_t GetHeight() const override;
    uint32_t GetStride() const override;
    int32_t GetFormat() const override;
    uint32_t GetSize() const override;
    uint64_t GetUsage() const override;
    void* GetVirAddress() const override;
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
    void SetVirAddress(const void* addr) override;
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
    bool operator==(const IBuffer& u) override;

private:
    int32_t index_ = -1;
    uint32_t width_ = 0;
    uint32_t height_ = 0;
    uint32_t stride_ = 0;
    uint32_t format_ = CAMERA_FORMAT_INVALID;
    uint32_t size_ = 0;
    uint64_t usage_ = 0;
    void* virAddr_ = nullptr;
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
} // namespace OHOS::Camera
#endif

