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

#include "gralloc_buffer_allocator.h"
#include "display_buffer_hwi_impl.h"
#include "buffer_adapter.h"
#include "image_buffer.h"

namespace OHOS::Camera {
using namespace OHOS::Model::Buffer;
using namespace OHOS::HDI::Display::Buffer::V1_0;
GrallocBufferAllocator::GrallocBufferAllocator() {}

GrallocBufferAllocator::~GrallocBufferAllocator()
{
}

RetCode GrallocBufferAllocator::Init()
{
    if (dispBufferHwi_ != nullptr) {
        CAMERA_LOGD("init success.");
        return RC_OK;
    }
    dispBufferHwi_.reset(new DisplayBufferHwiImpl());
    if (dispBufferHwi_ == nullptr) {
        return RC_ERROR;
    }

    return RC_OK;
}

std::shared_ptr<IBuffer> GrallocBufferAllocator::AllocBuffer(const uint32_t width,
                                                             const uint32_t height,
                                                             const uint64_t cameraUsage,
                                                             const uint32_t cameraFormat)
{
    if (dispBufferHwi_ == nullptr) {
        CAMERA_LOGE("dispBufferHwi_ is null");
        return nullptr;
    }

    PixelFormat format = BufferAdapter::CameraFormatToPixelFormat(cameraFormat);
    uint64_t usage = BufferAdapter::CameraUsageToGrallocUsage(cameraUsage);
    CAMERA_LOGI("buffer info : w[%{public}u], h[%{public}u], u[%{public}llu], f[%{public}u]",
        width, height, usage, format);

    BufferHandle* handle = nullptr;
    AllocInfo info = {
        .width = width,
        .height = height,
        .usage =  usage,
        .format = format
    };
    int32_t ret = dispBufferHwi_->AllocMem(info, handle);
    if (ret != DISPLAY_SUCCESS) {
        CAMERA_LOGE("Alloc graphic buffer failed, ret = %{public}d", ret);
        return nullptr;
    }

    std::shared_ptr<IBuffer> buffer = std::make_shared<ImageBuffer>(sourceType_);
    if (buffer != nullptr) {
        GrallocBufferToCameraBuffer(*handle, buffer);
        CAMERA_LOGD("Alloc graphic buffer success");
    }
    return buffer;
}

RetCode GrallocBufferAllocator::FreeBuffer(std::shared_ptr<IBuffer>& buffer)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(dispBufferHwi_, RC_ERROR);
    CHECK_IF_PTR_NULL_RETURN_VALUE(buffer, RC_ERROR);
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(buffer->GetSourceType(), sourceType_, RC_ERROR);

    BufferHandle* handle = AllocateBufferHandle(0, 0);
    CHECK_IF_PTR_NULL_RETURN_VALUE(handle, RC_ERROR);

    CameraBufferToGrallocBuffer(buffer, *handle);
    dispBufferHwi_->FreeMem(*handle);
    buffer->Free();

    if (handle != nullptr) {
        FreeBufferHandle(handle);
    }
    CAMERA_LOGD("Free buffer success.");

    return RC_OK;
}

RetCode GrallocBufferAllocator::MapBuffer(std::shared_ptr<IBuffer>& buffer)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(dispBufferHwi_, RC_ERROR);
    CHECK_IF_PTR_NULL_RETURN_VALUE(buffer, RC_ERROR);
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(buffer->GetSourceType(), sourceType_, RC_ERROR);

    BufferHandle* bufHandle = AllocateBufferHandle(0, 0);
    CHECK_IF_PTR_NULL_RETURN_VALUE(bufHandle, RC_ERROR);

    CameraBufferToGrallocBuffer(buffer, *bufHandle);
    void* virAddr = dispBufferHwi_->Mmap(*bufHandle);
    if (virAddr == nullptr) {
        CAMERA_LOGE("Map Buffer failed.");
        FreeBufferHandle(bufHandle);
        return RC_ERROR;
    }
    buffer->SetVirAddress(virAddr);

    if (bufHandle != nullptr) {
        FreeBufferHandle(bufHandle);
    }
    CAMERA_LOGD("Map buffer success.");

    return RC_OK;
}

RetCode GrallocBufferAllocator::UnmapBuffer(std::shared_ptr<IBuffer>& buffer)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(dispBufferHwi_, RC_ERROR);
    CHECK_IF_PTR_NULL_RETURN_VALUE(buffer, RC_ERROR);
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(buffer->GetSourceType(), sourceType_, RC_ERROR);

    BufferHandle* handle = AllocateBufferHandle(0, 0);
    CHECK_IF_PTR_NULL_RETURN_VALUE(handle, RC_ERROR);

    CameraBufferToGrallocBuffer(buffer, *handle);
    if (dispBufferHwi_->Unmap(*handle) != DISPLAY_SUCCESS) {
        CAMERA_LOGE("Unmap buffer failed.");
        FreeBufferHandle(handle);
        return RC_ERROR;
    }
    void* virAddr = nullptr;
    buffer->SetVirAddress(virAddr);

    if (handle != nullptr) {
        FreeBufferHandle(handle);
    }
    CAMERA_LOGD("Unmap buffer success.");

    return RC_OK;
}

RetCode GrallocBufferAllocator::FlushCache(std::shared_ptr<IBuffer>& buffer)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(dispBufferHwi_, RC_ERROR);
    CHECK_IF_PTR_NULL_RETURN_VALUE(buffer, RC_ERROR);
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(buffer->GetSourceType(), sourceType_, RC_ERROR);

    BufferHandle* handle = AllocateBufferHandle(0, 0);
    CHECK_IF_PTR_NULL_RETURN_VALUE(handle, RC_ERROR);

    CameraBufferToGrallocBuffer(buffer, *handle);
    if (dispBufferHwi_->FlushCache(*handle) != DISPLAY_SUCCESS) {
        CAMERA_LOGE("Flush cache buffer failed.");
        FreeBufferHandle(handle);
        return RC_ERROR;
    }

    if (handle != nullptr) {
        FreeBufferHandle(handle);
    }
    return RC_OK;
}

RetCode GrallocBufferAllocator::InvalidateCache(std::shared_ptr<IBuffer>& buffer)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(dispBufferHwi_, RC_ERROR);
    CHECK_IF_PTR_NULL_RETURN_VALUE(buffer, RC_ERROR);
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(buffer->GetSourceType(), sourceType_, RC_ERROR);

    BufferHandle* invalHandle = AllocateBufferHandle(0, 0);
    CHECK_IF_PTR_NULL_RETURN_VALUE(invalHandle, RC_ERROR);

    CameraBufferToGrallocBuffer(buffer, *invalHandle);
    if (dispBufferHwi_->InvalidateCache(*invalHandle) != DISPLAY_SUCCESS) {
        CAMERA_LOGE("Invalidate cache buffer failed.");
        FreeBufferHandle(invalHandle);
        return RC_ERROR;
    }

    if (invalHandle != nullptr) {
        FreeBufferHandle(invalHandle);
    }
    return RC_OK;
}

void GrallocBufferAllocator::CameraBufferToGrallocBuffer(const std::shared_ptr<IBuffer>& src, BufferHandle& dest) const
{
    if (src == nullptr || (&dest) == nullptr) {
        return;
    }

    dest.phyAddr = src->GetPhyAddress();
    dest.fd = src->GetFileDescriptor();
    dest.stride = static_cast<int32_t>(src->GetStride());
    dest.width = static_cast<int32_t>(src->GetWidth());
    dest.height = static_cast<int32_t>(src->GetHeight());
    dest.format = BufferAdapter::CameraFormatToPixelFormat(src->GetFormat());
    dest.usage =
        static_cast<uint64_t>(BufferAdapter::CameraUsageToGrallocUsage(src->GetUsage()));
    dest.size = static_cast<int32_t>(src->GetSize());
    dest.virAddr = src->GetVirAddress();

    return;
}

void GrallocBufferAllocator::GrallocBufferToCameraBuffer(const BufferHandle& src, std::shared_ptr<IBuffer>& dest) const
{
    if ((&src) == nullptr || dest == nullptr) {
        return;
    }

    dest->SetPhyAddress(src.phyAddr);
    dest->SetFileDescriptor(src.fd);
    dest->SetStride(static_cast<uint32_t>(src.stride));
    dest->SetWidth(static_cast<uint32_t>(src.width));
    dest->SetHeight(static_cast<uint32_t>(src.height));
    dest->SetFormat(BufferAdapter::PixelFormatToCameraFormat(static_cast<PixelFormat>(src.format)));
    dest->SetUsage(BufferAdapter::GrallocUsageToCameraUsage(src.usage));
    dest->SetSize(static_cast<uint32_t>(src.size));
    dest->SetVirAddress(src.virAddr);

    return;
}

REGISTER_BUFFER_ALLOCATOR(GrallocBufferAllocator, CAMERA_BUFFER_SOURCE_TYPE_GRALLOC);
} // namespace OHOS::Camera
