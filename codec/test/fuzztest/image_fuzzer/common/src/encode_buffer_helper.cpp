/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/mman.h>
#include <securec.h>
#include "ashmem.h"
#include "encode_buffer_helper.h"

namespace OHOS::VDI::HEIF {
using namespace OHOS::HDI::Codec::Image::V2_0;
using namespace OHOS::HDI::Display::Buffer::V1_2;
using namespace OHOS::HDI::Display::Composer::V1_2;
using namespace std;

uint32_t ToUint32(const uint8_t* ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    return (ptr[0] << 24) | (ptr[1] << 16) |  // 24:bit offset, 16: bit offset, 1:byte offset
           (ptr[2] << 8) | (ptr[3]);          // 8:bit offset, 2: byte offset, 3:byte offset
}

EncodeBufferHelper::EncodeBufferHelper()
{
    bufferMgr_ = OHOS::HDI::Display::Buffer::V1_2::IDisplayBuffer::Get();
}

EncodeBufferHelper::~EncodeBufferHelper()
{
    bufferMgr_ = nullptr;
    for (auto iter = allocatedFd_.begin(); iter != allocatedFd_.end(); ++iter) {
        close(*iter);
    }
    allocatedFd_.clear();
}


bool EncodeBufferHelper::InitialRgbaData(BufferHandle* handle, PixelFileInfo& pixelInfo, uint8_t* data, size_t &size)
{
    char* dst = reinterpret_cast<char*>(handle->virAddr);
    static constexpr uint32_t BYTES_PER_PIXEL_RBGA = 4;
    errno_t ret = EOK;
    uint8_t* dataEnd = data + size -1;
    if (dataEnd < data + pixelInfo.alignedWidth * BYTES_PER_PIXEL_RBGA * pixelInfo.displayHeight) {
        HDF_LOGI("Input Data length Not Enough");
        return false;
    }
    for (uint32_t i = 0; i < pixelInfo.displayHeight; i++) {
        ret = memcpy_s(dst, pixelInfo.alignedWidth * BYTES_PER_PIXEL_RBGA, data,
                       pixelInfo.alignedWidth * BYTES_PER_PIXEL_RBGA);
        dst += handle->stride;
    }
    data += pixelInfo.alignedWidth * BYTES_PER_PIXEL_RBGA * pixelInfo.displayHeight;
    size -= pixelInfo.alignedWidth * BYTES_PER_PIXEL_RBGA * pixelInfo.displayHeight;
    return (ret == EOK);
}

sptr<NativeBuffer> EncodeBufferHelper::CreateImgBuffer(uint8_t* data, size_t &size)
{
    PixelFileInfo pixelInfo;
    uint8_t* dataEnd = data + size -1;
    if (dataEnd < data + sizeof(pixelInfo.displayWidth)) {
        return nullptr;
    }
    static constexpr int SHIFT_CNT = 22;
    pixelInfo.displayWidth = (ToUint32(data) >> SHIFT_CNT); //Max 1024
    pixelInfo.alignedWidth = pixelInfo.displayWidth;
    data += sizeof(pixelInfo.displayWidth);
    size -= sizeof(pixelInfo.displayWidth);

    if (dataEnd < data + sizeof(pixelInfo.displayHeight)) {
        return nullptr;
    }
    pixelInfo.displayHeight = (ToUint32(data) >> SHIFT_CNT);
    pixelInfo.alignedHeight = pixelInfo.displayHeight;
    data += sizeof(pixelInfo.displayHeight);
    size -= sizeof(pixelInfo.displayHeight);

    pixelInfo.pixFmt = OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_RGBA_8888;
    uint64_t usage = OHOS::HDI::Display::Composer::V1_2::HBM_USE_CPU_READ |
                     OHOS::HDI::Display::Composer::V1_2::HBM_USE_CPU_WRITE |
                     OHOS::HDI::Display::Composer::V1_2::HBM_USE_MEM_DMA;
    AllocInfo alloc = {
        .width = pixelInfo.displayWidth,
        .height = pixelInfo.displayHeight,
        .usage =  usage,
        .format = pixelInfo.pixFmt
    };

    BufferHandle *handle = nullptr;
    int32_t ret = bufferMgr_->AllocMem(alloc, handle);
    IF_TRUE_RETURN_VAL_WITH_MSG(ret != HDF_SUCCESS, nullptr,
                                "failed to alloc output buffer, err [%{public}d] !", ret);
    sptr<NativeBuffer> imgBuffer = new NativeBuffer();
    imgBuffer->SetBufferHandle(handle, true);
    bufferMgr_->Mmap(*handle);

    HDF_LOGI("Fill Image RGB Data");
    bool flag = InitialRgbaData(handle, pixelInfo, data, size);

    (void)bufferMgr_->Unmap(*handle);
    if (!flag) {
        return nullptr;
    }
    HDF_LOGI("Fill Image RGB Data Succesfully");
    return imgBuffer;
}

SharedBuffer EncodeBufferHelper::CreateSharedBuffer(uint8_t* data, size_t &size)
{
    SharedBuffer buffer = {
        .fd = -1,
        .filledLen = 0,
        .capacity = 0
    };

    uint8_t* dataEnd = data + size - 1;
    if (dataEnd < data + sizeof(uint8_t)) {
        return buffer;
    }
    uint8_t totalSize = *data;
    data += sizeof(totalSize);
    size -= sizeof(totalSize);
    int fd = AshmemCreate("ForMetaData", (size_t)totalSize);
    IF_TRUE_RETURN_VAL_WITH_MSG(fd < 0, buffer, "cannot create ashmem for meta data");
    void *addr = mmap(nullptr, (size_t)totalSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == nullptr) {
        HDF_LOGE("failed to map addr for meta buffer");
        close(fd);
        return buffer;
    }
    if (dataEnd < data + totalSize) {
        close(fd);
        return buffer;
    }
    errno_t ret = EOK;
    ret = memcpy_s(reinterpret_cast<char*>(addr), totalSize, data, totalSize);
    if (ret != EOK) {
        close(fd);
        return buffer;
    }
    data += totalSize;
    size -= totalSize;
    if (munmap(addr, totalSize) != 0) {
        HDF_LOGW("failed to unmap addr for meta buffer");
    }
    buffer.fd = fd;
    buffer.filledLen = static_cast<uint32_t>(totalSize);
    buffer.capacity = static_cast<uint32_t>(AshmemGetSize(fd));
    allocatedFd_.insert(fd);
    return buffer;
}
}