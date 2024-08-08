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
#include "ashmem.h"
#include "buffer_helper.h"

namespace OHOS::VDI::HEIF {
using namespace OHOS::HDI::Codec::Image::V2_0;
using namespace OHOS::HDI::Display::Buffer::V1_2;
using namespace OHOS::HDI::Display::Composer::V1_2;
using namespace std;

static size_t GetFileSizeInBytes(ifstream &ifs)
{
    ifs.seekg(0, ifstream::end);
    auto len = ifs.tellg();
    ifs.seekg(0, ifstream::beg);
    return static_cast<size_t>(len);
}

BufferHelper::BufferHelper()
{
    bufferMgr_ = OHOS::HDI::Display::Buffer::V1_2::IDisplayBuffer::Get();
}

BufferHelper::~BufferHelper()
{
    bufferMgr_ = nullptr;
    for (auto iter = allocatedFd_.begin(); iter != allocatedFd_.end(); ++iter) {
        close(*iter);
    }
    allocatedFd_.clear();
}

bool BufferHelper::ExtractPixelInfoFromFilePath(const string& filePath, PixelFileInfo& pixelInfo)
{
    size_t pos = filePath.find_last_of('/');
    IF_TRUE_RETURN_VAL(pos == string::npos, false);
    pos = filePath.find_first_of('[', pos);
    IF_TRUE_RETURN_VAL(pos == string::npos, false);
    int ret = sscanf_s(filePath.substr(pos).c_str(), "[%ux%u][%ux%u][fmt0x%x].yuv",
                       &pixelInfo.displayWidth, &pixelInfo.displayHeight,
                       &pixelInfo.alignedWidth, &pixelInfo.alignedHeight,
                       &pixelInfo.pixFmt);
    static constexpr int EXP_CNT = 5;
    IF_TRUE_RETURN_VAL(ret != EXP_CNT, false);
    HDF_LOGI("pixel info: display=[%{public}u x %{public}u], aligned=[%{public}u x %{public}u]",
             pixelInfo.displayWidth, pixelInfo.displayHeight, pixelInfo.alignedWidth, pixelInfo.alignedHeight);
    return true;
}

bool BufferHelper::CopyYuvData(BufferHandle *handle, ifstream &ifs, PixelFileInfo& pixelInfo)
{
    static constexpr uint32_t BYTES_PER_PIXEL_YUV = 1;
    // Y plane
    char* dst = reinterpret_cast<char*>(handle->virAddr);
    for (uint32_t i = 0; i < pixelInfo.displayHeight; i++) {
        ifs.read(dst, pixelInfo.alignedWidth * BYTES_PER_PIXEL_YUV);
        dst += handle->stride;
    }
    // skip aligned lines
    for (uint32_t i = 0; i < (pixelInfo.alignedHeight - pixelInfo.displayHeight); i++) {
        ifs.read(dst, pixelInfo.alignedWidth * BYTES_PER_PIXEL_YUV);
    }
    // UV plane
    ImageLayout layout;
    int32_t ret = bufferMgr_->GetImageLayout(*handle, layout);
    IF_TRUE_RETURN_VAL_WITH_MSG(ret != HDF_SUCCESS, false,
                                "failed to get uv start, err [%{public}d] !", ret);
    static constexpr int PLANE_U = 1;
    static constexpr int PLANE_V = 2;
    static constexpr uint32_t UV_SAMPLE_RATE = 2;
    uint64_t uvOffset = (pixelInfo.pixFmt == OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP) ?
                        layout.planes[PLANE_U].offset :
                        layout.planes[PLANE_V].offset;
    dst = reinterpret_cast<char*>(handle->virAddr) + uvOffset;
    for (uint32_t i = 0; i < pixelInfo.displayHeight / UV_SAMPLE_RATE; i++) {
        ifs.read(dst, pixelInfo.alignedWidth * BYTES_PER_PIXEL_YUV);
        dst += handle->stride;
    }
    return true;
}

bool BufferHelper::CopyRgbaData(BufferHandle *handle, ifstream &ifs, PixelFileInfo& pixelInfo)
{
    static constexpr uint32_t BYTES_PER_PIXEL_RBGA = 4;
    char* dst = reinterpret_cast<char*>(handle->virAddr);
    for (uint32_t i = 0; i < pixelInfo.displayHeight; i++) {
        ifs.read(dst, pixelInfo.alignedWidth * BYTES_PER_PIXEL_RBGA);
        dst += handle->stride;
    }
    return true;
}

uint32_t BufferHelper::GetPixelFmtFromFileSuffix(const string& imageFile)
{
    if (imageFile.rfind(".rgba") != string::npos) {
        return OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_RGBA_8888;
    }
    if (imageFile.rfind(".nv21") != string::npos) {
        return OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCRCB_420_SP;
    }
    return OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP;
}

sptr<NativeBuffer> BufferHelper::CreateImgBuffer(const string& imageFile)
{
    IF_TRUE_RETURN_VAL(imageFile.length() <= 0, nullptr);
    ifstream ifs(imageFile, ios::binary);
    IF_TRUE_RETURN_VAL_WITH_MSG(!ifs.is_open(), nullptr, "cannot open %{public}s", imageFile.c_str());
    PixelFileInfo pixelInfo;
    IF_TRUE_RETURN_VAL_WITH_MSG(!ExtractPixelInfoFromFilePath(imageFile, pixelInfo), nullptr,
                                "invalid file path format: %{public}s", imageFile.c_str());
    uint64_t usage = OHOS::HDI::Display::Composer::V1_2::HBM_USE_CPU_READ |
                     OHOS::HDI::Display::Composer::V1_2::HBM_USE_CPU_WRITE |
                     OHOS::HDI::Display::Composer::V1_2::HBM_USE_MEM_DMA;
    pixelInfo.pixFmt = GetPixelFmtFromFileSuffix(imageFile);
    HDF_LOGI("pixelFmt=0x%{public}x", pixelInfo.pixFmt);
    AllocInfo alloc = {
        .width = pixelInfo.displayWidth,
        .height = pixelInfo.displayHeight,
        .usage =  usage,
        .format = pixelInfo.pixFmt
    };
    BufferHandle *handle = nullptr;
    int32_t ret = bufferMgr_->AllocMem(alloc, handle);
    IF_TRUE_RETURN_VAL_WITH_MSG(ret != HDF_SUCCESS, nullptr,
                                "failed to alloc buffer, err [%{public}d] !", ret);
    bufferMgr_->Mmap(*handle);
    bool flag = (pixelInfo.pixFmt == OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_RGBA_8888) ?
                CopyRgbaData(handle, ifs, pixelInfo) :
                CopyYuvData(handle, ifs, pixelInfo);
    (void)bufferMgr_->Unmap(*handle);
    if (!flag) {
        bufferMgr_->FreeMem(*handle);
        return nullptr;
    }
    sptr<NativeBuffer> imgBuffer = new NativeBuffer(handle);
    return imgBuffer;
}

SharedBuffer BufferHelper::CreateSharedBuffer(map<PropertyType, string>& metaInfo)
{
    SharedBuffer buffer = {
        .fd = -1,
        .filledLen = 0,
        .capacity = 0
    };
    ByteWriter bw;
    bool flag = true;
    for (auto iter = metaInfo.begin(); (iter != metaInfo.end()) && flag; ++iter) {
        flag = bw.AddDataFromFile(iter->first, iter->second);
    }
    if (flag && bw.Finalize(buffer)) {
        allocatedFd_.insert(buffer.fd);
    }
    return buffer;
}

SharedBuffer BufferHelper::CreateSharedBuffer(const string& metaFile)
{
    SharedBuffer buffer = {
        .fd = -1,
        .filledLen = 0,
        .capacity = 0
    };
    IF_TRUE_RETURN_VAL_WITH_MSG(metaFile.length() <= 0, buffer, "no metaFile");
    ifstream ifs(metaFile, ios::binary);
    IF_TRUE_RETURN_VAL_WITH_MSG(!ifs.is_open(), buffer, "cannot open %{public}s", metaFile.c_str());
    size_t totalSize = GetFileSizeInBytes(ifs);
    int fd = AshmemCreate("ForMetaData", totalSize);
    IF_TRUE_RETURN_VAL_WITH_MSG(fd < 0, buffer, "cannot create ashmem for meta data");
    void *addr = mmap(nullptr, totalSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == nullptr) {
        HDF_LOGE("failed to map addr for meta buffer");
        close(fd);
        return buffer;
    }
    ifs.read(reinterpret_cast<char*>(addr), totalSize);
    if (munmap(addr, totalSize) != 0) {
        HDF_LOGW("failed to unmap addr for meta buffer");
    }
    buffer.fd = fd;
    buffer.filledLen = static_cast<uint32_t>(totalSize);
    buffer.capacity = static_cast<uint32_t>(AshmemGetSize(fd));
    allocatedFd_.insert(fd);
    return buffer;
}

void BufferHelper::DumpBuffer(const string& filePath, const SharedBuffer& buffer)
{
    IF_TRUE_RETURN_WITH_MSG(filePath.length() <= 0, "dump path is empty");
    constexpr int maxPathLen = 256;
    char outputFilePath[maxPathLen] = {0};
    int ret = sprintf_s(outputFilePath, sizeof(outputFilePath), "%s/out.heic",
                        filePath.c_str());
    if (ret == -1) {
        HDF_LOGE("failed to create dump file");
        return;
    }
    HDF_LOGI("dump buffer to: %{public}s", outputFilePath);
    ofstream ofs(outputFilePath, ios::binary);
    IF_TRUE_RETURN_WITH_MSG(!ofs.is_open(), "cannot open %{public}s", outputFilePath);
    void *addr = mmap(nullptr, buffer.filledLen, PROT_READ | PROT_WRITE, MAP_SHARED, buffer.fd, 0);
    if (addr != nullptr) {
        ofs.write(static_cast<char*>(addr), static_cast<streamsize>(buffer.filledLen));
        ofs.close();
    } else {
        HDF_LOGE("failed to map addr for dump buffer");
    }
    if (munmap(addr, buffer.filledLen) != 0) {
        HDF_LOGW("failed to unmap addr for dump buffer");
    }
}

ByteWriter::~ByteWriter()
{
    for (auto iter = data_.begin(); iter != data_.end(); ++iter) {
        delete [] iter->data;
    }
    data_.clear();
}

bool ByteWriter::CopyDataTo(uint8_t* dstStart)
{
    size_t offset = 0;
    errno_t ret = EOK;
    for (auto iter = data_.begin(); (iter != data_.end()) && (ret == EOK); ++iter) {
        ret = memcpy_s(dstStart + offset, iter->len, iter->data, iter->len);
        offset += iter->len;
    }
    return (ret == EOK);
}

bool ByteWriter::Finalize(std::vector<uint8_t>& dst)
{
    dst.clear();
    dst.resize(totalSize_);
    return CopyDataTo(reinterpret_cast<uint8_t*>(dst.data()));
}

bool ByteWriter::AddDataFromFile(PropertyType key, const string& filePath)
{
    IF_TRUE_RETURN_VAL_WITH_MSG(filePath.length() <= 0, false, "no prop file");
    ifstream ifs(filePath, ios::binary);
    IF_TRUE_RETURN_VAL_WITH_MSG(!ifs.is_open(), false, "cannot open %{public}s", filePath.c_str());
    size_t fileSize = GetFileSizeInBytes(ifs);
    static constexpr size_t BYTE_TO_STORE_BUFFER_SIZE = 4;
    std::size_t dataSize = sizeof(key) + BYTE_TO_STORE_BUFFER_SIZE + fileSize;
    uint8_t* p = new uint8_t[dataSize];
    IF_TRUE_RETURN_VAL(p == nullptr, false);
    data_.emplace_back(DataBlock {
        .data = p,
        .len = dataSize
    });
    totalSize_ += dataSize;
    errno_t ret = memset_s(p, dataSize, 0, dataSize);
    IF_TRUE_RETURN_VAL_WITH_MSG(ret != EOK, false, "failed to init mem");
    size_t offset = 0;
    ret = memcpy_s(p + offset, sizeof(key), reinterpret_cast<uint8_t*>(&key), sizeof(key));
    IF_TRUE_RETURN_VAL_WITH_MSG(ret != EOK, false, "failed to copy key");
    offset += sizeof(key);
    ret = memcpy_s(p + offset, BYTE_TO_STORE_BUFFER_SIZE,
                   reinterpret_cast<uint8_t*>(&fileSize), BYTE_TO_STORE_BUFFER_SIZE);
    IF_TRUE_RETURN_VAL_WITH_MSG(ret != EOK, false, "failed to copy buffer size");
    offset += BYTE_TO_STORE_BUFFER_SIZE;
    ifs.read(reinterpret_cast<char*>(p) + offset, fileSize);
    return true;
}

bool ByteWriter::Finalize(SharedBuffer& buffer)
{
    int fd = AshmemCreate("ForMetaProp", totalSize_);
    IF_TRUE_RETURN_VAL_WITH_MSG(fd < 0, false, "cannot create ashmem for meta prop");
    void *addr = mmap(nullptr, totalSize_, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == nullptr) {
        HDF_LOGE("failed to map addr for meta prop");
        close(fd);
        return false;
    }
    bool flag = CopyDataTo(reinterpret_cast<uint8_t*>(addr));
    if (munmap(addr, totalSize_) != 0) {
        HDF_LOGW("failed to unmap addr for meta prop");
    }
    if (flag) {
        buffer.fd = fd;
        buffer.filledLen = static_cast<uint32_t>(totalSize_);
        buffer.capacity = static_cast<uint32_t>(AshmemGetSize(fd));
        return true;
    }
    return false;
}
}