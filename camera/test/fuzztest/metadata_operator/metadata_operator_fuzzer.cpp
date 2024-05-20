/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "camera.h"
#include "camera_metadata_operator.h"
#include "metadata_utils.h"

using namespace OHOS::Camera;
namespace OHOS {
const size_t THRESHOLD = 12;

enum BitOperat {
    INDEX_0 = 0,
    INDEX_1,
    INDEX_2,
    INDEX_3,
    OFFSET,
    MOVE_EIGHT_BITS = 8,
    MOVE_SIXTEEN_BITS = 16,
    DATA_TYPE_OFFSET = 20,
    MOVE_TWENTY_FOUR_BITS = 24,
    META_HEADER_SIZE = 28,
};
static uint32_t ConvertUint32(const uint8_t *bitOperat)
{
    if (bitOperat == nullptr) {
        return 0;
    }

    return (bitOperat[INDEX_0] << MOVE_TWENTY_FOUR_BITS) | (bitOperat[INDEX_1] << MOVE_SIXTEEN_BITS) |
        (bitOperat[INDEX_2] << MOVE_EIGHT_BITS) | (bitOperat[INDEX_3]);
}

uint32_t GetMinInputSize(const uint8_t *rawData)
{
    uint32_t dataType = ConvertUint32(rawData + DATA_TYPE_OFFSET);
    uint32_t dataSize;
    switch (dataType) {
        case META_TYPE_BYTE:
            dataSize = sizeof(uint8_t);
            break;
        case META_TYPE_INT32:
            dataSize = sizeof(int32_t);
            break;
        case META_TYPE_UINT32:
            dataSize = sizeof(uint32_t);
            break;
        case META_TYPE_FLOAT:
            dataSize = sizeof(float);
            break;
        case META_TYPE_INT64:
            dataSize = sizeof(int64_t);
            break;
        case META_TYPE_DOUBLE:
            dataSize = sizeof(double);
            break;
        case META_TYPE_RATIONAL:
            dataSize = sizeof(camera_rational_t);
            break;
        default:
            dataSize = 0;
            break;
    }
    uint32_t dataCount = ConvertUint32(rawData + MOVE_TWENTY_FOUR_BITS);
    uint32_t maxValue = std::numeric_limits<uint32_t>::max();
    if (dataSize == 0 || dataCount == 0 || dataCount > (maxValue - META_HEADER_SIZE)/dataSize) {
        return 0;
    }
    return (META_HEADER_SIZE + dataSize * dataCount);
}

void GetMetadataHeader(const uint8_t *rawData, size_t size, common_metadata_header_t* meta)
{
    uint32_t minInputSize = GetMinInputSize(rawData);
    if (size < minInputSize || minInputSize == 0) {
        return;
    }
    std::shared_ptr<CameraMetadata> metadata
        = std::make_shared<CameraMetadata>(MAX_ITEM_CAPACITY, MAX_ITEM_CAPACITY);
    std::vector<uint8_t> cameraAbility(rawData, rawData + size);
    MetadataUtils::ConvertVecToMetadata(cameraAbility, metadata);
    meta = metadata->get();
}

void FuncAllocateCameraMetadataBuffer(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = AllocateCameraMetadataBuffer(ConvertUint32(rawData),
        ConvertUint32(rawData + OFFSET));

    if (meta != nullptr) {
        FreeCameraMetadataBuffer(meta);
    }
}

void FuncIsCameraMetadataItemExist(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }

    IsCameraMetadataItemExist(meta, ConvertUint32(rawData + MOVE_EIGHT_BITS));
}

void FuncFindCameraMetadataItem(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }

    camera_metadata_item_t entry;
    FindCameraMetadataItem(meta, ConvertUint32(rawData + MOVE_EIGHT_BITS), &entry);
}

void FuncFindCameraMetadataItemIndex(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }
    
    uint32_t index = 0;
    FindCameraMetadataItemIndex(meta, ConvertUint32(rawData + MOVE_EIGHT_BITS), &index);
}

void FuncGetCameraMetadataItemName(const uint8_t *rawData, size_t size)
{
    GetCameraMetadataItemName(ConvertUint32(rawData));
}

void FuncAddCameraMetadataItem(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }
    camera_metadata_item_t entry;
    FindCameraMetadataItem(meta, ConvertUint32(rawData), &entry);

    std::shared_ptr<CameraMetadata> metadata1
        = std::make_shared<CameraMetadata>(MAX_ITEM_CAPACITY, MAX_ITEM_CAPACITY);
    common_metadata_header_t *meta1 = metadata1->get();
    AddCameraMetadataItem(meta1, entry.item, rawData, entry.count);
}

void FuncDeleteCameraMetadataItem(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }

    DeleteCameraMetadataItem(meta, ConvertUint32(rawData + MOVE_EIGHT_BITS));
}

void FuncFreeCameraMetadataBuffer(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = AllocateCameraMetadataBuffer(ConvertUint32(rawData),
        ConvertUint32(rawData + OFFSET));
    if (meta == nullptr) {
        return;
    }

    FreeCameraMetadataBuffer(meta);
}

void FuncFormatCameraMetadataToString(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }

    FormatCameraMetadataToString(meta);
}

void FuncGetMetadataItems(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }

    GetMetadataItems(meta);
}

void FuncGetMetadataData(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }

    GetMetadataData(meta);
}

void FuncGetCameraMetadataItem(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }

    camera_metadata_item_t item;
    GetCameraMetadataItem(meta, ConvertUint32(rawData), &item);
}

void FuncGetCameraMetadataItemCount(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }

    GetCameraMetadataItemCount(meta);
}

void FuncGetCameraMetadataItemCapacity(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }

    GetCameraMetadataItemCapacity(meta);
}

void FuncGetCameraMetadataDataSize(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *meta = nullptr;
    GetMetadataHeader(rawData, size, meta);
    if (meta == nullptr) {
        return;
    }

    GetCameraMetadataDataSize(meta);
}

void FuncCopyCameraMetadataItems(const uint8_t *rawData, size_t size)
{
    common_metadata_header_t *oldmeta = nullptr;
    GetMetadataHeader(rawData, size, oldmeta);
    if (oldmeta == nullptr) {
        return;
    }

    common_metadata_header_t *newmeta = AllocateCameraMetadataBuffer(MAX_ITEM_CAPACITY, MAX_ITEM_CAPACITY);
    if (newmeta == nullptr) {
        return;
    }
    CopyCameraMetadataItems(newmeta, oldmeta);
}

void FuncCalculateCameraMetadataItemDataSize(const uint8_t *rawData, size_t size)
{
    CalculateCameraMetadataItemDataSize(ConvertUint32(rawData), static_cast<size_t>(ConvertUint32(rawData + OFFSET)));
}

typedef void (*TestFuncDef)(const uint8_t *rawData, size_t size);
static TestFuncDef g_allTestFunc[] = {
    FuncAllocateCameraMetadataBuffer,
    FuncIsCameraMetadataItemExist,
    FuncFindCameraMetadataItem,
    FuncFindCameraMetadataItemIndex,
    FuncGetCameraMetadataItemName,
    FuncAddCameraMetadataItem,
    FuncDeleteCameraMetadataItem,
    FuncFreeCameraMetadataBuffer,
    FuncFormatCameraMetadataToString,
    FuncGetMetadataItems,
    FuncGetMetadataData,
    FuncGetCameraMetadataItem,
    FuncGetCameraMetadataItemCount,
    FuncGetCameraMetadataItemCapacity,
    FuncGetCameraMetadataDataSize,
    FuncCopyCameraMetadataItems,
    FuncCalculateCameraMetadataItemDataSize,
};


static void TestFuncSwitch(uint32_t cmd, const uint8_t *rawData, size_t size)
{
    int testCount = sizeof(g_allTestFunc) / sizeof(g_allTestFunc[0]);
    TestFuncDef curFunc = g_allTestFunc[cmd % testCount];
    curFunc(rawData, size);
}

bool DoSomethingInterestingWithMyApi(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    uint32_t cmd = ConvertUint32(rawData);
    rawData += sizeof(cmd);

    TestFuncSwitch(cmd, rawData, size);
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        CAMERA_LOGW("Fuzz test input is invalid. The size is smaller than %{public}zu", OHOS::THRESHOLD);
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyApi(data, size);
    return 0;
}
} // namespace OHOS