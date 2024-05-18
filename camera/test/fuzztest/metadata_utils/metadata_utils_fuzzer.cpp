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

void FuncEncodeCameraMetadata(const uint8_t *rawData, size_t size)
{
    MessageParcel data;
    std::shared_ptr<CameraMetadata> metadata
        = std::make_shared<CameraMetadata>(MAX_ITEM_CAPACITY, MAX_ITEM_CAPACITY);
    std::vector<uint8_t> cameraAbility(rawData, rawData + size);
    MetadataUtils::ConvertVecToMetadata(cameraAbility, metadata);

    MetadataUtils::EncodeCameraMetadata(metadata, data);
}

void FuncDecodeCameraMetadata(const uint8_t *rawData, size_t size)
{
    MessageParcel data;
    std::vector<uint32_t> dataVec(rawData, rawData + size);
    data.WriteUInt32Vector(dataVec);
    std::shared_ptr<CameraMetadata> metadata
        = std::make_shared<CameraMetadata>(MAX_ITEM_CAPACITY, MAX_ITEM_CAPACITY);

    MetadataUtils::DecodeCameraMetadata(data, metadata);
}

void FuncEncodeToString(const uint8_t *rawData, size_t size)
{
    std::shared_ptr<CameraMetadata> metadata
        = std::make_shared<CameraMetadata>(MAX_ITEM_CAPACITY, MAX_ITEM_CAPACITY);
    std::vector<uint8_t> cameraAbility(rawData, rawData + size);
    MetadataUtils::ConvertVecToMetadata(cameraAbility, metadata);

    MetadataUtils::EncodeToString(metadata);
}

void FuncDecodeFromString(const uint8_t *rawData, size_t size)
{
    std::string str(rawData, rawData + size);
    MetadataUtils::DecodeFromString(str);
}

void FuncConvertMetadataToVec(const uint8_t *rawData, size_t size)
{
    std::shared_ptr<CameraMetadata> metadata
        = std::make_shared<CameraMetadata>(MAX_ITEM_CAPACITY, MAX_ITEM_CAPACITY);
    std::vector<uint8_t> cameraAbility(rawData, rawData + size);
    MetadataUtils::ConvertVecToMetadata(cameraAbility, metadata);

    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(metadata, metaVec);
}

void FuncConvertVecToMetadata(const uint8_t *rawData, size_t size)
{
    std::shared_ptr<CameraMetadata> metadata
        = std::make_shared<CameraMetadata>(MAX_ITEM_CAPACITY, MAX_ITEM_CAPACITY);
    std::vector<uint8_t> cameraAbility(rawData, rawData + size);
    MetadataUtils::ConvertVecToMetadata(cameraAbility, metadata);
}

typedef void (*TestFuncDef)(const uint8_t *rawData, size_t size);
static TestFuncDef g_allTestFunc[] = {
    FuncEncodeCameraMetadata,
    FuncDecodeCameraMetadata,
    FuncEncodeToString,
    FuncDecodeFromString,
    FuncConvertMetadataToVec,
    FuncConvertVecToMetadata,
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

    uint32_t cmd = 0;
    rawData += sizeof(cmd);

    uint32_t minInputSize = GetMinInputSize(rawData);
    if (size < minInputSize || minInputSize == 0) {
        return false;
    }

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