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

#include "utils_data_stub.h"

namespace OHOS::Camera {
bool UtilsDataStub::WriteMetadataDataToVec(const camera_metadata_item_t &entry, std::vector<uint8_t>& cameraAbility)
{
    if (entry.data_type == META_TYPE_BYTE) {
        for (size_t i = 0; i < entry.count; i++) {
            WriteData<int8_t>(*(entry.data.u8 + i), cameraAbility);
        }
    } else if (entry.data_type == META_TYPE_INT32) {
        for (size_t i = 0; i < entry.count; i++) {
            WriteData<int32_t>(*(entry.data.i32 + i), cameraAbility);
        }
    } else if (entry.data_type == META_TYPE_FLOAT) {
        for (size_t i = 0; i < entry.count; i++) {
            WriteData<float>(*(entry.data.f + i), cameraAbility);
        }
    } else if (entry.data_type == META_TYPE_INT64) {
        for (size_t i = 0; i < entry.count; i++) {
            WriteData<int64_t>(*(entry.data.i64 + i), cameraAbility);
        }
    } else if (entry.data_type == META_TYPE_DOUBLE) {
        for (size_t i = 0; i < entry.count; i++) {
            WriteData<double>(*(entry.data.d + i), cameraAbility);
        }
    } else if (entry.data_type == META_TYPE_RATIONAL) {
        for (size_t i = 0; i < entry.count; i++) {
            WriteData<int32_t>((*(entry.data.r + i)).numerator, cameraAbility);
            WriteData<int32_t>((*(entry.data.r + i)).denominator, cameraAbility);
        }
    }

    return true;
}

bool UtilsDataStub::ConvertMetadataToVec(const std::shared_ptr<CameraMetadata> &metadata,
    std::vector<uint8_t>& cameraAbility)
{
    if (metadata == nullptr) {
        return false;
    }

    bool bRet = true;
    uint32_t tagCount = 0;
    common_metadata_header_t *meta = metadata->get();
    if (meta != nullptr) {
        tagCount = GetCameraMetadataItemCount(meta);
        WriteData<uint32_t>(tagCount, cameraAbility);
        WriteData<uint32_t>(GetCameraMetadataItemCapacity(meta), cameraAbility);
        WriteData<uint32_t>(GetCameraMetadataDataSize(meta), cameraAbility);
        for (uint32_t i = 0; i < tagCount; i++) {
            camera_metadata_item_t item;
            int ret = GetCameraMetadataItem(meta, i, &item);
            if (ret != CAM_META_SUCCESS) {
                return false;
            }

            WriteData<uint32_t>(item.index, cameraAbility);
            WriteData<uint32_t>(item.item, cameraAbility);
            WriteData<uint32_t>(item.data_type, cameraAbility);
            WriteData<uint32_t>(item.count, cameraAbility);

            bRet = WriteMetadataDataToVec(item, cameraAbility);
        }
    } else {
        cameraAbility.push_back(tagCount);
    }

    return bRet;
}

bool UtilsDataStub::EncodeCameraMetadata(const std::shared_ptr<CameraMetadata> &metadata,
    MessageParcel &data)
{
    if (metadata == nullptr) {
        return false;
    }

    bool bRet = true;
    uint32_t tagCount = 0;
    common_metadata_header_t *meta = metadata->get();
    if (meta != nullptr) {
        tagCount = Camera::GetCameraMetadataItemCount(meta);
        bRet = (bRet && data.WriteInt32(static_cast<int32_t>(tagCount)));
        camera_metadata_item_entry_t *item = Camera::GetMetadataItems(meta);
        for (uint32_t i = 0; i < tagCount; i++, item++) {
            camera_metadata_item_t entry;
            int ret = FindCameraMetadataItem(meta, item->item, &entry);
            if (ret == -ENOENT) {
                return false;
            }

            bRet = (bRet && data.WriteUint32(static_cast<uint32_t>(entry.index)));
            bRet = (bRet && data.WriteUint32(entry.item));
            bRet = (bRet && data.WriteUint8(static_cast<uint8_t>(entry.data_type)));
            bRet = (bRet && data.WriteUint32(static_cast<uint32_t>(entry.count)));
            bRet = (bRet && UtilsDataStub::WriteMetadata(entry, data));
        }
    } else {
        bRet = data.WriteInt32(tagCount);
    }
    return bRet;
}

bool UtilsDataStub::ReadMetadataDataFromVec(int32_t &index, camera_metadata_item_t &entry,
    const std::vector<uint8_t>& cameraAbility)
{
    if (entry.data_type == META_TYPE_BYTE) {
        entry.data.u8 = new(std::nothrow) uint8_t[entry.count];
        if (entry.data.u8 != nullptr) {
            for (size_t i = 0; i < entry.count; i++) {
                ReadData<uint8_t>(entry.data.u8[i], index, cameraAbility);
            }
        }
    } else if (entry.data_type == META_TYPE_INT32) {
        entry.data.i32 = new(std::nothrow) int32_t[entry.count];
        if (entry.data.i32 != nullptr) {
            for (size_t i = 0; i < entry.count; i++) {
                ReadData<int32_t>(entry.data.i32[i], index, cameraAbility);
            }
        }
    } else if (entry.data_type == META_TYPE_FLOAT) {
        entry.data.f = new(std::nothrow) float[entry.count];
        if (entry.data.f != nullptr) {
            for (size_t i = 0; i < entry.count; i++) {
                ReadData<float>(entry.data.f[i], index, cameraAbility);
            }
        }
    } else if (entry.data_type == META_TYPE_INT64) {
        entry.data.i64 = new(std::nothrow) int64_t[entry.count];
        if (entry.data.i64 != nullptr) {
            for (size_t i = 0; i < entry.count; i++) {
                ReadData<int64_t>(entry.data.i64[i], index, cameraAbility);
            }
        }
    } else if (entry.data_type == META_TYPE_DOUBLE) {
        entry.data.d = new(std::nothrow) double[entry.count];
        if (entry.data.d != nullptr) {
            for (size_t i = 0; i < entry.count; i++) {
                ReadData<double>(entry.data.d[i], index, cameraAbility);
            }
        }
    } else if (entry.data_type == META_TYPE_RATIONAL) {
        entry.data.r = new(std::nothrow) camera_rational_t[entry.count];
        if (entry.data.r != nullptr) {
            for (size_t i = 0; i < entry.count; i++) {
                ReadData<int32_t>(entry.data.r[i].numerator, index, cameraAbility);
                ReadData<int32_t>(entry.data.r[i].denominator, index, cameraAbility);
            }
        }
    }

    return true;
}

void UtilsDataStub::ConvertVecToMetadata(const std::vector<uint8_t>& cameraAbility,
    std::shared_ptr<CameraMetadata> &metadata)
{
    int32_t index = 0;
    uint32_t tagCount = 0;
    uint32_t itemCapacity = 0;
    uint32_t dataCapacity = 0;
    constexpr uint32_t MAX_SUPPORTED_TAGS = 1000;
    constexpr uint32_t MAX_SUPPORTED_ITEMS = 1000;
    constexpr uint32_t MAX_ITEM_CAPACITY = (1000 * 10);
    constexpr uint32_t MAX_DATA_CAPACITY = (1000 * 10 * 10);

    ReadData<uint32_t>(tagCount, index, cameraAbility);
    if (tagCount > MAX_SUPPORTED_TAGS) {
        tagCount = MAX_SUPPORTED_TAGS;
        METADATA_ERR_LOG("MetadataUtils::DecodeCameraMetadata tagCount is more than supported value");
    }
    ReadData<uint32_t>(itemCapacity, index, cameraAbility);
    if (itemCapacity > MAX_ITEM_CAPACITY) {
        itemCapacity = MAX_ITEM_CAPACITY;
        METADATA_ERR_LOG("MetadataUtils::DecodeCameraMetadata itemCapacity is more than supported value");
    }
    ReadData<uint32_t>(dataCapacity, index, cameraAbility);
    if (dataCapacity > MAX_DATA_CAPACITY) {
        dataCapacity = MAX_DATA_CAPACITY;
        METADATA_ERR_LOG("MetadataUtils::DecodeCameraMetadata dataCapacity is more than supported value");
    }

    std::vector<camera_metadata_item_t> items;
    for (int32_t i = 0; i < tagCount; i++) {
        camera_metadata_item_t item;
        ReadData<uint32_t>(item.index, index, cameraAbility);
        ReadData<uint32_t>(item.item, index, cameraAbility);
        ReadData<uint32_t>(item.data_type, index, cameraAbility);
        ReadData<uint32_t>(item.count, index, cameraAbility);
        if (item.count > MAX_SUPPORTED_ITEMS) {
            item.count = MAX_SUPPORTED_ITEMS;
            METADATA_ERR_LOG("MetadataUtils::DecodeCameraMetadata item.count is more than supported value");
        }
        ReadMetadataDataFromVec(index, item, cameraAbility);
        items.push_back(item);
    }

    metadata = std::make_shared<CameraMetadata>(itemCapacity, dataCapacity);
    common_metadata_header_t *meta = metadata->get();
    for (auto &item_ : items) {
        void *buffer = nullptr;
        MetadataUtils::ItemDataToBuffer(item_, &buffer);
        (void)AddCameraMetadataItem(meta, item_.item, buffer, item_.count);
        MetadataUtils::FreeMetadataBuffer(item_);
    }
}

void UtilsDataStub::DecodeCameraMetadata(MessageParcel &data, std::shared_ptr<CameraMetadata> &metadata)
{
    int32_t tagCount = data.ReadInt32();
    if (tagCount <= 0) {
        return;
    }

    int32_t metadataSize = 0;
    std::vector<camera_metadata_item_t> entrys;
    for (int32_t i = 0; i < tagCount; i++) {
        camera_metadata_item_t entry;
        entry.index = static_cast<size_t>(data.ReadUint32());
        entry.item = static_cast<uint32_t>(data.ReadUint32());
        entry.data_type = static_cast<uint8_t>(data.ReadUint8());
        entry.count = static_cast<size_t>(data.ReadUint32());
        ReadMetadata(entry, data);
        metadataSize++;

        entrys.push_back(entry);
    }

    metadata = std::make_shared<CameraMetadata>(tagCount, metadataSize);
    common_metadata_header_t *meta = metadata->get();
    for (auto &entry : entrys) {
        void *buffer = nullptr;
        UtilsDataStub::EntryDataToBuffer(entry, &buffer);
        if (buffer != nullptr) {
            (void)Camera::AddCameraMetadataItem(meta, entry.item, buffer, entry.count);
        }
        MetadataUtils::FreeMetadataBuffer(item_);
    }
}

bool UtilsDataStub::EncodeStreamInfo(const std::shared_ptr<StreamInfo> &pInfo, MessageParcel &parcel)
{
    bool bRet = true;
    bRet = (bRet && parcel.WriteInt32(static_cast<int32_t>(pInfo->streamId_)));
    bRet = (bRet && parcel.WriteInt32(static_cast<int32_t>(pInfo->width_)));
    bRet = (bRet && parcel.WriteInt32(static_cast<int32_t>(pInfo->height_)));
    bRet = (bRet && parcel.WriteInt32(static_cast<int32_t>(pInfo->format_)));
    bRet = (bRet && parcel.WriteInt32(pInfo->intent_));
    bRet = (bRet && parcel.WriteBool(pInfo->tunneledMode_));
    bool bufferQueueFlag = (pInfo->bufferQueue_->producer_ != nullptr) ? true : false;
    bRet = (bRet && parcel.WriteBool(bufferQueueFlag));
    if (bufferQueueFlag) {
        bRet = (bRet && parcel.WriteRemoteObject(pInfo->bufferQueue_->producer_->AsObject()));
    }
    bRet = (bRet && parcel.WriteInt32(static_cast<int32_t>(pInfo->minFrameDuration_)));
    bRet = (bRet && parcel.WriteInt32(pInfo->encodeType_));
    return bRet;
}

void UtilsDataStub::DecodeStreamInfo(MessageParcel &parcel, std::shared_ptr<StreamInfo> &pInfo)
{
    pInfo->streamId_ = static_cast<int>(parcel.ReadInt32());
    pInfo->width_ = static_cast<int>(parcel.ReadInt32());
    pInfo->height_ = static_cast<int>(parcel.ReadInt32());
    pInfo->format_ = static_cast<int>(parcel.ReadInt32());
    pInfo->intent_ = static_cast<StreamIntent>(parcel.ReadInt32());
    pInfo->tunneledMode_ = parcel.ReadBool();
    bool bufferQueueFlag = parcel.ReadBool();
    if (bufferQueueFlag) {
        sptr<IRemoteObject> remoteBufferProducer = parcel.ReadRemoteObject();
        pInfo->bufferQueue_->producer_ = OHOS::iface_cast<OHOS::IBufferProducer>(remoteBufferProducer);
    }
    pInfo->minFrameDuration_ = static_cast<int>(parcel.ReadInt32());
    pInfo->encodeType_ = static_cast<EncodeType>(parcel.ReadInt32());
}

int32_t UtilsDataStub::GetDataSize(uint8_t type)
{
    int32_t size = 0;
    if (type == META_TYPE_BYTE) {
        size = sizeof(uint8_t);
    } else if (type == META_TYPE_INT32) {
        size = sizeof(int32_t);
    } else if (type == META_TYPE_FLOAT) {
        size = sizeof(float);
    } else if (type == META_TYPE_INT64) {
        size = sizeof(int64_t);
    } else if (type == META_TYPE_DOUBLE) {
        size = sizeof(double);
    } else if (type == META_TYPE_RATIONAL) {
        size = sizeof(camera_rational_t);
    } else {
        size = 0;
    }
    return size;
}

bool UtilsDataStub::WriteMetadata(const camera_metadata_item_t &entry, MessageParcel &data)
{
    if (entry.data_type == META_TYPE_BYTE) {
        std::vector<uint8_t> buffers;
        for (size_t i = 0; i < entry.count; i++) {
            buffers.push_back(*(entry.data.u8 + i));
        }
        data.WriteUInt8Vector(buffers);
    } else if (entry.data_type == META_TYPE_INT32) {
        std::vector<int32_t> buffers;
        for (size_t i = 0; i < entry.count; i++) {
            buffers.push_back(*(entry.data.i32 + i));
        }
        data.WriteInt32Vector(buffers);
    } else if (entry.data_type == META_TYPE_FLOAT) {
        std::vector<float> buffers;
        for (size_t i = 0; i < entry.count; i++) {
            buffers.push_back(*(entry.data.f + i));
        }
        data.WriteFloatVector(buffers);
    } else if (entry.data_type == META_TYPE_INT64) {
        std::vector<int64_t> buffers;
        for (size_t i = 0; i < entry.count; i++) {
            buffers.push_back(*(entry.data.i64 + i));
        }
        data.WriteInt64Vector(buffers);
    } else if (entry.data_type == META_TYPE_DOUBLE) {
        std::vector<double> buffers;
        for (size_t i = 0; i < entry.count; i++) {
            buffers.push_back(*(entry.data.d + i));
        }
        data.WriteDoubleVector(buffers);
    } else if (entry.data_type == META_TYPE_RATIONAL) {
        std::vector<int32_t> buffers;
        for (size_t i = 0; i < entry.count; i++) {
            buffers.push_back((*(entry.data.r + i)).numerator);
            buffers.push_back((*(entry.data.r + i)).denominator);
        }
        data.WriteInt32Vector(buffers);
    }

    return true;
}

bool UtilsDataStub::ReadMetadata(camera_metadata_item_t &entry, MessageParcel &data)
{
    if (entry.data_type == META_TYPE_BYTE) {
        std::vector<uint8_t> buffers;
        data.ReadUInt8Vector(&buffers);
        entry.data.u8 = new(std::nothrow) uint8_t[entry.count];
        if (entry.data.u8 != nullptr) {
            for (size_t i = 0; i < entry.count; i++) {
                entry.data.u8[i] = buffers.at(i);
            }
        }
    } else if (entry.data_type == META_TYPE_INT32) {
        std::vector<int32_t> buffers;
        data.ReadInt32Vector(&buffers);
        entry.data.i32 = new(std::nothrow) int32_t[entry.count];
        if (entry.data.i32 != nullptr) {
            for (size_t i = 0; i < entry.count; i++) {
                entry.data.i32[i] = buffers.at(i);
            }
        }
    } else if (entry.data_type == META_TYPE_FLOAT) {
        std::vector<float> buffers;
        data.ReadFloatVector(&buffers);
        entry.data.f = new(std::nothrow) float[entry.count];
        if (entry.data.f != nullptr) {
            for (size_t i = 0; i < entry.count; i++) {
                entry.data.f[i] = buffers.at(i);
            }
        }
    } else if (entry.data_type == META_TYPE_INT64) {
        std::vector<int64_t> buffers;
        data.ReadInt64Vector(&buffers);
        entry.data.i64 = new(std::nothrow) int64_t[entry.count];
        if (entry.data.i64 != nullptr) {
            for (size_t i = 0; i < entry.count; i++) {
                entry.data.i64[i] = buffers.at(i);
            }
        }
    } else if (entry.data_type == META_TYPE_DOUBLE) {
        std::vector<double> buffers;
        data.ReadDoubleVector(&buffers);
        entry.data.d = new(std::nothrow) double[entry.count];
        if (entry.data.d != nullptr) {
            for (size_t i = 0; i < entry.count; i++) {
                entry.data.d[i] = buffers.at(i);
            }
        }
    } else if (entry.data_type == META_TYPE_RATIONAL) {
        std::vector<int32_t> buffers;
        data.ReadInt32Vector(&buffers);
        entry.data.r = new(std::nothrow) camera_rational_t[entry.count];
        if (entry.data.r != nullptr) {
            for (size_t i = 0, j = 0;
                i < entry.count && j < static_cast<size_t>(buffers.size());
                i++, j += 2) { // 2:Take two elements from the buffer vector container
                entry.data.r[i].numerator = buffers.at(j);
                entry.data.r[i].denominator = buffers.at(j + 1);
            }
        }
    }
    return true;
}

void UtilsDataStub::EntryDataToBuffer(const camera_metadata_item_t &entry, void **buffer)
{
    if (entry.data_type == META_TYPE_BYTE) {
        *buffer = static_cast<void*>(entry.data.u8);
    } else if (entry.data_type == META_TYPE_INT32) {
        *buffer = static_cast<void*>(entry.data.i32);
    } else if (entry.data_type == META_TYPE_FLOAT) {
        *buffer = static_cast<void*>(entry.data.f);
    } else if (entry.data_type == META_TYPE_INT64) {
        *buffer = static_cast<void*>(entry.data.i64);
    } else if (entry.data_type == META_TYPE_DOUBLE) {
        *buffer = static_cast<void*>(entry.data.d);
    } else if (entry.data_type == META_TYPE_RATIONAL) {
        *buffer = static_cast<void*>(entry.data.r);
    }
}
}
