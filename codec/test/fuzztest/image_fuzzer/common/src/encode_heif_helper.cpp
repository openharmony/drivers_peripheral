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

#include "encode_heif_helper.h"

namespace OHOS::VDI::HEIF {
using namespace OHOS::HDI::Codec::Image::V2_0;
using namespace std;

enum ValueOption : uint8_t {
    OPTION_0 = 0,
    OPTION_1,
    OPTION_2,
    OPTION_3,
    OPTION_BUTT
};

bool HeifEncodeHelper::AllocOutputBuffer(SharedBuffer& output)
{
    static constexpr size_t EXTERNAL_BUFFER_SIZE = 18 * 1024 * 1024;
    int fd = AshmemCreate("ForHeifEditOut", EXTERNAL_BUFFER_SIZE);
    bool flag = true;
    if (fd >= 0) {
        output.fd = fd;
        output.capacity = static_cast<uint32_t>(AshmemGetSize(fd));
    } else {
        flag = false;
        output.fd = -1;
        output.capacity = 0;
        HDF_LOGE("failed to create output buffer");
    }
    output.filledLen = 0;
    return flag;
}


void HeifEncodeHelper::Reset()
{
    inputImgs_.clear();
    inputMetas_.clear();
    refs_.clear();
}

ItemRef HeifEncodeHelper::FillRefItem(ItemRef item, uint8_t *data, size_t &size)
{
    uint8_t *dataEnd = data + size - 1;
    if (dataEnd < (data + sizeof(uint8_t))) {
        return item;
    }

    switch ((*data) % OPTION_BUTT) {
        case OPTION_0:
            item.type = DIMG;
            break;
        case OPTION_1:
            item.type = THMB;
            break;
        case OPTION_2:
            item.type = AUXL;
            break;
        case OPTION_3:
            item.type = CDSC;
            break;
    }
    data += sizeof(uint8_t);
    size -= sizeof(uint8_t);

    if (dataEnd < data + sizeof(item.from)) {
        return item;
    }
    item.from = ToUint32(data);
    data += sizeof(item.from);
    size -= sizeof(item.from);

    if (dataEnd < data + sizeof(uint8_t)) {
        return item;
    }
    uint8_t vecSize = (*data) % 2 + 1;
    data += sizeof(vecSize);
    size -= sizeof(vecSize);
    if (dataEnd < (data + vecSize * sizeof(item.from))) {
        return item;
    } else {
        while (vecSize--) {
            item.to.emplace_back(ToUint32(data));
            data += sizeof(item.from);
            size -= sizeof(item.from);
        }
    }
    return item;
}

bool HeifEncodeHelper::FillImageItem(ImgType type, ImageItem& item, uint8_t *data, size_t &size)
{
    uint8_t *dataEnd = data + size - 1;
    item.itemName = "";
    if (dataEnd < data + sizeof(item.id) + sizeof(item.quality) + sizeof(uint8_t)) {
        return false;
    }
    item.id = ToUint32(data);
    data += sizeof(item.id);
    size -= sizeof(item.id);

    item.pixelBuffer = bufferHelper_.CreateImgBuffer(data, size);
    IF_TRUE_RETURN_VAL((type != T_MAP && item.pixelBuffer == nullptr), false);
    item.isPrimary = (type == PRIMARY_IMG);
    item.isHidden = (type != PRIMARY_IMG);
    item.compressType = (type == T_MAP ? "none" : "hevc");

    item.quality = ToUint32(data);
    data += sizeof(item.quality);
    size -= sizeof(item.quality);

    item.liteProperties = {};
    uint8_t liteProSize = *data;
    data += sizeof(liteProSize);
    size -= sizeof(liteProSize);

    if (dataEnd < data + liteProSize) {
        return false;
    }

    HDF_LOGI("Fill Image LiteProperties");
    while (liteProSize--) {
        item.liteProperties.push_back(*data);
        data += sizeof(uint8_t);
        size -= sizeof(uint8_t);
    }

    item.sharedProperties = {
        .fd = -1,
        .filledLen = 0,
        .capacity = 0
    };

    if (dataEnd < (data + sizeof(uint8_t))) {
        return false;
    }
    uint8_t decision = (*data) % 2;
    data += sizeof(decision);
    size -= sizeof(decision);
    if (decision) {
        HDF_LOGI("Fill Image SharedProperties");
        item.sharedProperties = bufferHelper_.CreateSharedBuffer(data, size);
    }
    return true;
}

bool HeifEncodeHelper::AssembleParamForOtherImg(uint32_t primaryImgId, uint8_t *data, size_t &size)
{
    uint8_t *dataEnd = data + size - 1;
    if (dataEnd < data + sizeof(uint8_t)) {
        return false;
    }
    uint8_t decision = (*data) % 2;
    data += sizeof(uint8_t);
    size -= sizeof(uint8_t);

    if (decision == 1) {
        ImageItem itemAuxlImg;
        HDF_LOGI("Fill itemAuxlImg");
        if (!FillImageItem(AUXILIARY_IMG, itemAuxlImg, data, size)) {
            HDF_LOGE("%{public}s: Fill itemAuxlImg failed\n", __func__);
            return false;
        }
        HDF_LOGI("Fill itemAuxlImg Succesfully");
        inputImgs_.emplace_back(itemAuxlImg);
        ItemRef refAuxl = {
            .type = AUXL,
            .auxType = "",
            .from = itemAuxlImg.id,
            .to = {primaryImgId}
        };
        ItemRef newRefAulx = FillRefItem(refAuxl, data, size);
        refs_.emplace_back(newRefAulx);
    } else {
        ImageItem itemThmbImg;
        HDF_LOGI("Fill itemThmbImg");
        if (!FillImageItem(THUMBNAIL_IMG, itemThmbImg, data, size)) {
            HDF_LOGE("%{public}s: Fill itemThmbImg failed\n", __func__);
            return false;
        }
        HDF_LOGI("Fill itemThmbImg Succesfully");
        inputImgs_.emplace_back(itemThmbImg);

        ItemRef refThmb = {
            .type = THMB,
            .auxType = "",
            .from = itemThmbImg.id,
            .to = {primaryImgId}
        };
        ItemRef newRefThmb = FillRefItem(refThmb, data, size);
        refs_.emplace_back(newRefThmb);
    }
    return true;
}

bool HeifEncodeHelper::AssembleParamForTmap(uint8_t *data, size_t &size)
{
    ImageItem itemTmap;
    ImageItem itemPrimaryImg;
    ImageItem itemGainMap;
    HDF_LOGI("AssembleParamForTmap: Fill ImageItem");
    if (!FillImageItem(T_MAP, itemTmap, data, size)) {
        HDF_LOGE("%{public}s: Fill itemTmap failed\n", __func__);
        return false;
    }

    if (!FillImageItem(PRIMARY_IMG, itemPrimaryImg, data, size)) {
        HDF_LOGE("%{public}s: Fill itemPrimaryImg failed\n", __func__);
        return false;
    }

    if (!FillImageItem(GAIN_MAP, itemGainMap, data, size)) {
        HDF_LOGE("%{public}s: Fill itemGainMap failed\n", __func__);
        return false;
    }
    inputImgs_.emplace_back(itemTmap);
    inputImgs_.emplace_back(itemPrimaryImg);
    inputImgs_.emplace_back(itemGainMap);

    ItemRef refTMap = {
        .type = DIMG,
        .auxType = "",
        .from = itemTmap.id,
        .to = {itemPrimaryImg.id, itemGainMap.id}
    };

    HDF_LOGI("AssembleParamForTmap: Fill RefItem");
    ItemRef newRefTMap = FillRefItem(refTMap, data, size);
    refs_.emplace_back(newRefTMap);

    HDF_LOGI("AssembleParamForTmap: Fill OtherImg");
    if (AssembleParamForOtherImg(itemPrimaryImg.id, data, size)) {
        HDF_LOGI("AssembleParamForTmap: Fill MetaData");
        return AssembleParamForMetaData(itemPrimaryImg.id, data, size);
    }
    return false;
}

bool HeifEncodeHelper::AssembleParamForPrimaryImg(uint8_t *data, size_t &size)
{
    ImageItem itemPrimaryImg;
    HDF_LOGI("AssembleParamForPrimaryImg: Fill ImageItem");
    if (!FillImageItem(PRIMARY_IMG, itemPrimaryImg, data, size)) {
        HDF_LOGE("%{public}s: Fill itemPrimaryImg failed\n", __func__);
        return false;
    }
    inputImgs_.emplace_back(itemPrimaryImg);
    HDF_LOGI("AssembleParamForPrimaryImg: Fill OtherImg");
    if (AssembleParamForOtherImg(itemPrimaryImg.id, data, size)) {
        HDF_LOGI("AssembleParamForPrimaryImg: Fill MetaData");
        return AssembleParamForMetaData(itemPrimaryImg.id, data, size);
    }
    return true;
}

bool HeifEncodeHelper::FillMetaItem(MetaType type, MetaItem& item, uint8_t *data, size_t &size)
{
    uint8_t *dataEnd = data + size - 1;
    item.itemName = "";
    if (dataEnd < data + sizeof(item.id)) {
        return false;
    }
    item.id = ToUint32(data);
    data += sizeof(item.id);
    size -= sizeof(item.id);
    item.properties = {};

    if (type == USER_DATA) {
        static constexpr char USER_DATA_LABEL[] = "userdata";
        item.itemName = USER_DATA_LABEL;
        
        if (dataEnd < data + sizeof(uint8_t)) {
            return false;
        }
        uint8_t propertiesSize = *data;
        data += sizeof(propertiesSize);
        size -= sizeof(propertiesSize);

        if (dataEnd < data + propertiesSize) {
            return false;
        }

        while (propertiesSize--) {
            item.properties.emplace_back(*data);
            data += sizeof(uint8_t);
            size -= sizeof(uint8_t);
        }
    } else if (type == EXIF_DATA) {
        static constexpr char EXIF_LABEL[] = "exif";
        item.itemName = EXIF_LABEL;
    }
    item.data = bufferHelper_.CreateSharedBuffer(data, size);
    return (item.data.fd >= 0);
}

bool HeifEncodeHelper::AssembleParamForMetaData(uint32_t primaryImgId, uint8_t *data, size_t &size)
{
    HDF_LOGI("AssembleParamForMetaData");
    uint8_t* dataEnd = data + size - 1;
    if (dataEnd < data + sizeof(uint8_t)) {
        return false;
    }
    uint8_t decision = (*data) % 2;
    data += sizeof(decision);
    size -= sizeof(decision);
    if (decision) {
        HDF_LOGI("add exif");
        MetaItem metaExifData;
        HDF_LOGI("Fill Meta Item");
        IF_TRUE_RETURN_VAL(!FillMetaItem(EXIF_DATA, metaExifData, data, size), false);
        inputMetas_.emplace_back(metaExifData);
        ItemRef refItem1 = {
            .type = CDSC,
            .auxType = "",
            .from = metaExifData.id,
            .to = {primaryImgId}
        } ;
        ItemRef newRefIt1 = FillRefItem(refItem1, data, size);
        refs_.emplace_back(newRefIt1);
        HDF_LOGI("Fill EXIF Data Succesfully");
    } else {
        HDF_LOGI("add userData");
        MetaItem metaUserData;
        HDF_LOGI("Fill Meta Item");
        IF_TRUE_RETURN_VAL(!FillMetaItem(USER_DATA, metaUserData, data, size), false);
        inputMetas_.emplace_back(metaUserData);
        ItemRef refItem2 = {
            .type = CDSC,
            .auxType = "",
            .from = metaUserData.id,
            .to = {primaryImgId}
        } ;
        ItemRef newRefIt2 = FillRefItem(refItem2, data, size);
        refs_.emplace_back(newRefIt2);
        HDF_LOGI("Fill USER Data Succesfully");
    }
    return true;
}

}
