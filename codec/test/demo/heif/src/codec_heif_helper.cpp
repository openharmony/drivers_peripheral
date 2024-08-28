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

#include "codec_heif_helper.h"

namespace OHOS::VDI::HEIF {
using namespace OHOS::HDI::Codec::Image::V2_0;
using namespace std;

void HeifEncoderHelper::DoEncode()
{
    HDF_LOGI("start heif encode");
    Reset();
    bool flag = false;
    if (encodeOpt_.gainMapPath.length() > 0) {
        HDF_LOGI("AssembleParamForTmap");
        flag = AssembleParamForTmap();
    } else {
        HDF_LOGI("AssembleParamForPrimaryImg");
        flag = AssembleParamForPrimaryImg();
    }
    IF_TRUE_RETURN(!flag);
    HDF_LOGI("get ICodecImage");
    sptr<ICodecImage> hdiHeifEncoder = ICodecImage::Get();
    IF_TRUE_RETURN_WITH_MSG(hdiHeifEncoder == nullptr, "failed to get ICodecImage");
    SharedBuffer output;
    IF_TRUE_RETURN(!AllocOutputBuffer(output));
    uint32_t filledLen = 0;
    HDF_LOGI("DoHeifEncode");
    int32_t ret = hdiHeifEncoder->DoHeifEncode(inputImgs_, inputMetas_, refs_, output, filledLen);
    if (ret == HDF_SUCCESS) {
        HDF_LOGI("heif encode succeed");
        output.filledLen = filledLen;
        bufferHelper_.DumpBuffer(encodeOpt_.outputPath, output);
    } else {
        HDF_LOGE("heif encode failed");
    }
    close(output.fd);
}

bool HeifEncoderHelper::AllocOutputBuffer(SharedBuffer& output)
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


void HeifEncoderHelper::Reset()
{
    inputImgs_.clear();
    inputMetas_.clear();
    refs_.clear();
}

bool HeifEncoderHelper::AddPropOnlyForTmap(ByteWriter& bw)
{
    MasteringDisplayColourVolume clrVol = {
        .displayPrimariesRX = 1,
        .displayPrimariesRY = 2,
        .displayPrimariesGX = 3,
        .displayPrimariesGY = 4,
        .displayPrimariesBX = 5,
        .displayPrimariesBY = 6,
        .whitePointX = 0,
        .whitePointY = 0,
        .maxDisplayMasteringLuminance = 0,
        .minDisplayMasteringLuminance = 0
    };
    IF_TRUE_RETURN_VAL_WITH_MSG(!bw.AddData<MasteringDisplayColourVolume>(MASTER_DISPLAY_COLOR_VOLUME, clrVol), false,
                                "failed to add MASTER_DISPLAY_COLOR_VOLUME");
    HDF_LOGI("add MASTER_DISPLAY_COLOR_VOLUME succeed");

    ToneMapMetadata tmapMeta;
    static constexpr uint8_t MULTI_CHANNEL = 3;
    tmapMeta.channelCnt = MULTI_CHANNEL;
    tmapMeta.useBaseColorSpace = true;
    tmapMeta.baseHdrHeadroom = {12, 23};
    tmapMeta.alternateHdrHeadroom = {36, 62};
    tmapMeta.channels1 = {
        .gainMapMin = {5, 21},
        .gainMapMax = {5, 7},
        .gamma = {2, 7},
        .baseOffset = {1, 3},
        .alternateOffset = {1, 7}
    };
    tmapMeta.channels2 = {
        .gainMapMin = {5, 21},
        .gainMapMax = {5, 7},
        .gamma = {2, 7},
        .baseOffset = {1, 3},
        .alternateOffset = {1, 7}
    };
    tmapMeta.channels3 = {
        .gainMapMin = {5, 21},
        .gainMapMax = {5, 7},
        .gamma = {2, 7},
        .baseOffset = {1, 3},
        .alternateOffset = {1, 7}
    };
    IF_TRUE_RETURN_VAL_WITH_MSG(!bw.AddData<ToneMapMetadata>(TONE_MAP_METADATA, tmapMeta), false,
                                "failed to add TONE_MAP_METADATA");
    HDF_LOGI("add TONE_MAP_METADATA succeed");
    return true;
}

bool HeifEncoderHelper::AddPropMirrorAndRotate(ByteWriter& bw)
{
    static map<ImageMirror, bool> mirrorMap = {
        { ImageMirror::HORIZONTAL, false },
        { ImageMirror::VERTICAL,   true },
    };
    auto iterMirror = mirrorMap.find(encodeOpt_.mirrorInfo);
    if (iterMirror != mirrorMap.end()) {
        bool isMirrorVertical = iterMirror->second;
        IF_TRUE_RETURN_VAL_WITH_MSG(!bw.AddData<bool>(MIRROR_INFO, isMirrorVertical), false,
                                    "failed to add MIRROR_INFO");
        HDF_LOGI("add MIRROR_INFO succeed");
    }

    static map<ImageRotation, uint32_t> rotateMap = {
        { ImageRotation::ANTI_CLOCKWISE_90,  90 },
        { ImageRotation::ANTI_CLOCKWISE_180, 180 },
        { ImageRotation::ANTI_CLOCKWISE_270, 270 },
    };
    auto iterRotate = rotateMap.find(encodeOpt_.rotateInfo);
    if (iterRotate != rotateMap.end()) {
        uint32_t rotateDegree = iterRotate->second;
        IF_TRUE_RETURN_VAL_WITH_MSG(!bw.AddData<uint32_t>(ROTATE_INFO, rotateDegree), false,
                                    "failed to add ROTATE_INFO");
        HDF_LOGI("add ROTATE_INFO succeed");
    }
    return true;
}

bool HeifEncoderHelper::CreateImgParam(ImgType type, vector<uint8_t>& props)
{
    ByteWriter bw;

    if (type != T_MAP) {
        IF_TRUE_RETURN_VAL(!AddPropMirrorAndRotate(bw), false);
    }

    ColorType clrType = encodeOpt_.iccProfilePath.length() > 0 ? PROF : NCLX;
    IF_TRUE_RETURN_VAL_WITH_MSG(!bw.AddData<ColorType>(COLOR_TYPE, clrType), false, "failed to add COLOR_TYPE");
    HDF_LOGI("add COLOR_TYPE succeed");

    if (clrType == NCLX) {
        ColourInfo clrInfo = {
            .colourPrimaries = 2,
            .transferCharacteristics = 2,
            .matrixCoefficients = 2,
            .fullRangeFlag = false
        };
        IF_TRUE_RETURN_VAL_WITH_MSG(!bw.AddData<ColourInfo>(COLOR_INFO, clrInfo), false, "failed to add COLOR_INFO");
        HDF_LOGI("add COLOR_INFO succeed");
    }

    if (type == T_MAP || type == PRIMARY_IMG) {
        ContentLightLevel level = {
            .maxContentLightLevel = 1,
            .maxPicAverageLightLevel = 2
        };
        IF_TRUE_RETURN_VAL_WITH_MSG(!bw.AddData<ContentLightLevel>(CONTENT_LIGHT_LEVEL, level), false,
                                    "failed to add CONTENT_LIGHT_LEVEL");
        HDF_LOGI("add CONTENT_LIGHT_LEVEL succeed");
    }

    if (type == T_MAP) {
        IF_TRUE_RETURN_VAL(!AddPropOnlyForTmap(bw), false);
    }

    IF_TRUE_RETURN_VAL_WITH_MSG(!bw.Finalize(props), false, "failed to write img prop");
    return true;
}

bool HeifEncoderHelper::FillImageItem(ImgType type, ImageItem& item)
{
    map<ImgType, string> typeToFile = {
        { PRIMARY_IMG,   encodeOpt_.primaryImgPath },
        { AUXILIARY_IMG, encodeOpt_.auxiliaryImgPath },
        { THUMBNAIL_IMG, encodeOpt_.thumbnailImgPath },
        { GAIN_MAP,      encodeOpt_.gainMapPath },
        { T_MAP,         "" },
    };
    item.itemName = "";
    item.id = GetNextId();
    item.sharedProperties = {
        .fd = -1,
        .filledLen = 0,
        .capacity = 0
    };
    item.pixelBuffer = bufferHelper_.CreateImgBuffer(typeToFile[type]);
    IF_TRUE_RETURN_VAL((type != T_MAP && item.pixelBuffer == nullptr), false);
    item.isPrimary = (type == PRIMARY_IMG);
    item.isHidden = (type != PRIMARY_IMG);
    item.compressType = (type == T_MAP ? "none" : "hevc");
    static constexpr uint32_t ENCODE_QUALITY = 85;
    item.quality = ENCODE_QUALITY;
    IF_TRUE_RETURN_VAL(!CreateImgParam(type, item.liteProperties), false);
    map<PropertyType, string> sharedProps;
    if (encodeOpt_.iccProfilePath.length() > 0) {
        HDF_LOGI("add ICC_PROFILE");
        sharedProps[ICC_PROFILE] = encodeOpt_.iccProfilePath;
    }
    if (type == T_MAP && encodeOpt_.it35Path.length() > 0) {
        HDF_LOGI("add IT35_INFO");
        sharedProps[IT35_INFO] = encodeOpt_.it35Path;
    }
    IF_TRUE_RETURN_VAL(sharedProps.empty(), true);
    item.sharedProperties = bufferHelper_.CreateSharedBuffer(sharedProps);
    return (item.sharedProperties.fd >= 0);
}

bool HeifEncoderHelper::AssembleParamForOtherImg(uint32_t primaryImgId)
{
    if (encodeOpt_.auxiliaryImgPath.length() > 0) {
        ImageItem itemAuxlImg;
        IF_TRUE_RETURN_VAL(!FillImageItem(AUXILIARY_IMG, itemAuxlImg), false);
        inputImgs_.emplace_back(itemAuxlImg);
        refs_.emplace_back(ItemRef {
            .type = AUXL,
            .auxType = "",
            .from = itemAuxlImg.id,
            .to = {primaryImgId}
        });
    }
    if (encodeOpt_.thumbnailImgPath.length() > 0) {
        ImageItem itemThmbImg;
        IF_TRUE_RETURN_VAL(!FillImageItem(THUMBNAIL_IMG, itemThmbImg), false);
        inputImgs_.emplace_back(itemThmbImg);
        refs_.emplace_back(ItemRef {
            .type = THMB,
            .auxType = "",
            .from = itemThmbImg.id,
            .to = {primaryImgId}
        });
    }
    return true;
}

bool HeifEncoderHelper::AssembleParamForTmap()
{
    ImageItem itemTmap;
    ImageItem itemPrimaryImg;
    ImageItem itemGainMap;
    IF_TRUE_RETURN_VAL(!FillImageItem(T_MAP, itemTmap), false);
    IF_TRUE_RETURN_VAL(!FillImageItem(PRIMARY_IMG, itemPrimaryImg), false);
    IF_TRUE_RETURN_VAL(!FillImageItem(GAIN_MAP, itemGainMap), false);
    inputImgs_.emplace_back(itemTmap);
    inputImgs_.emplace_back(itemPrimaryImg);
    inputImgs_.emplace_back(itemGainMap);
    refs_.emplace_back(ItemRef {
        .type = DIMG,
        .auxType = "",
        .from = itemTmap.id,
        .to = {itemPrimaryImg.id, itemGainMap.id}
    });
    if (AssembleParamForOtherImg(itemPrimaryImg.id)) {
        return AssembleParamForMetaData(itemPrimaryImg.id);
    }
    return false;
}

bool HeifEncoderHelper::AssembleParamForPrimaryImg()
{
    ImageItem itemPrimaryImg;
    IF_TRUE_RETURN_VAL(!FillImageItem(PRIMARY_IMG, itemPrimaryImg), false);
    inputImgs_.emplace_back(itemPrimaryImg);
    if (AssembleParamForOtherImg(itemPrimaryImg.id)) {
        return AssembleParamForMetaData(itemPrimaryImg.id);
    }
    return false;
}

bool HeifEncoderHelper::FillMetaItem(const string& metaFile, MetaType type, MetaItem& item)
{
    item.itemName = "";
    item.id = GetNextId();
    item.properties = {};
    if (type == USER_DATA) {
        static constexpr char USER_DATA_LABEL[] = "userdata";
        item.itemName = USER_DATA_LABEL;
        bool useCompress = true;
        ByteWriter bw;
        IF_TRUE_RETURN_VAL_WITH_MSG(!bw.AddData<bool>(USER_DATA_DO_COMPRESS, useCompress), false,
                                    "failed to add USER_DATA_DO_COMPRESS");
        IF_TRUE_RETURN_VAL_WITH_MSG(!bw.Finalize(item.properties), false, "failed to write USER_DATA_DO_COMPRESS");
    } else if (type == EXIF_DATA) {
        static constexpr char EXIF_LABEL[] = "exif";
        item.itemName = EXIF_LABEL;
    }
    item.data = bufferHelper_.CreateSharedBuffer(metaFile);
    return (item.data.fd >= 0);
}

bool HeifEncoderHelper::AssembleParamForMetaData(uint32_t primaryImgId)
{
    HDF_LOGI("AssembleParamForMetaData");
    if (encodeOpt_.exifDataPath.length() > 0) {
        HDF_LOGI("add exif: %{public}s", encodeOpt_.exifDataPath.c_str());
        MetaItem metaExifData;
        IF_TRUE_RETURN_VAL(!FillMetaItem(encodeOpt_.exifDataPath, EXIF_DATA, metaExifData), false);
        inputMetas_.emplace_back(metaExifData);
        refs_.emplace_back(ItemRef {
            .type = CDSC,
            .auxType = "",
            .from = metaExifData.id,
            .to = {primaryImgId}
        });
    }
    if (encodeOpt_.userDataPath.length() > 0) {
        HDF_LOGI("add userData: %{public}s", encodeOpt_.userDataPath.c_str());
        MetaItem metaUserData;
        IF_TRUE_RETURN_VAL(!FillMetaItem(encodeOpt_.userDataPath, USER_DATA, metaUserData), false);
        inputMetas_.emplace_back(metaUserData);
        refs_.emplace_back(ItemRef {
            .type = CDSC,
            .auxType = "",
            .from = metaUserData.id,
            .to = {primaryImgId}
        });
    }
    return true;
}
}
