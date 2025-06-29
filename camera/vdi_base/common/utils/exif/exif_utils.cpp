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

#include "exif_utils.h"
#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <iostream>
#include <camera.h>
#include "securec.h"

namespace OHOS::Camera {
static const unsigned int IMAGE_DATA_OFFSET = 20;

// Raw exif header data
static const unsigned char EXIF_HEADER[] = {0xff, 0xd8, 0xff, 0xe1};

static const unsigned int EXIF_HEADER_LENGTH = sizeof(EXIF_HEADER);

constexpr uint32_t DEGREE_INDEX = 0; // Index
constexpr uint32_t MINUTE_INDEX = 1; // Index
constexpr uint32_t SECOND_INDEX = 2; // Index

#define FILE_BYTE_ORDER EXIF_BYTE_ORDER_INTEL

static ExifEntry *CreateTag(ExifData *exif, ExifIfd ifd, ExifTag tag, size_t len, ExifFormat format)
{
    void *buf = nullptr;
    ExifEntry *entry = nullptr;

    ExifMem *mem = exif_mem_new_default();
    assert(mem != NULL);

    entry = exif_entry_new_mem(mem);
    assert(entry != nullptr);

    buf = exif_mem_alloc(mem, len);
    assert(buf != nullptr);

    if (!entry) {
        return nullptr;
    }
    entry->data = static_cast<unsigned char*>(buf);
    entry->size = len;
    entry->tag = tag;
    entry->components = len;
    entry->format = format;

    exif_content_add_entry(exif->ifd[ifd], entry);

    exif_mem_unref(mem);
    exif_entry_unref(entry);

    return entry;
}

uint32_t ExifUtils::GetGpsRef(LatOrLong latOrLongType, double number, char *gpsRef, int length)
{
    char north[2] = "N";
    char south[2] = "S";
    char east[2] = "E";
    char west[2] = "W";

    if (gpsRef == nullptr) {
        CAMERA_LOGE("%{public}s gpsRef is null.", __FUNCTION__);
        return RC_ERROR;
    }

    if (latOrLongType == LATITUDE_TYPE) {
        if (number > 0) {
            if (strncpy_s(gpsRef, length, north, strlen(north)) != 0) {
                CAMERA_LOGE("%{public}s exif strncpy_s failed.", __FUNCTION__);
                return RC_ERROR;
            }
        } else {
            if (strncpy_s(gpsRef, length, south, strlen(south)) != 0) {
                CAMERA_LOGE("%{public}s exif strncpy_s failed.", __FUNCTION__);
                return RC_ERROR;
            }
        }
    } else {
        if (number > 0) {
            if (strncpy_s(gpsRef, length, east, strlen(east)) != 0) {
                CAMERA_LOGE("%{public}s exif strncpy_s failed.", __FUNCTION__);
                return RC_ERROR;
            }
        } else {
            if (strncpy_s(gpsRef, length, west, strlen(west)) != 0) {
                CAMERA_LOGE("%{public}s exif strncpy_s failed.", __FUNCTION__);
                return RC_ERROR;
            }
        }
    }

    return RC_OK;
}

uint32_t ExifUtils::AddLatOrLongInfo(ExifData *exif,
    double number, LatOrLong latOrLongType)
{
    ExifEntry *entry = nullptr;
    char gpsRef[2] = {0}; // Index
    ExifRational gpsRational[3]; // Index
    int32_t degree = 0;
    int32_t minute = 0;
    int32_t second = 0;

    if (GetGpsRef(latOrLongType, number, gpsRef, sizeof(gpsRef)) != RC_OK) {
        CAMERA_LOGE("%{public}s exif GetGpsRef failed.", __FUNCTION__);
        return RC_ERROR;
    }

    ConvertGpsDataToDms(number, &degree, &minute, &second);
    gpsRational[DEGREE_INDEX].numerator = static_cast<uint32_t>(degree); // Index
    gpsRational[DEGREE_INDEX].denominator = 1;
    gpsRational[MINUTE_INDEX].numerator = static_cast<uint32_t>(minute); // Index
    gpsRational[MINUTE_INDEX].denominator = 1;
    gpsRational[SECOND_INDEX].numerator = static_cast<uint32_t>(second); // Index
    gpsRational[SECOND_INDEX].denominator = 1;

    // LATITUDE_TYPE/LONGITUDE_TYPE reference
    if (latOrLongType == LATITUDE_TYPE) {
        entry = CreateTag(exif, EXIF_IFD_GPS, EXIF_TAG_GPS_LATITUDE_REF, sizeof(gpsRef), EXIF_FORMAT_ASCII);
    } else {
        entry = CreateTag(exif, EXIF_IFD_GPS, EXIF_TAG_GPS_LONGITUDE_REF, sizeof(gpsRef), EXIF_FORMAT_ASCII);
    }
    if (entry == nullptr) {
        CAMERA_LOGE("%{public}s CreateTag failed.", __FUNCTION__);
        return RC_ERROR;
    }
    if (memcpy_s(entry->data, entry->size, gpsRef, sizeof(gpsRef)) != 0) {
        CAMERA_LOGE("%{public}s exif memcpy_s failed.", __FUNCTION__);
        return RC_ERROR;
    }
    // LATITUDE_TYPE/LONGITUDE_TYPE value
    constexpr uint32_t gpsDmsCount = 3;
    if (latOrLongType == LATITUDE_TYPE) {
        entry = CreateTag(exif, EXIF_IFD_GPS, EXIF_TAG_GPS_LATITUDE,
            gpsDmsCount * exif_format_get_size(EXIF_FORMAT_RATIONAL),
            EXIF_FORMAT_RATIONAL);
    } else {
        entry = CreateTag(exif, EXIF_IFD_GPS, EXIF_TAG_GPS_LONGITUDE,
            gpsDmsCount * exif_format_get_size(EXIF_FORMAT_RATIONAL),
            EXIF_FORMAT_RATIONAL);
    }
    exif_set_rational(entry->data, FILE_BYTE_ORDER, gpsRational[0]);
    exif_set_rational(entry->data + 8, FILE_BYTE_ORDER, gpsRational[1]); // 8bit
    exif_set_rational(entry->data + 16, FILE_BYTE_ORDER, gpsRational[2]); // 16bit
    return RC_OK;
}

uint32_t ExifUtils::AddAltitudeInfo(ExifData *exif, double altitude)
{
    unsigned char seaLevelFlag = 0;
    ExifEntry *entry = nullptr;
    ExifRational gpsAltitudeRational;
    exif_rational altitudeRational;

    if (altitude > 0) {
        seaLevelFlag = 0;
    } else {
        altitude = abs(altitude);
        seaLevelFlag = 1;
    }
    ConvertAltitudeToRational(altitude, altitudeRational);
    gpsAltitudeRational.numerator = altitudeRational.numerator;
    gpsAltitudeRational.denominator = altitudeRational.denominator;
    // Altitude reference
    entry = CreateTag(exif, EXIF_IFD_GPS, EXIF_TAG_GPS_ALTITUDE_REF, sizeof(seaLevelFlag), EXIF_FORMAT_BYTE);
    exif_set_short(entry->data, FILE_BYTE_ORDER, seaLevelFlag);

    // Altitude value
    entry = CreateTag(exif, EXIF_IFD_GPS, EXIF_TAG_GPS_ALTITUDE, exif_format_get_size(EXIF_FORMAT_RATIONAL),
        EXIF_FORMAT_RATIONAL);
    exif_set_rational(entry->data, FILE_BYTE_ORDER, gpsAltitudeRational);
    return RC_OK;
}

uint32_t ExifUtils::IsJpegPicture(unsigned char *dataBuffer, int32_t dataBufferSize, void *address)
{
    if (memcpy_s(dataBuffer, dataBufferSize, address, dataBufferSize) != 0) {
        CAMERA_LOGE("%{public}s exif memcpy_s failed.", __FUNCTION__);
        return RC_ERROR;
    }

    if (!(dataBuffer[0] == 0xFF && dataBuffer[1] == 0xD8)) {
        CAMERA_LOGE("%{public}s not jpeg file,won't add exif for it.", __FUNCTION__);
        return RC_ERROR;
    }

    if ((dataBuffer[6] == 'E' && dataBuffer[7] == 'x' && dataBuffer[8] == 'i' && dataBuffer[9] == 'f')) { // Index
        CAMERA_LOGE("%{public}s already add exif, won't overwrite exif info.", __FUNCTION__);
        return RC_ERROR;
    }
    return RC_OK;
}

uint32_t ExifUtils::PackageJpeg(unsigned char *tempBuffer, int32_t totalTempBufferSize, unsigned char *exifData,
    unsigned int exifDataLength, data_info sourceData)
{
    unsigned char orderValue = 0;
    unsigned char value = 0;
    constexpr uint32_t exifBlockLength = 2;
    orderValue = (exifDataLength + exifBlockLength) >> 8; // 8bit
    value = (exifDataLength + exifBlockLength) & 0xff;
    if (memcpy_s(tempBuffer, totalTempBufferSize, EXIF_HEADER, EXIF_HEADER_LENGTH) != 0) {
        CAMERA_LOGE("%{public}s exif memcpy_s failed.", __FUNCTION__);
        return RC_ERROR;
    }
    if (memcpy_s(tempBuffer + EXIF_HEADER_LENGTH, totalTempBufferSize, &orderValue,
        sizeof(orderValue)) != 0) {
        CAMERA_LOGE("%{public}s exif memcpy_s failed.", __FUNCTION__);
        return RC_ERROR;
    }
    if (memcpy_s(tempBuffer + EXIF_HEADER_LENGTH + sizeof(orderValue), totalTempBufferSize, &value,
        sizeof(value)) != 0) {
        CAMERA_LOGE("%{public}s exif memcpy_s failed.", __FUNCTION__);
        return RC_ERROR;
    }
    if (memcpy_s(tempBuffer + EXIF_HEADER_LENGTH + sizeof(orderValue) + sizeof(value), totalTempBufferSize,
        exifData, exifDataLength) != 0) {
        CAMERA_LOGE("%{public}s exif memcpy_s failed.", __FUNCTION__);
        return RC_ERROR;
    }
    if (memcpy_s(tempBuffer + EXIF_HEADER_LENGTH + sizeof(orderValue) + sizeof(value) + exifDataLength,
        totalTempBufferSize,
        sourceData.dataBuffer + IMAGE_DATA_OFFSET,
        sourceData.dataBufferSize - IMAGE_DATA_OFFSET) != 0) {
        CAMERA_LOGE("%{public}s exif memcpy_s failed.", __FUNCTION__);
        return RC_ERROR;
    }
    return RC_OK;
}

uint32_t ExifUtils::SetExifData(exif_data info, ExifData *exif,
    unsigned char **exifData, unsigned int *exifDataLength)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(exif, RC_ERROR);

    exif_data_set_option(exif, EXIF_DATA_OPTION_FOLLOW_SPECIFICATION);
    exif_data_set_data_type(exif, EXIF_DATA_TYPE_COMPRESSED);
    exif_data_set_byte_order(exif, FILE_BYTE_ORDER);
    if (AddLatOrLongInfo(exif, info.latitude, LATITUDE_TYPE) != RC_OK) {
        return RC_ERROR;
    }
    if (AddLatOrLongInfo(exif, info.longitude, LONGITUDE_TYPE) != RC_OK) {
        return RC_ERROR;
    }
    if (AddAltitudeInfo(exif, info.altitude) != RC_OK) {
        return RC_ERROR;
    }
    exif_data_save_data(exif, exifData, exifDataLength);

    return RC_OK;
}

void ExifUtils::FreeResource(unsigned char *dataBuffer, unsigned char *tempBuffer,
    ExifData *exif, unsigned char *exifData)
{
    if (dataBuffer != nullptr) {
        free(dataBuffer);
    }
    if (tempBuffer != nullptr) {
        free(tempBuffer);
    }
    free(exifData);
    exif_data_unref(exif);
}

uint32_t ExifUtils::AddCustomExifInfo(exif_data info, void *address, int32_t &outPutSize)
{
    uint32_t ret = RC_ERROR;
    unsigned char *exifData = nullptr;
    unsigned int exifDataLength = 0;
    ExifData *exif = nullptr;
    unsigned char *dataBuffer = nullptr;
    unsigned char *tempBuffer = nullptr;
    int32_t totalTempBufferSize = 0;
    int32_t dataBufferSize = info.frame_size;
    constexpr uint32_t exifBlockLength = 2;

    exif = exif_data_new();
    if (!exif) {
        CAMERA_LOGE("%{public}s exif new failed.", __FUNCTION__);
        return ret;
    }

    if (SetExifData(info, exif, &exifData, &exifDataLength) != RC_OK) {
        CAMERA_LOGE("%{public}s exif SetExifData failed.", __FUNCTION__);
        return ret;
    }

    dataBuffer = static_cast<unsigned char *>(malloc(dataBufferSize));
    if (!dataBuffer) {
        CAMERA_LOGE("%{public}s Allocate data buf failed.", __FUNCTION__);
        return ret;
    }
    data_info sourceData;
    sourceData.dataBuffer = dataBuffer;
    sourceData.dataBufferSize = dataBufferSize;

    // Check buffer whether is valid
    if (IsJpegPicture(dataBuffer, dataBufferSize, address) == RC_ERROR) {
        goto error;
    }
    totalTempBufferSize = static_cast<int32_t>(EXIF_HEADER_LENGTH + exifBlockLength +  exifDataLength +
        (static_cast<uint32_t>(dataBufferSize) - IMAGE_DATA_OFFSET));
    tempBuffer = static_cast<unsigned char *>(malloc(totalTempBufferSize));
    if (!tempBuffer) {
        CAMERA_LOGE("%{public}s Allocate temp buf failed.", __FUNCTION__);
        return ret;
    }
    ret = PackageJpeg(tempBuffer, totalTempBufferSize, exifData, exifDataLength, sourceData);
    outPutSize = totalTempBufferSize;
    if (memcpy_s(address, totalTempBufferSize, tempBuffer, totalTempBufferSize) != 0) {
        CAMERA_LOGE("%{public}s exif memcpy_s failed.", __FUNCTION__);
        return RC_ERROR;
    }

error:
    FreeResource(dataBuffer, tempBuffer, exif, exifData);

    return ret;
}

void ExifUtils::ConvertGpsDataToDms(double number, int32_t *degrees, int32_t *minutes, int32_t *seconds)
{
    number = abs(number);
    double  approximateNumber = 0.0;
    constexpr uint32_t timePeriod = 60;
    constexpr uint32_t roundingValue = 5;
    constexpr uint32_t precision = 10;
    int32_t hour = static_cast<int32_t>(number);
    int32_t minute = static_cast<int32_t>((number - hour) * timePeriod);
    int32_t second = static_cast<int32_t>(((number - hour) * timePeriod - minute) * timePeriod);

    approximateNumber = ((number - hour) * timePeriod - minute) * timePeriod - second;
    if (static_cast<int32_t>(approximateNumber * precision) >= roundingValue) {
        second = second + 1;
    }
    if (second == timePeriod) {
        second = 0;
        minute = minute + 1;
    }
    if (minute == timePeriod) {
        minute = 0;
        hour = hour + 1;
    }
    *degrees = hour;
    *minutes = minute;
    *seconds = second;

    return;
}

void ExifUtils::ConvertAltitudeToRational(double altitude, exif_rational &outPutAltitude)
{
    long long numerator = 0;
    long long denominator = 1;
    bool isSeparator = false;
    uint32_t count = 0;
    std::string strData = "";
    strData = std::to_string(altitude);
    CAMERA_LOGI("%{public}s strData = %{public}s", __FUNCTION__, strData.c_str());

    count = strData.length();
    CAMERA_LOGI("%{public}s count = %{public}d", __FUNCTION__, count);
    constexpr uint32_t digitPosition = 10;
    for (uint32_t i = 0; i < count; i++) {
        char character = strData[i];
        if (character == '.') {
            isSeparator = true;
        } else {
            numerator = numerator * digitPosition + (character  - '0');
            CAMERA_LOGI("%{public}s numerator =  %{public}lld", __FUNCTION__, numerator);
            if (isSeparator) {
                denominator *= digitPosition;
                CAMERA_LOGI("%{public}s denominator =  %{public}lld", __FUNCTION__, denominator);
            }
        }
    }
    constexpr uint32_t commonDivisor = 2;
    constexpr uint32_t resetValue = 1;
    for (int i = commonDivisor; static_cast<long long>(i) < numerator; i++) {
        if ((numerator % i == 0) && (denominator % i == 0)) {
            numerator /= i;
            denominator /= i;
            i = resetValue;
        }
    }

    outPutAltitude.numerator = numerator;
    outPutAltitude.denominator = denominator;
    CAMERA_LOGI("%{public}s outPutAltitude.numerator =  %{public}d and outPutAltitude.denominator =  %{public}d",
        __FUNCTION__, outPutAltitude.numerator, outPutAltitude.denominator);
}
}  // namespace OHOS::Camera
