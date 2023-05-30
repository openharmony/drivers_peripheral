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

#ifndef HOS_CAMERA_EXIF_UTILS_H
#define HOS_CAMERA_EXIF_UTILS_H

#include "libexif/exif-data.h"

using int32_t = signed int;
using uint32_t = unsigned int;

using exif_data = struct {
    double latitude;
    double longitude;
    double altitude;
    int32_t frame_size;
};

using data_info = struct {
    unsigned char *dataBuffer;
    int32_t dataBufferSize;
};

enum RetCode : int32_t {
    RC_OK = 0,
    RC_ERROR,
};

enum LatOrLong : int32_t {
    LATITUDE_TYPE = 0,
    LONGITUDE_TYPE,
};

using exif_rational = struct {
    int32_t numerator;
    int32_t denominator;
};

namespace OHOS::Camera {
class ExifUtils {
public:
    static uint32_t AddCustomExifInfo(exif_data info, void *address, int32_t &outPutSize);

private:
    static void ConvertGpsDataToDms(double number, int32_t *degrees, int32_t *minutes, int32_t *seconds);
    static void ConvertAltitudeToRational(double altitude, exif_rational &outPutAltitude);
    static uint32_t AddLatOrLongInfo(ExifData *exif, double number, LatOrLong latOrLongType);
    static uint32_t AddAltitudeInfo(ExifData *exif, double altitude);
    static uint32_t IsJpegPicture(unsigned char *dataBuffer, int32_t dataBufferSize, void *address);
    static uint32_t PackageJpeg(unsigned char *tempBuffer, int32_t totalTempBufferSize, unsigned char *exifData,
        unsigned int exifDataLength, data_info sourceData);
};
}  // namespace OHOS::Camera
#endif
