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

#ifndef CAMERA_COMMON_H
#define CAMERA_COMMON_H

#include <stream.h>
#include <string>
#include <cstdlib>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <vector>
#include <camera/camera_product.h>
#include <hdf_base.h>
#include <hdf_io_service_if.h>
#include <hdf_log.h>
#include <hdf_sbuf.h>

namespace OHOS::Camera {

#define DEVICE_NAME_NUM 20
#define DRIVER_NAME_NUM 16
#define NAME_SIZE 32
#define BUFFER_TYPE_MAX_NUM 3
#define FORMAT_TYPE_MAX_NUM 32
#define CAMERA_DEVICE_MAX_NUM 4
#define DESCRIPTION_NAME_NAME 50

#define CHECK_SBUF_RET(param) do { \
    if ((param) == nullptr) { \
        HDF_LOGE("%{public}s: fail to obtain sbuf, line: %{public}d", __func__, __LINE__); \
        return HDF_FAILURE; \
    } \
} while (0)

#define CHECK_RETURN_RESULT(ret) do { \
    if ((ret) != 0) { \
        HDF_LOGE("%{public}s: failed, ret = %{public}d, line: %{public}d", __func__, ret, __LINE__); \
        return ret; \
    } \
} while (0)

enum CameraFmtCmd : uint32_t {
    CMD_CAMERA_GET_FORMAT,
    CMD_CAMERA_SET_FORMAT,
    CMD_CAMERA_SET_CROP,
    CMD_CAMERA_GET_CROP,
    CMD_CAMERA_SET_FPS,
    CMD_CAMERA_GET_FPS,
};

struct SensorInfo {
    uint8_t mode;
    char driverName[DRIVER_NAME_NUM];
    uint8_t id;
    uint8_t exposure;
    uint8_t mirror;
    uint8_t gain;
};

struct IspInfo {
    uint8_t mode;
    char driverName[DRIVER_NAME_NUM];
    uint8_t id;
    uint8_t brightness;
    uint8_t contrast;
    uint8_t saturation;
    uint8_t hue;
    uint8_t sharpness;
    uint8_t gain;
    uint8_t gamma;
    uint8_t whiteBalance;
};

struct VcmInfo {
    uint8_t mode;
    char driverName[DRIVER_NAME_NUM];
    uint8_t id;
    uint8_t focus;
    uint8_t autoFocus;
    uint8_t zoom;
    uint32_t zoomMaxNum;
};

struct LensInfo {
    uint8_t mode;
    char driverName[DRIVER_NAME_NUM];
    uint8_t id;
    uint8_t aperture;
};

struct FlashInfo {
    uint8_t mode;
    char driverName[DRIVER_NAME_NUM];
    uint8_t id;
    uint8_t flashMode;
    uint8_t flashIntensity;
};

struct VdiStreamInfo {
    uint8_t mode;
    char driverName[DRIVER_NAME_NUM];
    uint8_t id;
    uint32_t heightMaxNum;
    uint32_t widthMaxNum;
    uint32_t frameRateMaxNum;
    uint32_t bufferTypeNum;
    uint8_t bufferCount;
    uint32_t bufferType[BUFFER_TYPE_MAX_NUM];
};

struct DeviceaInfo {
    struct SensorInfo sensor;
    struct IspInfo isp;
    struct VcmInfo vcm;
    struct LensInfo lens;
    struct FlashInfo flash;
    struct VdiStreamInfo stream;
};

struct CameraFeature {
    uint32_t type;
    int32_t permissionId;
    char deviceName[DEVICE_NAME_NUM];
    char driverName[DRIVER_NAME_NUM];
};

struct CameraFract {
    uint32_t numerator;
    uint32_t denominator;
};

struct CameraRect {
    int32_t left;
    int32_t top;
    uint32_t width;
    uint32_t height;
};

struct CameraFmtDesc {
    uint32_t index;                 /* Format number */
    uint32_t type;                  /* enum camera_buf_type */
    char description[NAME_SIZE];    /* Description string */
    uint32_t pixelFormat;           /* frame format */
    uint32_t width;                 /* frame width */
    uint32_t height;                /* frame height */
    uint32_t sizeImage;
    struct CameraFract fps;
};

struct CameraFrmSizeDesc {
    uint32_t index;         /* Frame size number */
    uint32_t pixelFormat;   /* Pixel format */
    uint32_t type;          /* Frame size type the device supports. */
    uint32_t width;         /* Frame width [pixel] */
    uint32_t height;        /* Frame height [pixel] */
};

struct CameraFrmRatioDesc {
    uint32_t index;         /* Frame format index */
    uint32_t pixelFormat;   /* Pixel format */
    uint32_t width;         /* Frame width */
    uint32_t height;        /* Frame height */
    uint32_t numerator;
    uint32_t denominator;
};

struct CtrlCapInfo {
    uint32_t ctrlId;
    uint32_t max;
    uint32_t min;
    uint32_t step;
    uint32_t defaultValue;
};

struct CameraControlConfig {
    uint32_t id;
    uint32_t value;
    struct CtrlCapInfo ctrlInfo;
};

using CameraCtrl = struct CameraDeviceControl {
    struct CameraControlConfig control;
    struct CameraRect crop;
    struct CameraFmtDesc fmtdesc;
};

struct CameraCapability {
    char driver[DRIVER_NAME_NUM];   /* name of the driver module */
    char card[NAME_SIZE];           /* name of the card */
    char busInfo[NAME_SIZE];        /* name of the bus */
    uint32_t capabilities;          /* capabilities of the physical device as a whole */
};

RetCode SendCameraCmd(const uint32_t cmd, struct HdfSBuf *reqData, struct HdfSBuf *respData);
int32_t CameraDriverClientInit(void);
int32_t SendDeviceInfo(struct HdfSBuf *reqData, struct CameraFeature feature, bool state);
using BufCallback = std::function<void(std::shared_ptr<FrameSpec>)>;

} // namespace OHOS::Camera
#endif // CAMERA_COMMON_H
