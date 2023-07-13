/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_VDI_CAMERA_V1_0_TYPES_H
#define OHOS_VDI_CAMERA_V1_0_TYPES_H

#include <cstdbool>
#include <cstdint>
#include <vector>
#include "buffer_producer_sequenceable.h"

namespace OHOS {
class MessageParcel;
}

namespace OHOS {
namespace VDI {
namespace Camera {
namespace V1_0 {

using namespace OHOS;
using namespace HDI::Camera::V1_0;
using namespace OHOS::HDI::Camera::V1_0;

enum VdiCamRetCode : int32_t {
    NO_ERROR = 0,
    CAMERA_BUSY = -1,
    INSUFFICIENT_RESOURCES = -2,
    INVALID_ARGUMENT = -3,
    METHOD_NOT_SUPPORTED = -4,
    CAMERA_CLOSED = -5,
    DEVICE_ERROR = -6,
    NO_PERMISSION = -7,
};

enum VdiResultCallbackMode : int32_t {
    PER_FRAME = 0,
    ON_CHANGED = 1,
};

enum VdiOperationMode : int32_t {
    NORMAL = 0,
};

enum VdiStreamIntent : int32_t {
    PREVIEW = 0,
    VIDEO = 1,
    STILL_CAPTURE = 2,
    POST_VIEW = 3,
    ANALYZE = 4,
    CUSTOM = 5,
};

enum VdiEncodeType : int32_t {
    ENCODE_TYPE_NULL = 0,
    ENCODE_TYPE_H264 = 1,
    ENCODE_TYPE_H265 = 2,
    ENCODE_TYPE_JPEG = 3,
};

enum VdiStreamSupportType : int32_t {
    DYNAMIC_SUPPORTED = 0,
    RE_CONFIGURED_REQUIRED = 1,
    NOT_SUPPORTED = 2,
};

enum VdiCameraStatus : int32_t {
    UN_AVAILABLE = 0,
    AVAILABLE = 1,
};

enum VdiFlashlightStatus : int32_t {
    FLASHLIGHT_OFF = 0,
    FLASHLIGHT_ON = 1,
    FLASHLIGHT_UNAVAILABLE = 2,
};

enum VdiCameraEvent : int32_t {
    CAMERA_EVENT_DEVICE_ADD = 0,
    CAMERA_EVENT_DEVICE_RMV = 1,
};

enum VdiErrorType : int32_t {
    FATAL_ERROR = 0,
    REQUEST_TIMEOUT = 1,
    DRIVER_ERROR = 2,
    DEVICE_PREEMPT = 3,
    DEVICE_DISCONNECT = 4,
    DCAMERA_ERROR_BEGIN = 1024,
    DCAMERA_ERROR_DEVICE_IN_USE,
    DCAMERA_ERROR_NO_PERMISSION,
};

enum VdiStreamError : int32_t {
    UNKNOWN_ERROR = 0,
    BUFFER_LOST = 1,
};

struct VdiStreamInfo {
    int32_t streamId_;
    int32_t width_;
    int32_t height_;
    int32_t format_;
    int32_t dataspace_;
    VdiStreamIntent intent_;
    bool tunneledMode_;
    sptr<BufferProducerSequenceable> bufferQueue_;
    int32_t minFrameDuration_;
    VdiEncodeType encodeType_;
};

struct VdiStreamAttribute {
    int32_t streamId_;
    int32_t width_;
    int32_t height_;
    int32_t overrideFormat_;
    int32_t overrideDataspace_;
    int32_t producerUsage_;
    int32_t producerBufferCount_;
    int32_t maxBatchCaptureCount_;
    int32_t maxCaptureCount_;
} __attribute__ ((aligned(8)));

struct VdiCaptureInfo {
    std::vector<int32_t> streamIds_;
    std::vector<uint8_t> captureSetting_;
    bool enableShutterCallback_;
};

struct VdiCaptureEndedInfo {
    int32_t streamId_;
    int32_t frameCount_;
} __attribute__ ((aligned(8)));

struct VdiCaptureErrorInfo {
    int32_t streamId_;
    VdiStreamError error_;
} __attribute__ ((aligned(8)));

} // V1_0
} // Camera
} // VDI
} // OHOS
#endif // OHOS_VDI_CAMERA_V1_0_TYPES_H
