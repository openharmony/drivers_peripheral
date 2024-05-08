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

#ifndef CAMERA_HAL_HISYSEVENT_H
#define CAMERA_HAL_HISYSEVENT_H
#include <chrono>
#include <string>
#include <map>
#include "hisysevent.h"
#include "camera.h"
#include <memory>

namespace OHOS::Camera {

enum ErrorEventType {
    CREATE_PIPELINE_ERROR,
    TURN_BUFFER_ERROR,
    REQUEST_BUFFER_ERROR,
    REQUEST_GRAPHIC_BUFFER_ERROR,
    COPY_BUFFER_ERROR,
    TYPE_CAST_ERROR,
    OPEN_DEVICE_NODE_ERROR,
    FORMAT_CAST_ERROR
};

enum PerformanceEventType {
    TIME_FOR_OPEN_CAMERA,
    TIME_FOR_CAPTURE,
    TIME_FOR_FIRST_FRAME
};

class CameraHalHisysevent {
public:
    static std::string CreateMsg(const char* format, ...);
    static void WriteFaultHisysEvent(const std::string &name, const std::string &msg);
    static std::string GetEventName(ErrorEventType errorEventType);
};

class CameraHalPerfSysevent final {
    PerformanceEventType perfEventType_;
    bool isPrint_;
    const char *const funcName_;
    std::chrono::system_clock::time_point begin;
public:
    CameraHalPerfSysevent(PerformanceEventType perfEventType, bool isPrint, const char *name);
    ~CameraHalPerfSysevent();
    CameraHalPerfSysevent(const CameraHalPerfSysevent&) = delete;
    CameraHalPerfSysevent(CameraHalPerfSysevent&&) = delete;
    CameraHalPerfSysevent& operator = (const CameraHalPerfSysevent&) = delete;
    CameraHalPerfSysevent& operator = (CameraHalPerfSysevent&&) = delete;
};

#define CAMERAHALPERFSYSEVENT_COND(pet, cond) CameraHalPerfSysevent cameraHalPerfSysevent(pet, cond, __FUNCTION__)

#define CAMERAHALPERFSYSEVENT(pet) CAMERAHALPERFSYSEVENT_COND(pet, true)

#define CAMERAHALPERFSYSEVENT_EQUAL(arg, x, pet) CAMERAHALPERFSYSEVENT_COND(pet, ((arg) == (x)))
}  // namespace OHOS::Camera
#endif
