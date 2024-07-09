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

#include "camera_hal_hisysevent.h"
#define MAX_STRING_SIZE 256

namespace OHOS::Camera {

#define TOSTR(x) #x

std::map<ErrorEventType, std::string> g_eventNameMap = {
    {CREATE_PIPELINE_ERROR, "CREATE_PIPELINE_ERROR"},
    {TURN_BUFFER_ERROR, "TURN_BUFFER_ERROR"},
    {REQUEST_BUFFER_ERROR, "REQUEST_BUFFER_ERROR"},
    {REQUEST_GRAPHIC_BUFFER_ERROR, "REQUEST_GRAPHIC_BUFFER_ERROR"},
    {COPY_BUFFER_ERROR, "COPY_BUFFER_ERROR"},
    {TYPE_CAST_ERROR, "TYPE_CAST_ERROR"},
    {OPEN_DEVICE_NODE_ERROR, "OPEN_DEVICE_NODE_ERROR"},
    {FORMAT_CAST_ERROR, "FORMAT_CAST_ERROR"}
};

std::map<PerformanceEventType, std::string> g_perfEventNameMap = {
    {TIME_FOR_OPEN_CAMERA, std::string(TOSTR(TIME_FOR_OPEN_CAMERA))},
    {TIME_FOR_CAPTURE, std::string(TOSTR(TIME_FOR_CAPTURE))},
    {TIME_FOR_FIRST_FRAME, std::string(TOSTR(TIME_FOR_FIRST_FRAME))}
};

std::map<StatisicEventType, std::string> g_staEventNameMap = {
    {TIME_OF_CAPTURE, std::string(TOSTR(TIME_OF_CAPTURE))},
    {TIME_OF_VEDIOA_AND_DURATION, std::string(TOSTR(TIME_OF_VEDIOA_AND_DURATION))},
    {INFORMATION_OF_CAMERA, std::string(TOSTR(INFORMATION_OF_CAMERA))},
    {PARAMS_OFCAPTURE_OR_VEDIO, std::string(TOSTR(PARAMS_OFCAPTURE_OR_VEDIO))},
};

std::string CameraHalHisysevent::CreateMsg(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    char msg[MAX_STRING_SIZE] = {0};
    if (vsnprintf_s(msg, sizeof(msg), sizeof(msg) - 1, format, args) < 0) {
        CAMERA_LOGE("failed to call vsnprintf_s");
        va_end(args);
        return "";
    }
    va_end(args);
    return msg;
}

std::string CameraHalHisysevent::GetEventName(ErrorEventType errorEventType)
{
    auto it = g_eventNameMap.find(errorEventType);
    if (it != g_eventNameMap.end()) {
        return g_eventNameMap[errorEventType];
    }
    return "";
}

void CameraHalHisysevent::WriteFaultHisysEvent(const std::string &name, const std::string &msg)
{
    CAMERA_LOGI("WriteFaultHisysEvent name:%{public}s msg:%{public}s", name.c_str(), msg.c_str());
    int32_t ret = HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::CAMERA_HAL, "CAMERA_HAL_ERR",
                                  OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, "NAME", name, "MSG", msg);
    if (ret != 0) {
        CAMERA_LOGE("WriteFaultHisysEvent filed name:%{public}s ret:%{public}d", name.c_str(), ret);
    }
}

CameraHalPerfSysevent::CameraHalPerfSysevent(PerformanceEventType perfEventType, bool isPrint, const char *name)
    : perfEventType_(perfEventType), isPrint_(isPrint), funcName_(name)
{
    begin = std::chrono::system_clock::now();
}

CameraHalPerfSysevent::~CameraHalPerfSysevent()
{
    if (isPrint_) {
        std::chrono::system_clock::time_point end = std::chrono::system_clock::now();
        auto microsec = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
            HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::CAMERA_HAL, "CAMERA_HAL_PERFORMANCE",
                OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
                "NAME", g_perfEventNameMap[perfEventType_],
                "FUNCTION", std::string(funcName_),
                "TIMECOST", microsec);
    }
}

std::string CameraHalTimeSysevent::GetEventName(StatisicEventType statisicEventType)
{
    auto it = g_staEventNameMap.find(statisicEventType);
    if (it != g_staEventNameMap.end()) {
        return g_staEventNameMap[statisicEventType];
    }
    return "";
}

void CameraHalTimeSysevent::WriteTimeStatisicEvent(const std::string &name)
{
    std::chrono::system_clock::time_point begin = std::chrono::system_clock::now();
    std::time_t now = std::chrono::system_clock::to_time_t(begin);
    std::string timepoint_str = std::ctime(&now);
    CAMERA_LOGI("WriteTimeStatisicEvent name:%{public}s, timepoint:%{public}s", name.c_str(), timepoint_str.c_str());
    int32_t ret = HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::CAMERA_HAL, "CAMERA_HAL_STATISTIC",
                                  OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
                                  "NAME", name, "TIMEPOINT", timepoint_str);
    if (ret != 0) {
        CAMERA_LOGE("WriteTimeStatisicEvent file name:%{public}s, ret:%{public}d", name.c_str(), ret);
    }
}

void CameraHalTimeSysevent::WriteCameraInformationEvent(const std::string &name, common_metadata_header_t *data)
{
    CAMERA_LOGI("WriteCameraInformationEvent start!!");
    camera_metadata_item_t entry;
    if (FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &entry) == 0) {
        uint8_t cameraConnectType = *(entry.data.u8);
        if (static_cast<int>(cameraConnectType) == OHOS_CAMERA_CONNECTION_TYPE_BUILTIN) {
            CAMERA_LOGI("cameraConnectType is %{public}d", cameraConnectType);
            HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::CAMERA_HAL, "CAMERA_HAL_STATISTIC",
                            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
                            "NAME", name, "INFORMATION", cameraConnectType);
        } else if (static_cast<int>(cameraConnectType) == OHOS_CAMERA_CONNECTION_TYPE_USB_PLUGIN) {
            CAMERA_LOGI("cameraConnectType is %{public}d", cameraConnectType);
            HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::CAMERA_HAL, "CAMERA_HAL_STATISTIC",
                            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
                            "NAME", name, "INFORMATION", cameraConnectType);
        } else {
            CAMERA_LOGE("cameraConnectType not start!!");
        }
    } else {
        CAMERA_LOGE("OHOS_ABILITY_CAMERA_CONNECTION_TYPE not find!!");
    }
}

void CameraHalTimeSysevent::WriteCameraParameterEvent(const std::string &name, common_metadata_header_t *data)
{
    CAMERA_LOGI("WriteCameraParameterEvent start!!");
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::CAMERA_HAL, "CAMERA_HAL_STATISTIC",
                    OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
                    "NAME", name, "PARAMETER", CameraMetadata::FormatCameraMetadataToString(data));
}
}