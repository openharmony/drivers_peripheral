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

#include <sys/prctl.h>
#include <osal/osal_mem.h>
#include "camera_dev.h"
#include "project_hardware.h"

namespace OHOS::Camera {

HosCameraDev::HosCameraDev() {}
HosCameraDev::~HosCameraDev() {}

char* HosCameraDev::GetCameraName(const std::string& cameraId)
{
    int cameraId_list = 0;
    char deviceName[DEVICE_NAME_NUM] = {0};

    for (auto iter = hardware.cbegin(); iter != hardware.cend(); iter++) {
        hardwareLists_.push_back(*iter);
    }

    for (auto iter = hardwareLists_.cbegin(); iter != hardwareLists_.cend(); iter++) {
        if ((*iter).hardwareName == cameraId) {
            cameraId_list = (*iter).cameraId;
        }
    }

    if (snprintf_s(deviceName, DEVICE_NAME_NUM, DEVICE_NAME_NUM - 1, "camera%d", cameraId_list) < 0) {
        CAMERA_LOGE("error: get deviceName failed! cameraDevice id = %{public}d\n", cameraId_list);
        return nullptr;
    }

    return deviceName;
}

RetCode HosCameraDev::start(const std::string& cameraId)
{
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (myFileFormat_ == nullptr) {
        myFileFormat_ = std::make_shared<HosCameraFileFormat>();
        if (myFileFormat_ == nullptr) {
            CAMERA_LOGE("error: myFileFormat_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    myFileFormat_->CameraOpenDevice(cameraId, permissionId_, deviceName);

    return RC_OK;
}

RetCode HosCameraDev::stop(const std::string& cameraId)
{
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (myFileFormat_ == nullptr) {
        myFileFormat_ = std::make_shared<HosCameraFileFormat>();
        if (myFileFormat_ == nullptr) {
            CAMERA_LOGE("error: myFileFormat_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    myFileFormat_->CameraCloseDevice(cameraId, permissionId_, deviceName);

    return RC_OK;
}

RetCode HosCameraDev::Init(std::vector<std::string>& cameraIds)
{
    int32_t ret = 0;
    char deviceName[DEVICE_NAME_NUM] = {0};

    ret = CameraDriverClientInit();
    if (ret != HDF_SUCCESS) {
        CAMERA_LOGE("error: CameraDriverClientInit failed, ret = %{public}d\n", ret);
    }

    auto myControl_ = std::make_shared<HosCameraControl>();
    if (myControl_ == nullptr) {
        CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
        return RC_ERROR;
    }
    std::shared_ptr<HosCameraDev> mydev_ = std::make_shared<HosCameraDev>();
    for (auto &it : cameraIds) {
        if (strncpy_s(deviceName, DEVICE_NAME_NUM, mydev_->GetCameraName(it), DEVICE_NAME_NUM) != 0) {
            CAMERA_LOGE("strncpy_s error!");
            return RC_ERROR;
        }
        CAMERA_LOGD("deviceName: %{public}s\n", deviceName);
        myControl_->CameraMatchDevice(it, mydev_->permissionId_, deviceName);
    }

    return RC_OK;
}

RetCode HosCameraDev::PowerUp(const std::string& cameraId, int type)
{
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosCameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    myControl_->CameraPowerUp(cameraId, type, permissionId_, deviceName);

    return RC_OK;
}

RetCode HosCameraDev::PowerDown(const std::string& cameraId, int type)
{
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosCameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    myControl_->CameraPowerDown(cameraId, type, permissionId_, deviceName);

    return RC_OK;
}

RetCode HosCameraDev::ReqBuffers(const std::string& cameraId, int type, unsigned int buffCont)
{
    int32_t rc;
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    if (myBuffers_ == nullptr) {
        myBuffers_ = std::make_shared<HosCameraBuffers>(memoryType_);
        if (myBuffers_ == nullptr) {
            CAMERA_LOGE("error: myBuffers_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    myBuffers_->CameraInitMemory(cameraId, type, permissionId_, deviceName);
    rc = myBuffers_->CameraReqMemory(type, permissionId_, deviceName, buffCont);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: CameraReqMemory failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode HosCameraDev::CreatBuffer(const std::string& cameraId, int type,
    const std::shared_ptr<FrameSpec>& frameSpec)
{
    int32_t rc;
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    if (frameSpec == nullptr || myBuffers_ == nullptr) {
        CAMERA_LOGE("error: rameSpec or myBuffers_ is nullptr\n");
        return RC_ERROR;
    }

    CAMERA_LOGD("frameSpec->buffer index == %{public}d\n", frameSpec->buffer_->GetIndex());
    rc = myBuffers_->CameraAllocBuffer(type, permissionId_, deviceName, frameSpec);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: CameraAllocBuffer failed\n");
        return RC_ERROR;
    }

    rc = myBuffers_->CameraStreamQueue(type, permissionId_, deviceName, frameSpec);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: CameraStreamQueue failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode HosCameraDev::QueueBuffer(const std::string& cameraId, int type,
    const std::shared_ptr<FrameSpec>& frameSpec)
{
    int32_t rc;
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    if (frameSpec == nullptr || myBuffers_ == nullptr) {
        CAMERA_LOGE("error: frameSpec or myBuffers_ is nullptr\n");
        return RC_ERROR;
    }

    rc = myBuffers_->CameraStreamQueue(type, permissionId_, deviceName, frameSpec);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: CameraStreamQueue failed\n");
        return RC_ERROR;
    }

    return RC_OK;
}

RetCode HosCameraDev::ReleaseBuffers(const std::string& cameraId, int type)
{
    char deviceName[DEVICE_NAME_NUM] = {0};
    int32_t rc;

    if (myBuffers_ == nullptr) {
        myBuffers_ = std::make_shared<HosCameraBuffers>(memoryType_);
        if (myBuffers_ == nullptr) {
            CAMERA_LOGE("error: myBuffers_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    rc = myBuffers_->CameraReleaseBuffers(type, permissionId_, deviceName);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: CameraReleaseBuffers failed\n");
        return RC_ERROR;
    }

    return RC_OK;
}

void HosCameraDev::loopBuffers(const std::string& cameraId, int type)
{
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (myBuffers_ == nullptr) {
        CAMERA_LOGE("myBuffers_ is nullptr\n");
        return;
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return;
    }
    while (streamNumber_ > 0) {
        int32_t ret = myBuffers_->CameraStreamDequeue(type, permissionId_, deviceName);
        if (ret != HDF_SUCCESS) {
            CAMERA_LOGE("CameraStreamDequeue failed!\n");
            return;
        }
    }
    CAMERA_LOGD("loopBuffers exit\n");
}

RetCode HosCameraDev::StartStream(const std::string& cameraId, int type)
{
    int32_t rc;
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    if (myStreams_ == nullptr) {
        myStreams_ = std::make_shared<HosCameraStreams>();
        if (myStreams_ == nullptr) {
            CAMERA_LOGE("error: myStreams_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    rc = myStreams_->CameraStreamOn(type, permissionId_, deviceName);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: CameraStreamOn failed\n");
        return RC_ERROR;
    }
    if (streamNumber_ == 0) {
        streamThread_ = new (std::nothrow) std::thread(&HosCameraDev::loopBuffers, this, cameraId, type);
        if (streamThread_ == nullptr) {
            CAMERA_LOGE("error: start thread failed\n");
            return RC_ERROR;
        }
    }

    streamNumber_++;
    return RC_OK;
}

RetCode HosCameraDev::StopStream(const std::string& cameraId, int type)
{
    int32_t rc;
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (myStreams_ == nullptr) {
        myStreams_ = std::make_shared<HosCameraStreams>();
        if (myStreams_ == nullptr) {
            CAMERA_LOGE("error: myStreams_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (streamThread_ == nullptr) {
        CAMERA_LOGE("error: thread is stopped\n");
        return RC_ERROR;
    }

    streamNumber_ -= 1;
    CAMERA_LOGD("streamNumber_ = %{public}d\n", streamNumber_);
    if (streamNumber_ == 0) {
        CAMERA_LOGE("waiting loopBuffers stop\n");
        streamThread_->join();
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    rc = myStreams_->CameraStreamOff(type, permissionId_, deviceName);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: CameraStreamOff failed\n");
        return RC_ERROR;
    }
    if (streamNumber_ == 0) {
        delete streamThread_;
        streamThread_ = nullptr;
    }
    return RC_OK;
}

RetCode HosCameraDev::GetControls(const std::string& cameraId, int type, CameraCtrl &ctrl)
{
    char deviceName[DEVICE_NAME_NUM] = {0};
    int32_t rc;
    struct CameraFeature feature = {};

    feature.type = type;
    feature.permissionId = permissionId_;
    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosCameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    rc = myControl_->CameraQueryConfig(cameraId, feature, deviceName, ctrl);
    if (rc != RC_OK) {
        CAMERA_LOGE("error: CameraQueryConfig failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode HosCameraDev::UpdateSetting(const std::string& cameraId, int type, CameraCtrl &ctrl)
{
    char deviceName[DEVICE_NAME_NUM] = {0};
    int32_t rc;
    struct CameraFeature feature = {};

    feature.type = type;
    feature.permissionId = permissionId_;
    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosCameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    rc = myControl_->CameraSetConfig(cameraId, feature, deviceName, ctrl);
    if (rc != RC_OK) {
        CAMERA_LOGE("error: CameraSetConfig failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode HosCameraDev::QuerySetting(const std::string& cameraId, int type, CameraCtrl &ctrl)
{
    char deviceName[DEVICE_NAME_NUM] = {0};
    int32_t rc;
    struct CameraFeature feature = {};

    feature.type = type;
    feature.permissionId = permissionId_;
    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosCameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    rc = myControl_->CameraGetConfig(cameraId, feature, deviceName, ctrl);
    if (rc != RC_OK) {
        CAMERA_LOGE("error: CameraSetConfig failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode HosCameraDev::CameraGetNumberConfig(const std::string& cameraId,
    int type, std::vector<CameraCtrl>& control)
{
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    feature.type = type;
    feature.permissionId = permissionId_;
    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosCameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    return myControl_->CameraGetConfigs(cameraId, feature, deviceName, control, control.size());
}

RetCode HosCameraDev::CameraSetNumberConfig(const std::string& cameraId,
    int type, std::vector<CameraCtrl>& control)
{
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    feature.type = type;
    feature.permissionId = permissionId_;
    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosCameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    return myControl_->CameraSetConfigs(cameraId, feature, deviceName, control, control.size());
}

RetCode HosCameraDev::GetFmtDescs(const std::string& cameraId, int type, std::vector<CameraCtrl>& fmtDesc)
{
    int32_t rc;
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (myFileFormat_ == nullptr) {
        myFileFormat_ = std::make_shared<HosCameraFileFormat>();
        if (myFileFormat_ == nullptr) {
            CAMERA_LOGE("error: myFileFormat_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    rc = myFileFormat_->CameraGetFmtDescs(cameraId, type, permissionId_, deviceName, fmtDesc);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: CameraGetFmtDescs failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode HosCameraDev::ConfigSys(const std::string& cameraId, int type, CameraFmtCmd command, CameraCtrl& format)
{
    char deviceName[DEVICE_NAME_NUM] = {0};
    int32_t rc;
    struct CameraFeature feature = {};

    feature.type = type;
    feature.permissionId = permissionId_;
    if (myFileFormat_ == nullptr) {
        myFileFormat_ = std::make_shared<HosCameraFileFormat>();
        if (myFileFormat_ == nullptr) {
            CAMERA_LOGE("error: myFileFormat_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    switch (command) {
        case CMD_CAMERA_GET_FORMAT:
            rc = myFileFormat_->CameraGetFormat(cameraId, feature, deviceName, format);
            break;
        case CMD_CAMERA_SET_FORMAT:
            rc = myFileFormat_->CameraSetFormat(cameraId, feature, deviceName, format);
            break;
        case CMD_CAMERA_GET_CROP:
            rc = myFileFormat_->CameraGetCrop(cameraId, feature, deviceName, format);
            break;
        case CMD_CAMERA_SET_CROP:
            rc = myFileFormat_->CameraSetCrop(cameraId, feature, deviceName, format);
            break;
        case CMD_CAMERA_GET_FPS:
            rc = myFileFormat_->CameraGetFPS(cameraId, feature, deviceName, format);
            break;
        case CMD_CAMERA_SET_FPS:
            rc = myFileFormat_->CameraSetFPS(cameraId, feature, deviceName, format);
            break;
        default:
            CAMERA_LOGE("error: unknow command\n");
            break;
    }
    if (rc != RC_OK) {
        CAMERA_LOGE("error: CMD %{public}d failed\n", command);
    }
    return rc;
}

RetCode HosCameraDev::GetDeviceAbility(const std::string& cameraId, int type)
{
    int32_t rc;
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosCameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    rc = myControl_->CameraGetAbility(cameraId, type, permissionId_, deviceName);
    if (rc != RC_OK) {
        CAMERA_LOGE("error: CameraGetAbility failed\n");
    }

    return rc;
}

RetCode HosCameraDev::EnumDevices(const std::string& cameraId, int type, struct DeviceaInfo &device)
{
    char deviceName[DEVICE_NAME_NUM] = {0};
    int32_t rc;

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosCameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    rc = myControl_->CameraEnumDevices(cameraId, type, permissionId_, deviceName, device);
    if (rc != RC_OK) {
        CAMERA_LOGE("error: CameraEnumDevices failed\n");
    }

    return rc;
}

RetCode HosCameraDev::SetCallback(BufCallback cb)
{
    if (cb == nullptr) {
        CAMERA_LOGE("error: SetCallback is null");
        return RC_ERROR;
    }
    if (myBuffers_ == nullptr) {
        myBuffers_ = std::make_shared<HosCameraBuffers>(memoryType_);
        if (myBuffers_ == nullptr) {
            CAMERA_LOGE("error: myBuffers_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    myBuffers_->SetCallback(cb);
    return RC_OK;
}

RetCode HosCameraDev::Flush(const std::string& cameraId)
{
    int32_t rc;
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    if (myBuffers_ == nullptr) {
        myBuffers_ = std::make_shared<HosCameraBuffers>(memoryType_);
        if (myBuffers_ == nullptr) {
            CAMERA_LOGE("error: myBuffers_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    rc = myBuffers_->Flush(deviceName);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: Flush: failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

void HosCameraDev::SetMemoryType(uint8_t &memType)
{
    CAMERA_LOGD("func[HosCameraDev::%{public}s] memType[%{public}d]", __func__, memType);
    if (memType == MEMTYPE_MMAP) {
        memoryType_ = MEMTYPE_MMAP;
    } else if (memType == MEMTYPE_DMABUF) {
        memoryType_ = MEMTYPE_DMABUF;
    }
}
} // namespace OHOS::Camera
