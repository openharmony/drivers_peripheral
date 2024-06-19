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

#include "camera_dev.h"
#include "camera_hardware.h"

namespace OHOS::Camera {

CameraDev::CameraDev() {}
CameraDev::~CameraDev() {}

char *CameraDev::GetCameraName(const std::string &cameraId)
{
    int32_t cameraIdList = 0;
    char deviceName[DEVICE_NAME_NUM] = {0};

    for (auto iter = hardware.cbegin(); iter != hardware.cend(); iter++) {
        hardwareLists_.push_back(*iter);
    }

    for (auto iter = hardwareLists_.cbegin(); iter != hardwareLists_.cend(); iter++) {
        if ((*iter).hardwareName == cameraId) {
            cameraIdList = (*iter).cameraId;
        }
    }

    if (snprintf_s(deviceName, DEVICE_NAME_NUM, DEVICE_NAME_NUM - 1, "camera%d", cameraIdList) < 0) {
        CAMERA_LOGE("error: get deviceName failed! cameraDevice id = %{public}d\n", cameraIdList);
        return nullptr;
    }

    return deviceName;
}

RetCode CameraDev::Start(const std::string &cameraId)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myFileFormat_ == nullptr) {
        myFileFormat_ = std::make_shared<CameraFileFormat>();
        if (myFileFormat_ == nullptr) {
            CAMERA_LOGE("error: myFileFormat_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, 0, deviceName, false);
    CHECK_RETURN_RESULT(ret);

    ret = myFileFormat_->CameraOpenDevice(feature);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraOpenDevice failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraDev::Stop(const std::string &cameraId)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myFileFormat_ == nullptr) {
        myFileFormat_ = std::make_shared<CameraFileFormat>();
        if (myFileFormat_ == nullptr) {
            CAMERA_LOGE("error: myFileFormat_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, 0, deviceName, false);
    CHECK_RETURN_RESULT(ret);

    ret = myFileFormat_->CameraCloseDevice(feature);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraCloseDevice failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraDev::Init(std::vector<std::string> &cameraIds)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    ret = CameraDriverClientInit();
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraDriverClientInit failed, ret = %{public}d\n", ret);
        return RC_ERROR;
    }

    auto myControl_ = std::make_shared<CameraControl>();
    if (myControl_ == nullptr) {
        CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
        return RC_ERROR;
    }
    std::shared_ptr<CameraDev> mydev_ = std::make_shared<CameraDev>();
    for (auto &it : cameraIds) {
        if (strncpy_s(deviceName, DEVICE_NAME_NUM, mydev_->GetCameraName(it), DEVICE_NAME_NUM) != 0) {
            CAMERA_LOGE("strncpy_s error!");
            return RC_ERROR;
        }
        CAMERA_LOGD("deviceName: %{public}s\n", deviceName);
        ret = mydev_->SetDeviceInfo(&feature, it, STREAM_TYPE, deviceName, true);
        CHECK_RETURN_RESULT(ret);
    
        myControl_->CameraMatchDevice(feature);
    }

    return RC_OK;
}

RetCode CameraDev::PowerUp(const std::string &cameraId, int type)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<CameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);
    
    ret = myControl_->CameraPowerUp(feature);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraPowerUp failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraDev::PowerDown(const std::string &cameraId, int type)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<CameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myControl_->CameraPowerDown(feature);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraPowerDown failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraDev::ReqBuffers(const std::string &cameraId, int type, unsigned int buffCont)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    if (myBuffers_ == nullptr) {
        myBuffers_ = std::make_shared<CameraBuffer>(memoryType_);
        if (myBuffers_ == nullptr) {
            CAMERA_LOGE("error: myBuffers_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    ret = myBuffers_->CameraInitMemory(feature);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraInitMemory failed\n");
        return RC_ERROR;
    }
    ret = myBuffers_->CameraReqMemory(feature, buffCont);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraReqMemory failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraDev::CreatBuffer(const std::string &cameraId, int type, const std::shared_ptr<FrameSpec> &frameSpec)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (frameSpec == nullptr || myBuffers_ == nullptr) {
        CAMERA_LOGE("error: rameSpec or myBuffers_ is nullptr\n");
        return RC_ERROR;
    }
    CAMERA_LOGD("frameSpec->buffer index == %{public}d\n", frameSpec->buffer_->GetIndex());

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myBuffers_->CameraAllocBuffer(feature, frameSpec);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraAllocBuffer failed\n");
        return RC_ERROR;
    }

    ret = myBuffers_->CameraStreamQueue(feature, frameSpec);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraStreamQueue failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraDev::QueueBuffer(const std::string &cameraId, int type, const std::shared_ptr<FrameSpec> &frameSpec)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (frameSpec == nullptr || myBuffers_ == nullptr) {
        CAMERA_LOGE("error: frameSpec or myBuffers_ is nullptr\n");
        return RC_ERROR;
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myBuffers_->CameraStreamQueue(feature, frameSpec);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraStreamQueue failed\n");
        return RC_ERROR;
    }

    return RC_OK;
}

RetCode CameraDev::ReleaseBuffers(const std::string &cameraId, int type)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myBuffers_ == nullptr) {
        myBuffers_ = std::make_shared<CameraBuffer>(memoryType_);
        if (myBuffers_ == nullptr) {
            CAMERA_LOGE("error: myBuffers_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myBuffers_->CameraReleaseBuffers(feature);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraReleaseBuffers failed\n");
        return RC_ERROR;
    }

    return RC_OK;
}

void CameraDev::LoopBuffers(const std::string &cameraId, int type)
{
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myBuffers_ == nullptr) {
        CAMERA_LOGE("myBuffers_ is nullptr\n");
        return;
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return;
    }

    int32_t ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    if (ret != RC_OK) {
        CAMERA_LOGE("SetDeviceInfo error!");
        return;
    }

    while (streamNumber_ > 0) {
        ret = myBuffers_->CameraStreamDequeue(feature);
        if (ret != RC_OK) {
            CAMERA_LOGE("CameraStreamDequeue failed!\n");
            return;
        }
    }
    CAMERA_LOGD("LoopBuffers exit\n");
}

RetCode CameraDev::StartStream(const std::string &cameraId, int type)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    if (myStreams_ == nullptr) {
        myStreams_ = std::make_shared<CameraStreams>();
        if (myStreams_ == nullptr) {
            CAMERA_LOGE("error: myStreams_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myStreams_->CameraStreamOn(feature);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraStreamOn failed\n");
        return RC_ERROR;
    }
    if (streamNumber_ == 0) {
        streamThread_ = new (std::nothrow) std::thread([this, cameraId, type] {this->LoopBuffers(cameraId, type);});
        if (streamThread_ == nullptr) {
            CAMERA_LOGE("error: start thread failed\n");
            return RC_ERROR;
        }
    }

    streamNumber_++;
    return RC_OK;
}

RetCode CameraDev::StopStream(const std::string &cameraId, int type)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myStreams_ == nullptr) {
        myStreams_ = std::make_shared<CameraStreams>();
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
        CAMERA_LOGE("waiting LoopBuffers stop\n");
        streamThread_->join();
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myStreams_->CameraStreamOff(feature);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraStreamOff failed\n");
        return RC_ERROR;
    }
    if (streamNumber_ == 0) {
        delete streamThread_;
        streamThread_ = nullptr;
    }
    return RC_OK;
}

RetCode CameraDev::GetControls(const std::string &cameraId, int type, CameraCtrl &ctrl)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<CameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myControl_->CameraQueryConfig(feature, ctrl);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraQueryConfig failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraDev::UpdateSetting(const std::string &cameraId, int type, CameraCtrl &ctrl)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<CameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myControl_->CameraSetConfig(feature, ctrl);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraSetConfig failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraDev::QuerySetting(const std::string &cameraId, int type, CameraCtrl &ctrl)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<CameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myControl_->CameraGetConfig(feature, ctrl);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraSetConfig failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraDev::CameraGetNumberConfig(const std::string &cameraId,
    int type, std::vector<CameraCtrl> &control)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<CameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    return myControl_->CameraGetConfigs(feature, control, control.size());
}

RetCode CameraDev::CameraSetNumberConfig(const std::string &cameraId, int type, std::vector<CameraCtrl> &control)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<CameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    return myControl_->CameraSetConfigs(feature, control, control.size());
}

RetCode CameraDev::GetFmtDescs(const std::string &cameraId, int type, std::vector<CameraCtrl> &fmtDesc)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myFileFormat_ == nullptr) {
        myFileFormat_ = std::make_shared<CameraFileFormat>();
        if (myFileFormat_ == nullptr) {
            CAMERA_LOGE("error: myFileFormat_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myFileFormat_->CameraGetFmtDescs(feature, fmtDesc);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraGetFmtDescs failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraDev::ConfigSys(const std::string &cameraId, int type, CameraFmtCmd command, CameraCtrl &format)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myFileFormat_ == nullptr) {
        myFileFormat_ = std::make_shared<CameraFileFormat>();
        if (myFileFormat_ == nullptr) {
            CAMERA_LOGE("error: myFileFormat_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    switch (command) {
        case CMD_CAMERA_GET_FORMAT:
            ret = myFileFormat_->CameraGetFormat(feature, format);
            break;
        case CMD_CAMERA_SET_FORMAT:
            ret = myFileFormat_->CameraSetFormat(feature, format);
            break;
        case CMD_CAMERA_GET_CROP:
            ret = myFileFormat_->CameraGetCrop(feature, format);
            break;
        case CMD_CAMERA_SET_CROP:
            ret = myFileFormat_->CameraSetCrop(feature, format);
            break;
        case CMD_CAMERA_GET_FPS:
            ret = myFileFormat_->CameraGetFPS(feature, format);
            break;
        case CMD_CAMERA_SET_FPS:
            ret = myFileFormat_->CameraSetFPS(feature, format);
            break;
        default:
            CAMERA_LOGE("error: unknow command\n");
            break;
    }
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CMD %{public}d failed\n", command);
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode CameraDev::GetDeviceAbility(const std::string &cameraId, int type)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<CameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myControl_->CameraGetAbility(feature);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraGetAbility failed\n");
        return RC_ERROR;
    }

    return RC_OK;
}

RetCode CameraDev::EnumDevices(const std::string &cameraId, int type, struct DeviceaInfo &device)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};
    struct CameraFeature feature = {};

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<CameraControl>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("error: myControl_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }

    ret = SetDeviceInfo(&feature, cameraId, type, deviceName, true);
    CHECK_RETURN_RESULT(ret);

    ret = myControl_->CameraEnumDevices(feature, device);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: CameraEnumDevices failed\n");
        return RC_ERROR;
    }

    return RC_OK;
}

RetCode CameraDev::SetCallback(BufCallback cb)
{
    if (cb == nullptr) {
        CAMERA_LOGE("error: SetCallback is null");
        return RC_ERROR;
    }
    if (myBuffers_ == nullptr) {
        myBuffers_ = std::make_shared<CameraBuffer>(memoryType_);
        if (myBuffers_ == nullptr) {
            CAMERA_LOGE("error: myBuffers_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }
    myBuffers_->SetCallback(cb);
    return RC_OK;
}

RetCode CameraDev::Flush(const std::string &cameraId)
{
    int32_t ret;
    char deviceName[DEVICE_NAME_NUM] = {0};

    if (strncpy_s(deviceName, DEVICE_NAME_NUM, GetCameraName(cameraId), DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s error!");
        return RC_ERROR;
    }
    if (myBuffers_ == nullptr) {
        myBuffers_ = std::make_shared<CameraBuffer>(memoryType_);
        if (myBuffers_ == nullptr) {
            CAMERA_LOGE("error: myBuffers_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    ret = myBuffers_->Flush(deviceName);
    if (ret != RC_OK) {
        CAMERA_LOGE("error: Flush: failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

void CameraDev::SetMemoryType(uint8_t &memType)
{
    CAMERA_LOGD("func[CameraDev::%{public}s] memType[%{public}d]", __func__, memType);
    if (memType == MEMTYPE_MMAP) {
        memoryType_ = MEMTYPE_MMAP;
    } else if (memType == MEMTYPE_DMABUF) {
        memoryType_ = MEMTYPE_DMABUF;
    }
}

int32_t CameraDev::SetDeviceInfo(struct CameraFeature *feature,
    const std::string &cameraId, int type, char *deviceName, bool state)
{
    if (state) {
        feature->type = type;
    }

    feature->permissionId = CAMERA_MASTER;
    if (strncpy_s(feature->deviceName, DEVICE_NAME_NUM, deviceName, DEVICE_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s deviceName error!");
        return RC_ERROR;
    }
    if (strncpy_s(feature->driverName, DRIVER_NAME_NUM, cameraId.c_str(), DRIVER_NAME_NUM) != 0) {
        CAMERA_LOGE("strncpy_s driverName error!");
        return RC_ERROR;
    }
    return RC_OK;
}
} // namespace OHOS::Camera
