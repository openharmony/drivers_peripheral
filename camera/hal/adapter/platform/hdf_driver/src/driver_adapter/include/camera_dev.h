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

#ifndef HOS_HDF_CAMERA_DEV_H
#define HOS_HDF_CAMERA_DEV_H

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <map>
#include <mutex>
#include <thread>
#include <vector>
#include "camera_buffer.h"
#include "camera_fileformat.h"
#include "camera_stream.h"
#include "camera_control.h"
#include "camera_common.h"
#include "device_manager_adapter.h"

namespace OHOS::Camera {
class HosCameraDev {
public:
    HosCameraDev();
    ~HosCameraDev();

    RetCode start(const std::string& cameraId);

    RetCode stop(const std::string& cameraId);

    RetCode PowerUp(const std::string& cameraId, int type);

    RetCode PowerDown(const std::string& cameraId, int type);

    RetCode CameraGetNumberConfig(const std::string& cameraId, int type, std::vector<CameraCtrl>& control);

    RetCode CameraSetNumberConfig(const std::string& cameraId, int type, std::vector<CameraCtrl>& control);

    RetCode GetFmtDescs(const std::string& cameraId, int type, std::vector<CameraCtrl>& fmtDesc);

    RetCode ConfigSys(const std::string& cameraId, int type, CameraFmtCmd command, CameraCtrl& format);

    RetCode GetDeviceAbility(const std::string& cameraId, int type);

    RetCode EnumDevices(const std::string& cameraId, int type, struct DeviceaInfo &device);

    RetCode GetControls(const std::string& cameraId, int type, CameraCtrl &ctrl);

    RetCode UpdateSetting(const std::string& cameraId, int type, CameraCtrl &ctrl);

    RetCode QuerySetting(const std::string& cameraId, int type, CameraCtrl &ctrl);

    RetCode ReqBuffers(const std::string& cameraId, int type, unsigned int buffCont);

    RetCode CreatBuffer(const std::string& cameraId, int type, const std::shared_ptr<FrameSpec>& frameSpec);

    RetCode StartStream(const std::string& cameraId, int type);

    RetCode QueueBuffer(const std::string& cameraId, int type, const std::shared_ptr<FrameSpec>& frameSpec);

    RetCode ReleaseBuffers(const std::string& cameraId, int type);

    RetCode StopStream(const std::string& cameraId, int type);

    RetCode SetCallback(BufCallback cb);

    RetCode Flush(const std::string& cameraId);

    void SetMemoryType(uint8_t &memType);

    static RetCode Init(std::vector<std::string>& cameraIds);

private:
    char* GetCameraName(const std::string& cameraId);
    void loopBuffers(const std::string& cameraId, int type);

    uint32_t streamNumber_ = 0;
    uint32_t permissionId_ = CAMERA_MASTER;
    std::thread* streamThread_ = nullptr;

    std::shared_ptr<HosCameraBuffers> myBuffers_ = nullptr;
    std::shared_ptr<HosCameraStreams> myStreams_ = nullptr;
    std::shared_ptr<HosCameraFileFormat> myFileFormat_ = nullptr;
    std::shared_ptr<HosCameraControl> myControl_ = nullptr;
    std::vector<HardwareConfiguration> hardwareLists_;
    enum CamMemType memoryType_ = MEMTYPE_MMAP;
};
} // namespace OHOS::Camera
#endif // HOS_HDF_CAMERA_DEV_H
