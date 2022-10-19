/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "utest_camera_hdi_base.h"

#ifdef HDF_LOG_TAG
#undef HDF_LOG_TAG
#endif

#define HDF_LOG_TAG camera_service_test

constexpr const char *TEST_SERVICE_NAME = "camera_service";

void CameraHdiBaseTest::SetUpTestCase(void)
{
}

void CameraHdiBaseTest::TearDownTestCase(void)
{
}

void CameraHdiBaseTest::SetUp(void)
{
}

void CameraHdiBaseTest::TearDown(void)
{
}

bool CameraHdiBaseTest::InitCameraHost()
{
    if (cameraHost_ != nullptr) {
        return true;
    }
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    cameraHost_ = OHOS::Camera::CameraHost::CreateCameraHost();
#else
    cameraHost_ = ICameraHost::Get(TEST_SERVICE_NAME, false);
#endif
    if (cameraHost_ == nullptr) {
        return false;
    }
    return true;
}

bool CameraHdiBaseTest::GetCameraDevice()
{
    if (cameraDevice_ != nullptr) {
        return true;
    }

    if (cameraIds_.empty()) {
        return false;
    }

    std::string cameraId = cameraIds_.front();
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    std::shared_ptr<CameraDeviceCallback> deviceCallback = std::make_shared<CameraDeviceCallback>();
#else
    sptr<DemoCameraDeviceCallback> deviceCallback = new DemoCameraDeviceCallback();
#endif
    CamRetCode rc = (CamRetCode)cameraHost_->OpenCamera(cameraId, deviceCallback, cameraDevice_);
    if (cameraDevice_ == nullptr) {
        return false;
    }
    return true;
}

bool CameraHdiBaseTest::GetStreamOperator()
{
    if (streamOperator_ != nullptr) {
        return true;
    }

    if (cameraDevice_ == nullptr) {
        return false;
    }

#ifdef CAMERA_BUILT_ON_OHOS_LITE
    std::shared_ptr<StreamOperatorCallback> streamOperatorCallback = std::make_shared<StreamOperatorCallback>();
#else
    OHOS::sptr<IStreamOperatorCallback> streamOperatorCallback = new DemoStreamOperatorCallback();
#endif
    (void)cameraDevice_->GetStreamOperator(streamOperatorCallback, streamOperator_);
    if (streamOperator_ == nullptr) {
        return false;
    }
    return true;
}

bool CameraHdiBaseTest::GetCameraIds()
{
    if (InitCameraHost()) {
        (void)cameraHost_->GetCameraIds(cameraIds_);
    }
    if (cameraIds_.empty()) {
        return false;
    }
    return true;
}

int32_t CameraHdiBaseTest::SaveToFile(const std::string& path, const void* buffer, int32_t size) const
{
    char checkPath[PATH_MAX] = {0};
    if (::realpath(path.c_str(), checkPath) == nullptr) {
        return -1;
    }
    int imgFd = open(path.c_str(), O_RDWR | O_CREAT, 00766);
    if (imgFd == -1) {
        std::cout << "open file failed." << std::endl;
        return -1;
    }

    int ret = write(imgFd, buffer, size);
    if (ret == -1) {
        std::cout << "write failed." << std::endl;
        close(imgFd);
        return -1;
    }
    close(imgFd);
    return 0;
}

uint64_t CameraHdiBaseTest::GetCurrentLocalTimeStamp() const
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return tmp.count();
}

#ifdef CAMERA_BUILT_ON_OHOS_LITE
#define YUV_SAVE_PATH "/userdata/camera"
#else
#define YUV_SAVE_PATH "/data/log/camera"
#endif

int32_t CameraHdiBaseTest::SaveYUV(const char* type, const void* buffer, int32_t size)
{
    if (strncmp(type, "preview", strlen(type)) == 0) {
        previewBufCnt += 1;
        if (previewBufCnt % 8 != 0) { // 8:Save one frame every eight frames
            std::cout << "receive preview buffer not save" << std::endl;
            return 0;
        }
    }

    if (access(YUV_SAVE_PATH, F_OK) != 0) {
        std::cout << "save path: " << YUV_SAVE_PATH << " not exist" << std::endl;
        return 0;
    }

    char path[PATH_MAX] = {0};
    int ret;
    if (strncmp(type, "preview", strlen(type)) == 0) {
        system("mkdir -p " YUV_SAVE_PATH "/preview/");
        char prefix[] = YUV_SAVE_PATH "/preview/";
        ret = sprintf_s(path, sizeof(path) / sizeof(path[0]), "%s%s_%lld.yuv",
            prefix, type, GetCurrentLocalTimeStamp());
    } else {
        system("mkdir -p " YUV_SAVE_PATH "/capture/");
        char prefix[] = YUV_SAVE_PATH "/capture/";
        ret = sprintf_s(path, sizeof(path) / sizeof(path[0]), "%s%s_%lld.jpg",
            prefix, type, GetCurrentLocalTimeStamp());
    }
    if (ret < 0) {
        std::cout << "sprintf path failed: " << path << std::endl;
        CAMERA_LOGE("%s: sprintf path failed", __func__);
        return -1;
    }

    std::cout << "save yuv to file:" << path << std::endl;
    int imgFd = open(path, O_RDWR | O_CREAT | O_APPEND, 00766); // 00766:file jurisdiction
    if (imgFd == -1) {
        std::cout << "open file failed, errno = " << strerror(errno) << std::endl;
        return -1;
    }

    ret = write(imgFd, buffer, size);
    if (ret == -1) {
        std::cout << "write file failed, error = " << strerror(errno) << std::endl;
        close(imgFd);
        return -1;
    }
    close(imgFd);
    return 0;
}

int32_t DemoCameraHostCallback::OnCameraStatus(const std::string& cameraId, CameraStatus status)
{
    (void)cameraId;
    (void)status;
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

int32_t DemoCameraHostCallback::OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status)
{
    CAMERA_LOGI("%{public}s, enter. cameraId = %s, status = %d",
        __func__, cameraId.c_str(), static_cast<int>(status));
    return RC_OK;
}

int32_t DemoCameraHostCallback::OnCameraEvent(const std::string& cameraId, CameraEvent event)
{
    CAMERA_LOGI("%{public}s, enter. cameraId = %s, event = %d",
        __func__, cameraId.c_str(), static_cast<int>(event));
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    (void)captureId;
    (void)streamIds;
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
{
    (void)captureId;
    (void)infos;
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    (void)captureId;
    (void)infos;
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    (void)captureId;
    (void)streamIds;
    (void)timestamp;
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

int32_t DemoCameraDeviceCallback::OnError(ErrorType type, int32_t errorCode)
{
    (void)type;
    (void)errorCode;
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

int32_t DemoCameraDeviceCallback::OnResult(uint64_t timestamp, const std::vector<uint8_t>& result)
{
    (void)timestamp;
    (void)result;
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}
