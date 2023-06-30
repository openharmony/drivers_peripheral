/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef USB_CAMERA_TEST_MULT_H
#define USB_CAMERA_TEST_MULT_H

#include "test_camera_base.h"

enum {
    STREAM_ID_PREVIEW_DOUBLE = 1100, // 1100:double preview streamID
    STREAM_ID_CAPTURE_DOUBLE,
    STREAM_ID_VIDEO_DOUBLE,
    CAPTURE_ID_PREVIEW_DOUBLE = 2100, // 2100:double preview captureId
    CAPTURE_ID_CAPTURE_DOUBLE,
    CAPTURE_ID_VIDEO_DOUBLE
};

class UtestUSBCameraTestMult : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
    CamRetCode SelectOpenCamera(std::string cameraId);
    void AchieveStreamOperator();
    uint32_t ConvertPixfmtHal2V4l2(uint32_t ohosfmt);
    void DefaultInfosPreview();
    void DefaultInfosVideo();
    void DefaultInfosCapture();
    void StartStream(std::vector<StreamIntent> intents);
    void StoreImage(const unsigned char *bufStart, const uint32_t size);
    void StoreVideo(const unsigned char *bufStart, const uint32_t size);
    void OpenVideoFile();
    void CloseFd();
    void StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming);
    void StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds);

    std::shared_ptr<TestCameraBase> cameraBase_ = nullptr;
    bool usbCameraExit_ = false;
    std::vector<uint8_t> vecAbility_ = {};
    std::shared_ptr<CameraAbility> ability_ = nullptr;
    OHOS::sptr<ICameraDevice> cameraDevice_ = nullptr;
    OHOS::sptr<IStreamOperator> streamOperator_ = nullptr;
    std::shared_ptr<StreamCustomer> streamCustomerPreview_ = nullptr;
    std::shared_ptr<StreamCustomer> streamCustomerCapture_ = nullptr;
    std::shared_ptr<StreamCustomer> streamCustomerVideo_ = nullptr;
    std::vector<StreamInfo> streamInfos_ = {};
    StreamInfo streamInfoPre_ = {};
    StreamInfo streamInfoVideo_ = {};
    StreamInfo streamInfoCapture_ = {};
    CaptureInfo captureInfo_ = {};
    uint32_t videoFormat_;
    int videoFd_ = -1;
};
#endif
