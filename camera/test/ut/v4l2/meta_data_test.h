/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef META_DATA_H
#define META_DATA_H

#include "test_camera_base.h"
#define PREVIEW_WIDTH  640
#define PREVIEW_HEIGHT 480

class MetaDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
    void CreateStream(int streamId, StreamIntent intent);
    void CommitStream();
    void SetStreamInfo(StreamInfo &streamInfo, const std::shared_ptr<StreamCustomer> &streamCustomer,
        const int streamId, const StreamIntent intent);
    void StartCapture(
        int streamId, int captureId, bool shutterCallback, bool isStreaming, const CaptureInfo captureInfo);
    void StopStream(std::vector<int> &captureIds, std::vector<int> &streamIds);
    void StartCustomCapture();
    void StartPreviewVideoStream();
    void StartPreviewCaptureStream();
    void StopPreviewVideoStream();
    void StopPreviewCaptureStream();
    void SetFps(std::shared_ptr<CameraSetting> &metaData, int32_t fps, bool isUpdate);
    void Prepare(ResultCallbackMode mode, std::vector<MetaType> &results);
    void UpdateSettings(std::shared_ptr<CameraSetting> &metaData);
    void StartPreviewVideoCapture();

public:
    CamRetCode result_;
    std::shared_ptr<TestCameraBase> cameraBase_ = nullptr;
    std::shared_ptr<StreamCustomer> streamCustomerPreview_ = nullptr;
    std::shared_ptr<StreamCustomer> streamCustomerSnapshot_ = nullptr;
    std::shared_ptr<StreamCustomer> streamCustomerVideo_ = nullptr;
    std::vector<StreamInfo> streamInfos_;
    CaptureInfo captureInfo_ = {};
};
#endif /* META_DATA_H */
