/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef CAMERA_VIDEO_TEST_H
#define CAMERA_VIDEO_TEST_H

#include "test_display.h"

class CameraVideoTest : public testing::Test {
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
    CaptureInfo captureInfo_ = {};
    std::shared_ptr<StreamCustomer> streamCustomerPreview_ = nullptr;
    std::shared_ptr<StreamCustomer> streamCustomerSnapshot_ = nullptr;
    std::shared_ptr<StreamCustomer> streamCustomerVideo_ = nullptr;
    std::vector<StreamInfo> streamInfos_;
    std::shared_ptr<TestDisplay> display_ = nullptr;
};
#endif /* CAMERA_VIDEO_TEST_H */
