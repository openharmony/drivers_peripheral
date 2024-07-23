/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file expected in compliance with the License.
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
#include "adapter_test.h"

void UtestAdapterTest::SetUpTestCase(void)
{}
void UtestAdapterTest::TearDownTestCase(void)
{}
void UtestAdapterTest::SetUp(void)
{
    if (cameraBase == nullptr)
    cameraBase = std::make_shared<TestCameraBase>();
    cameraBase->FBInit();
    cameraBase->Init();
}
void UtestAdapterTest::TearDown(void)
{
    cameraBase->Close();
}

/**
  * @tc.name: OpenCamera cameraID input error
  * @tc.desc: OpenCamera, cameraID is not found.
  * @tc.level: level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestAdapterTest, camera_adapter_0001)
{
    std::cout << "==========[test log] Preview stream, expected success." << std::endl;
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}