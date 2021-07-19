/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
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
#include "dfx_test.h"
#include <fstream>
#include "parameters.h"
namespace {
    static const int TimeTransformation_us = 1000000;
    static const int Times = 1000;
    std::ofstream writeIntoFile;
}

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;
float DfxTest::calTime(struct timeval start, struct timeval end)
{
    float time_use = 0;
    time_use = (end.tv_sec - start.tv_sec) * TimeTransformation_us + (end.tv_usec - start.tv_usec);
    return time_use;
}
void DfxTest::SetUpTestCase(void) {}
void DfxTest::TearDownTestCase(void) {}
void DfxTest::SetUp(void)
{
    Test_ = std::make_shared<OHOS::Camera::Test>();
    Test_->Init();
    Test_->Open();
}
void DfxTest::TearDown(void)
{
    Test_->Close();

}

/**
  * @tc.name: Check Open camera's time consuming.
  * @tc.desc: Check Open camera's time consuming.
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(DfxTest, Camera_Dfx_0001, TestSize.Level3)
{
    std::cout << "==========[test log] DFX: SetProperty & GetProperty."<< std::endl;
    bool result = false;
    std::string property="hdi_timeout";
    std::string value = "false";
    std::string parameter;
    result = OHOS::system::SetParameter(property, value);
    if(result){
        parameter = OHOS::system::GetParameter(property, value);
        std::cout << "==========[test log] DFX: GetProperty hdi_timeout = " << parameter << std::endl;
    }
    else{
        std::cout << "==========[test log] DFX: SetProperty failed." << std::endl;
    }
}

/**
  * @tc.name: Check Open camera's time consuming.
  * @tc.desc: Check Open camera's time consuming.
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(DfxTest, Camera_Dfx_0002, TestSize.Level3)
{
    std::cout << "==========[test log]Preview stream, timeout." << std::endl;
    bool result = false;
    std::string property="hdi_timeout";
    std::string value = "on";
    std::string parameter;
    result = OHOS::system::SetParameter(property, value);
    if(result){
       // 启动流
        Test_->intents = {Camera::PREVIEW};
        Test_->StartStream(Test_->intents);
        // 获取预览图
        Test_->StartCapture(Test_->streamId_preview, Test_->captureId_preview, false, true);
        // 释放流
        Test_->captureIds = {Test_->captureId_preview};
        Test_->streamIds = {Test_->streamId_preview};
        Test_->StopStream(Test_->captureIds, Test_->streamIds);
    }
}