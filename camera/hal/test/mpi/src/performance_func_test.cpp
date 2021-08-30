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
#include "performance_func_test.h"
#include <fstream>
namespace {
    static const int TimeTransformation_us = 1000000;
    static const int Times = 1000;
    std::ofstream writeIntoFile;
}

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;
float PerformanceFuncTest::calTime(struct timeval start, struct timeval end)
{
    float time_use = 0;
    time_use = (end.tv_sec - start.tv_sec) * TimeTransformation_us + (end.tv_usec - start.tv_usec);
    return time_use;
}
void PerformanceFuncTest::SetUpTestCase(void) {}
void PerformanceFuncTest::TearDownTestCase(void) {}
void PerformanceFuncTest::SetUp(void) {}
void PerformanceFuncTest::TearDown(void)
{
    Test_->Close();

}

/**
  * @tc.name: Check Open camera's time consuming.
  * @tc.desc: Check Open camera's time consuming.
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(PerformanceFuncTest, Camera_Performance_0001, TestSize.Level3)
{
    std::cout << "==========[test log] Performance: Check Open camera's time consuming."<< std::endl;
    struct timeval start;
    struct timeval end;
    float time_use;
    float totle_time_use = 0;
    writeIntoFile.open("TimeConsuming.txt", ios::app);
    for (int i= 0; i < Times; i++) {
        gettimeofday(&start, NULL);
        Test_ = std::make_shared<OHOS::Camera::Test>();
        Test_->Init();
        Test_->Open();
        gettimeofday(&end, NULL);
        time_use = calTime(start, end);
        totle_time_use = totle_time_use + time_use;
        // 后处理，关闭相机
        Test_->Close();
    }
    float avrg_time = totle_time_use/ Times;
    EXPECT_LT(avrg_time, 80000);
    std::cout << "==========[test log] Performance: Open camera's average time consuming: ";
    std::cout << avrg_time << "us." << std::endl;
    writeIntoFile << "==========[test log] Performance: Open camera's average time consuming: ";
    writeIntoFile << avrg_time << "us." << std::endl;
}

/**
  * @tc.name: Check Start Streams's time consuming.
  * @tc.desc: Check Start Streams's time consuming.
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(PerformanceFuncTest, Camera_Performance_0002, TestSize.Level3)
{
    std::cout << "==========[test log] Performance: Check Start Streams's time consuming." << std::endl;
    struct timeval start;
    struct timeval end;
    float time_use;
    float totle_time_use = 0;
    writeIntoFile.open("TimeConsuming.txt", ios::app);
    Test_ = std::make_shared<OHOS::Camera::Test>();
    Test_->Init();
    Test_->Open();
    for (int i = 0; i < Times; i ++) {
        // 创建并获取streamOperator信息
        Test_->streamOperatorCallback = new StreamOperatorCallback();
        Test_->rc = Test_->cameraDevice->GetStreamOperator(Test_->streamOperatorCallback, Test_->streamOperator);
        EXPECT_EQ(false, Test_->rc != Camera::NO_ERROR || Test_->streamOperator == nullptr);
        // 创建数据流
        Test_->streamInfo = std::make_shared<Camera::StreamInfo>();
        Test_->streamInfo->streamId_ = 1001;
        Test_->streamInfo->width_ = 1920;
        Test_->streamInfo->height_ = 1080;
        Test_->streamInfo->format_ = PIXEL_FMT_YCRCB_420_SP;
        Test_->streamInfo->datasapce_ = 10;
        Test_->streamInfo->intent_ = Camera::PREVIEW;
        Test_->streamInfo->tunneledMode_ = 5;
        std::shared_ptr<OHOS::Camera::Test::StreamConsumer> preview_consumer =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
        Test_->streamInfo->bufferQueue_ = preview_consumer->CreateProducer([this](void* addr, uint32_t size) {
            Test_->SaveYUV("preview", addr, size);
        });
        Test_->streamInfo->bufferQueue_->SetQueueSize(8);
        Test_->consumerMap_[Camera::PREVIEW] = preview_consumer;
        std::vector<std::shared_ptr<Camera::StreamInfo>>().swap(Test_->streamInfos);
        Test_->streamInfos.push_back(Test_->streamInfo);
        gettimeofday(&start, NULL);
        Test_->rc = Test_->streamOperator->CreateStreams(Test_->streamInfos);
        EXPECT_EQ(Test_->rc, Camera::NO_ERROR);
        // 配流起流
        Test_->rc = Test_->streamOperator->CommitStreams(Camera::NORMAL, Test_->ability);
        gettimeofday(&end, NULL);
        EXPECT_EQ(Test_->rc, Camera::NO_ERROR);
        time_use = calTime(start, end);
        totle_time_use = totle_time_use + time_use;
        // 释放流
        Test_->rc = Test_->streamOperator->ReleaseStreams({1001});
        EXPECT_EQ(Test_->rc, Camera::NO_ERROR);
    }
    float avrg_time = totle_time_use / Times;
    EXPECT_LT(avrg_time, 100000);
    std::cout << "==========[test log] Performance: Start Streams's average time consuming: ";
    std::cout << avrg_time << "us." << std::endl;
    writeIntoFile << "==========[test log] Performance: Start Streams's average time consuming: ";
    writeIntoFile << avrg_time << "us. " << std::endl;
}

/**
  * @tc.name: Check Close camera's time consuming.
  * @tc.desc: Check Close camera's time consuming.
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(PerformanceFuncTest, Camera_Performance_0003, TestSize.Level3)
{
    std::cout << "==========[test log] Performance: Check Close camera's time consuming."<< std::endl;
    struct timeval start;
    struct timeval end;
    float time_use;
    float totle_time_use = 0;
    writeIntoFile.open("TimeConsuming.txt", ios::app);
    Test_ = std::make_shared<OHOS::Camera::Test>();
    Test_->Init();
    for (int i= 0; i < Times; i++) {
        Test_->Open();
        gettimeofday(&start, NULL);
        Test_->Close();
        gettimeofday(&end, NULL);
        time_use = calTime(start, end);
        totle_time_use = totle_time_use + time_use;

    }
    float avrg_time = totle_time_use/ Times;
    EXPECT_LT(avrg_time, 100000);
    std::cout << "==========[test log] Performance: Close camera's average time consuming: ";
    std::cout << avrg_time << "us." << std::endl;
    writeIntoFile << "==========[test log] Performance: Close camera's average time consuming: ";
    writeIntoFile << avrg_time << "us." << std::endl;
}
