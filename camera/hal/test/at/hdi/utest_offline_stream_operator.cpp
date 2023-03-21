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

#include "utest_offline_stream_operator.h"
#include "camera.h"
#include "camera_metadata_info.h"
#include "ibuffer.h"
#include "idevice_manager.h"
#include "if_system_ability_manager.h"
#include "v1_0/ioffline_stream_operator.h"
#include "iservice_registry.h"
#include <surface.h>
#include <display_type.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define SURFACE_ID (12345 + 666 + 2333)

using namespace OHOS;
using namespace std;
using namespace testing::ext;

const int CAMERA_BUFFER_QUEUE_IPC = 654320;
uint64_t GetCurrentLocalTimeStampOFL()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return tmp.count();
}

int32_t SaveToFile(const char* type, const void* buffer, int32_t size)
{
    int ret;
    char path[PATH_MAX] = {0};
    ret = sprintf_s(path, PATH_MAX, "/mnt/%s_%lld.yuv", type, GetCurrentLocalTimeStampOFL());
    if (ret < 0) {
        std::cout << "sprintf_s failed, errno = " << strerror(errno) << std::endl;
        return -1;
    }
    int imgFd = open(path, O_RDWR | O_CREAT, 00766);
    if (imgFd == -1) {
        std::cout << "open file failed, errno = " << strerror(errno) << std::endl;
        return -1;
    }

    ret = write(imgFd, buffer, size);
    if (ret == -1) {
        std::cout << "write file failed, errno = " << strerror(errno) << std::endl;
        close(imgFd);
        return -1;
    }

    close(imgFd);
    return 0;
}

void OffileStreamOperatorImplTest::SetUpTestCase(void)
{
    std::cout << "Camera::StreamOperatorImp SetUpTestCase" << std::endl;
}

void OffileStreamOperatorImplTest::TearDownTestCase(void)
{
    std::cout << "Camera::StreamOperatorImp TearDownTestCase" << std::endl;
}

void OffileStreamOperatorImplTest::SetUp(void)
{
    bool ret = InitCameraHost();
    if (!ret) {
        std::cout << "OffileStreamOperatorImplTest init camerahost failed" << std::endl;
        return;
    }

    ret = GetCameraIds();
    if (!ret) {
        std::cout << "OffileStreamOperatorImplTest init GetCameraIds failed" << std::endl;
        return;
    }

    ret = GetCameraDevice();
    if (!ret) {
        std::cout << "OffileStreamOperatorImplTest init GetCameraDevice failed" << std::endl;
        return;
    }

    ret = GetStreamOperator();
    if (!ret) {
        std::cout << "OffileStreamOperatorImplTest init GetStreamOperator failed" << std::endl;
        return;
    }
}

void OffileStreamOperatorImplTest::TearDown(void)
{
    std::cout << "Camera::StreamOperatorImp TearDown.." << std::endl;
}

HWTEST_F(OffileStreamOperatorImplTest, UTestRelease, TestSize.Level0)
{
    CamRetCode rc;
    OHOS::sptr<IOfflineStreamOperator> offlineStreamOperator = new OfflineStreamOperator();
    ASSERT_NE(offlineStreamOperator, nullptr);
    rc = (CamRetCode)offlineStreamOperator->Release();
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);
}
