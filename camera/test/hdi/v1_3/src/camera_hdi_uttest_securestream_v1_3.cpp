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

#include "camera_hdi_uttest_securestream_v1_3.h"
#include <functional>

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;
void CameraHdiUtTestSecureStreamV1_3::SetUpTestCase(void) {}
void CameraHdiUtTestSecureStreamV1_3::TearDownTestCase(void) {}
void CameraHdiUtTestSecureStreamV1_3::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init(); // assert inside
    cameraTest->OpenSecureCamera(DEVICE_0); // assert inside
}

void CameraHdiUtTestSecureStreamV1_3::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: Camera_Hdi_SecureStream_V1_3_001
 * @tc.desc: invoke OpenSecureCamera, verification
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestSecureStreamV1_3, Camera_Hdi_SecureStream_V1_3_001, TestSize.Level1)
{
}

/**
 * @tc.name: Camera_Hdi_SecureStream_V1_3_002
 * @tc.desc: invoke GetSecureCameraSeq, verification
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestSecureStreamV1_3, Camera_Hdi_SecureStream_V1_3_002, TestSize.Level1)
{
    EXPECT_NE(cameraTest, nullptr);
    EXPECT_NE(cameraTest->cameraDeviceV1_3, nullptr);
    uint64_t SeqId;
    int32_t res = cameraTest->cameraDeviceV1_3->GetSecureCameraSeq(SeqId);
    std::cout << "SeqId: " << SeqId << std::endl;
    EXPECT_EQ(res, HDI::Camera::V1_0::NO_ERROR);
}