/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CAMERA_TAG_UTTEST_V1_1_H
#define CAMERA_TAG_UTTEST_V1_1_H

#include "hdi_common_v1_1.h"

class CameraTagUtTestV1_1 : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
    void TakePhotoWithTags(std::shared_ptr<OHOS::Camera::CameraSetting> meta);
    void TakePhotoWithTags(std::shared_ptr<OHOS::Camera::CameraSetting> meta, OHOS::Camera::OperationMode_V1_1 mode);
    std::shared_ptr<OHOS::Camera::HdiCommonV1_1> cameraTest = nullptr;
};
#endif
