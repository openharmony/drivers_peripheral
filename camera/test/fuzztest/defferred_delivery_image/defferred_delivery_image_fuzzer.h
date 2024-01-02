/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef CAMERA_DEVICE_FUZZER_H
#define CAMERA_DEVICE_FUZZER_H

#define FUZZ_PROJECT_NAME "defferred_delivery_image_fuzzer"
#include "common.h"
#include "v1_2/image_process_service_proxy.h"
#include "v1_2/iimage_process_session.h"
#include "v1_2/iimage_process_callback.h"
namespace OHOS {
    std::shared_ptr<OHOS::Camera::CameraManager> cameraTest_ = nullptr;
    sptr<OHOS::HDI::Camera::V1_2::IImageProcessService> imageProcessService_ = nullptr;
    sptr<OHOS::HDI::Camera::V1_2::IImageProcessSession> imageProcessSession_ = nullptr;
    std::vector<std::string> pendingImageIds_;
    class TestImageProcessCallback : public OHOS::HDI::Camera::V1_2::IImageProcessCallback {
    public:
        TestImageProcessCallback() = default;
        virtual ~TestImageProcessCallback() = default;
        int32_t OnProcessDone(const std::string& imageId,
            const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer) override
        {
            return 0;
        };
        int32_t OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status) override
        {
            return 0;
        };
        int32_t OnError(const std::string& imageId, OHOS::HDI::Camera::V1_2::ErrorCode errorCode) override
        {
            return 0;
        };
    };
    sptr<TestImageProcessCallback> imageProcessCallback_;
}
#endif
