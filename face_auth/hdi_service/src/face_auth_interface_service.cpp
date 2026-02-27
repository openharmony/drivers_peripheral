/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "face_auth_interface_service.h"

#include <hdf_base.h>

#include "all_in_one_executor_impl.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#undef LOG_TAG
#define LOG_TAG "FACE_AUTH_IMPL"

namespace OHOS {
namespace HDI {
namespace FaceAuth {
extern "C" IFaceAuthInterface *FaceAuthInterfaceImplGetInstance(void)
{
    auto faceAuthInterfaceService = new (std::nothrow) FaceAuthInterfaceService();
    if (faceAuthInterfaceService == nullptr) {
        IAM_LOGE("faceAuthInterfaceService is nullptr");
        return nullptr;
    }
    return faceAuthInterfaceService;
}

FaceAuthInterfaceService::FaceAuthInterfaceService()
{
    auto executor = new (std::nothrow) AllInOneExecutorImpl();
    if (executor == nullptr) {
        IAM_LOGE("executor is nullptr");
        return;
    }
    executorList_.push_back(sptr<IAllInOneExecutor>(executor));
}

int32_t FaceAuthInterfaceService::GetExecutorList(std::vector<sptr<IAllInOneExecutor>> &executorList)
{
    IAM_LOGI("interface mock start");
    for (auto executor : executorList_) {
        executorList.push_back(executor);
    }
    IAM_LOGI("interface mock success");
    return HDF_SUCCESS;
}

int32_t FaceAuthInterfaceService::SetBufferProducer(const sptr<BufferProducerSequenceable> &bufferProducer)
{
    IAM_LOGI("interface mock start set buffer producer %{public}s",
        UserIam::Common::GetPointerNullStateString(bufferProducer.GetRefPtr()).c_str());
    return HDF_SUCCESS;
}

int32_t FaceAuthInterfaceService::SetCameraController(const sptr<ICameraControllerCallback>& cameraController)
{
    IAM_LOGI("interface mock start set camera controller %{public}s",
        UserIam::Common::GetPointerNullStateString(cameraController.GetRefPtr()).c_str());
    return HDF_SUCCESS;
}

int32_t FaceAuthInterfaceService::GetCameraSettings(uint64_t scheduleId, const std::vector<uint8_t>& cameraAbility,
    std::vector<uint8_t>& cameraSettings)
{
    IAM_LOGI("interface mock start get camera settings start, ability len %{public}zu, settings len %{public}zu",
        cameraAbility.size(), cameraSettings.size());
    static_cast<void>(scheduleId);
    IAM_LOGI("interface mock start get camera settings end");
    return HDF_SUCCESS;
}

int32_t FaceAuthInterfaceService::SetCameraSecureSeqId(uint64_t scheduleId, uint64_t secureSeqId)
{
    IAM_LOGI("interface mock start set camera secure seq id start");
    static_cast<void>(scheduleId);
    static_cast<void>(secureSeqId);
    IAM_LOGI("interface mock start set camera secure seq id end");
    return HDF_SUCCESS;
}

int32_t FaceAuthInterfaceService::OnCameraError(uint64_t scheduleId, int32_t resultCode)
{
    IAM_LOGI("interface mock start received camera error start");
    static_cast<void>(scheduleId);
    static_cast<void>(resultCode);
    IAM_LOGI("interface mock start received camera error end");
    return HDF_SUCCESS;
}
} // namespace FaceAuth
} // namespace HDI
} // namespace OHOS
