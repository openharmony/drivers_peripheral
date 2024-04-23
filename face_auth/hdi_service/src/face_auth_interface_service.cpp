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
} // namespace FaceAuth
} // namespace HDI
} // namespace OHOS
