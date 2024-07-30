/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "motion_if_service.h"
#include <hdf_base.h>
#include "hitrace_meter.h"

#define HDF_LOG_TAG "uhdf_motion_service"

namespace OHOS {
namespace HDI {
namespace Motion {
namespace V1_1 {
MotionIfService::MotionIfService()
{
    int32_t ret = GetMotionVdiImpl();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s get motion vdi impl failed!", __func__);
    }
}

MotionIfService::~MotionIfService()
{
    if (vdi_ != nullptr) {
        HdfCloseVdi(vdi_);
    }
}

int32_t MotionIfService::GetMotionVdiImpl()
{
    struct WrapperMotionVdi *wrapperMotionVdi = nullptr;
    uint32_t version = 0;
    vdi_ = HdfLoadVdi(HDI_MOTION_VDI_LIBNAME);
    if (vdi_ == nullptr || vdi_->vdiBase == nullptr) {
        HDF_LOGE("%{public}s load motion vdi failed!", __func__);
        return HDF_FAILURE;
    }

    version = HdfGetVdiVersion(vdi_);
    if (version != 1) {
        HDF_LOGE("%{public}s get motion vdi  version failed!", __func__);
        return HDF_FAILURE;
    }

    wrapperMotionVdi = reinterpret_cast<struct WrapperMotionVdi *>(vdi_->vdiBase);
    motionVdiImpl_ = wrapperMotionVdi->motionModule;
    if (motionVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s get motion impl failed!", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}
int32_t MotionIfService::Init()
{
    if (motionVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s get motion vdi  version failed!", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = motionVdiImpl_->InitMotion();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s impl init failed,error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t MotionIfService::EnableMotion(int32_t motionType)
{
    HDF_LOGI("%{public}s: motionType is %{public}d", __func__, motionType);
    if (motionVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s motionVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    if ((motionType < HDF_MOTION_TYPE_PICKUP) || (motionType >= HDF_MOTION_TYPE_MAX)) {
        return HDF_ERR_INVALID_PARAM;
    }

    StartTrace(HITRACE_TAG_HDF, "EnableMotion");
    int32_t ret = motionVdiImpl_->EnableMotion(motionType);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Enable failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t MotionIfService::DisableMotion(int32_t motionType)
{
    HDF_LOGI("%{public}s: motionType is %{public}d", __func__, motionType);
    if (motionVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s motionVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    if ((motionType < HDF_MOTION_TYPE_PICKUP) || (motionType >= HDF_MOTION_TYPE_MAX)) {
        return HDF_ERR_INVALID_PARAM;
    }

    StartTrace(HITRACE_TAG_HDF, "DisableMotion");
    int32_t ret = motionVdiImpl_->DisableMotion(motionType);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Disable failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t MotionIfService::Register(const sptr<IMotionCallback> &callbackObj)
{
    HDF_LOGI("%{public}s", __func__);
    if (motionVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s motionVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "Register");
    sptr<MotionCallbackVdi> motionCb = new MotionCallbackVdi(callbackObj);
    int32_t ret = motionVdiImpl_->RegisterMotionCallback(motionCb);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Register failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t MotionIfService::Unregister(const sptr<IMotionCallback> &callbackObj)
{
    HDF_LOGI("%{public}s", __func__);
    if (motionVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s motionVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "Unregister");
    sptr<MotionCallbackVdi> motionCb = new MotionCallbackVdi(callbackObj);
    int32_t ret = motionVdiImpl_->UnregisterMotionCallback(motionCb);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Unregister failed, Unregistererror code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t MotionIfService::SetMotionConfig(int32_t motionType, const std::vector<uint8_t>& data)
{
    HDF_LOGI("%{public}s: motionType is %{public}d", __func__, motionType);
    if (motionVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s motionVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "SetMotionConfig");
    int32_t ret = motionVdiImpl_->SetMotionConfig(motionType, data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SetMotionConfig failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

extern "C" IMotionInterface *MotionInterfaceImplGetInstance(void)
{
    MotionIfService *impl = new (std::nothrow) MotionIfService();
    if (impl == nullptr) {
        return nullptr;
    }

    int32_t ret = impl->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s service init failed, error code is %{public}d", __func__, ret);
        delete impl;
        return nullptr;
    }

    return impl;
}
} // V1_1
} //Motion
} //HDI
} //OHOS
