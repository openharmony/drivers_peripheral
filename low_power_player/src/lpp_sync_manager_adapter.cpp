/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dlfcn.h>
#include "lpp_log.h"
#include "lpp_sync_manager_adapter.h"

namespace OHOS {
namespace HDI {
namespace LowPowerPlayer {
namespace V1_0 {

LppSyncManagerAdapter::LppSyncManagerAdapter(uint32_t instanceId)
{
    HDF_LOGI("LppSyncManagerAdapter %{public}s", __func__);
    instanceId_ = instanceId;
    int32_t ret = LoadVdi();
    if (ret == HDF_SUCCESS) {
        vdiImpl_ = createVdi_();
        CHECK_NULLPOINTER_RETURN(vdiImpl_);
    } else {
        HDF_LOGE("%{public}s: Load LPP VDI failed", __func__);
    }

    ret = vdiImpl_->Init(instanceId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Init failed", __func__);
    }
}

LppSyncManagerAdapter::~LppSyncManagerAdapter()
{
    std::lock_guard<std::mutex> lck(mutex_);

    if (vdiImpl_->Release(instanceId_) != 0) {
        HDF_LOGE("LppSyncManagerAdapter Release failed");
    }
    if (destroyVdi_ != nullptr && vdiImpl_ != nullptr) {
        destroyVdi_(vdiImpl_);
        vdiImpl_ = nullptr;
        destroyVdi_ = nullptr;
    }
}

int32_t LppSyncManagerAdapter::LoadVdi()
{
    const char* errStr = dlerror();
    if (errStr != nullptr) {
        HDF_LOGD("%{public}s: allocator load vdi, clear earlier dlerror: %{public}s", __func__, errStr);
    }
    libHandle_ = dlopen(LOW_POWER_PLAYER_VDI_LIBRARY, RTLD_LAZY);
    if (libHandle_ == nullptr) {
        HDF_LOGE("lpp load vendor vdi default library failed: %{public}s", LOW_POWER_PLAYER_VDI_LIBRARY);
    } else {
        HDF_LOGD("lpp load vendor vdi library: %{public}s", LOW_POWER_PLAYER_VDI_LIBRARY);
    }
    CHECK_NULLPOINTER_RETURN_VALUE(libHandle_, HDF_FAILURE);
    createVdi_ = reinterpret_cast<CreateLowPowerPlayerVdiFunc>(dlsym(libHandle_, "CreateLowPowerPlayerVdi"));
    if (createVdi_ == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            HDF_LOGE("%{public}s: allocator CreateLowPowerPlayerVdi dlsym error: %{public}s", __func__, errStr);
        }
        dlclose(libHandle_);
        return HDF_FAILURE;
    }
    destroyVdi_ = reinterpret_cast<DestroyLowPowerPlayerVdiFunc>(dlsym(libHandle_, "DestroyLowPowerPlayerVdi"));
    if (destroyVdi_ == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            HDF_LOGE("%{public}s: allocator DestroyLowPowerPlayerVdi dlsym error: %{public}s", __func__, errStr);
        }
        dlclose(libHandle_);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t LppSyncManagerAdapter::SetVideoChannelId(uint32_t channelId)
{
    int32_t ret = vdiImpl_->SetVideoChannelId(channelId, instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "SetVideoChannelId failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::StartRender()
{
    int32_t ret = vdiImpl_->StartRender(instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "StartRender failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::RenderNextFrame()
{
    int32_t ret = vdiImpl_->RenderNextFrame(instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "RenderNextFrame failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Pause()
{
    int32_t ret = vdiImpl_->Pause(instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Pause failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Resume()
{
    int32_t ret = vdiImpl_->Resume(instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Resume failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Flush()
{
    int32_t ret = vdiImpl_->Flush(instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Flush failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Stop()
{
    int32_t ret = vdiImpl_->Stop(instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Stop failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Reset()
{
    int32_t ret = vdiImpl_->Reset(instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Reset failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Release()
{
    int32_t ret = vdiImpl_->Release(instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Release failed.");
    return ret;
}


int32_t LppSyncManagerAdapter::SetTunnelId(uint64_t tunnelId)
{
    int32_t ret = vdiImpl_->SetTunnelId(tunnelId, instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "SetTunnelId failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::SetTargetStartFrame(uint64_t framePts, uint32_t timeoutMs)
{
    int32_t ret = vdiImpl_->SetTargetStartFrame(framePts, timeoutMs, instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "SetTargetStartFrame failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::SetPlaybackSpeed(float mode)
{
    int32_t ret = vdiImpl_->SetPlaybackSpeed(mode, instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "SetPlaybackSpeed failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::RegisterCallback(const sptr<ILppSyncManagerCallback>& syncCallback)
{
    HDF_LOGI("LppSyncManagerAdapter %{public}s", __func__);
    vdiImpl_->RegisterCallback(syncCallback, instanceId_);
    return HDF_SUCCESS;
}

int32_t LppSyncManagerAdapter::GetParameter(std::map<std::string, std::string>& parameter)
{
    int32_t ret = vdiImpl_->GetParameter(parameter, instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "GetParameter failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::GetShareBuffer(int32_t& fd)
{
    int32_t ret = vdiImpl_->GetShareBuffer(fd, instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "GetShareBuffer failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::SetParameter(const std::map<std::string, std::string>& parameter)
{
    int32_t ret = vdiImpl_->SetParameter(parameter, instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "SetParameter failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::UpdateTimeAnchor(uint64_t anchorPts, uint64_t anchorClk)
{
    int32_t ret = vdiImpl_->UpdateTimeAnchor(anchorPts, anchorClk, instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "UpdateTimeAnchor failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::BindOutputBuffers(const std::map<uint32_t, sptr<NativeBuffer>>& outputBuffers)
{
    int32_t ret = vdiImpl_->BindOutputBuffers(outputBuffers, instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "BindOutputBuffers failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::UnbindOutputBuffers()
{
    int32_t ret = vdiImpl_->UnbindOutputBuffers(instanceId_);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "UnbindOutputBuffers failed.");
    return ret;
}

}
}
}
}
