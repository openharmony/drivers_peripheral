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

static std::mutex mutex_;
static std::shared_ptr<void> libHandle_ = nullptr;
static CreateLowPowerPlayerVdiFunc createVdi_ = nullptr;
static DestroyLowPowerPlayerVdiFunc destroyVdi_ = nullptr;

LppSyncManagerAdapter::~LppSyncManagerAdapter()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (vdiImpl_ != nullptr) {
        destroyVdi_(vdiImpl_);
        vdiImpl_ = nullptr;
    }
}

int32_t LppSyncManagerAdapter::LoadVendorLib()
{
    if (libHandle_ == nullptr) {
        void* handle = dlopen(LOW_POWER_PLAYER_VDI_LIBRARY, RTLD_LAZY);
        CHECK_TRUE_RETURN_RET_LOG(handle == nullptr, HDF_FAILURE, "dlopen failed, %{public}s", dlerror());
        libHandle_ = std::shared_ptr<void>(handle, dlclose);
    }

    if (createVdi_ == nullptr) {
        createVdi_ = reinterpret_cast<CreateLowPowerPlayerVdiFunc>(dlsym(libHandle_.get(), "CreateLowPowerPlayerVdi"));
        CHECK_TRUE_RETURN_RET_LOG(createVdi_ == nullptr, HDF_FAILURE, "createVdi_ dlsym failed, %{public}s", dlerror());
    }

    if (destroyVdi_ == nullptr) {
        destroyVdi_ =
            reinterpret_cast<DestroyLowPowerPlayerVdiFunc>(dlsym(libHandle_.get(), "DestroyLowPowerPlayerVdi"));
        CHECK_TRUE_RETURN_RET_LOG(
            destroyVdi_ == nullptr, HDF_FAILURE, "destroyVdi_ dlsym failed, %{public}s", dlerror());
    }
    return HDF_SUCCESS;
}

int32_t LppSyncManagerAdapter::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = LoadVendorLib();
    CHECK_TRUE_RETURN_RET_LOG(ret != HDF_SUCCESS, HDF_FAILURE, "load vdi failed");

    vdiImpl_ = createVdi_();
    CHECK_TRUE_RETURN_RET_LOG(vdiImpl_ == nullptr, HDF_FAILURE, "createVdi_ failed");

    ret = vdiImpl_->Init();
    CHECK_TRUE_RETURN_RET_LOG(ret != HDF_SUCCESS, HDF_FAILURE, "Init failed");
    return HDF_SUCCESS;
}

int32_t LppSyncManagerAdapter::SetVideoChannelId(uint32_t channelId)
{
    int32_t ret = vdiImpl_->SetVideoChannelId(channelId);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "SetVideoChannelId failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::StartRender()
{
    int32_t ret = vdiImpl_->StartRender();
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "StartRender failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::RenderNextFrame()
{
    int32_t ret = vdiImpl_->RenderNextFrame();
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "RenderNextFrame failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Pause()
{
    int32_t ret = vdiImpl_->Pause();
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Pause failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Resume()
{
    int32_t ret = vdiImpl_->Resume();
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Resume failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Flush()
{
    int32_t ret = vdiImpl_->Flush();
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Flush failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Stop()
{
    int32_t ret = vdiImpl_->Stop();
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Stop failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Reset()
{
    int32_t ret = vdiImpl_->Reset();
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Reset failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::Release()
{
    int32_t ret = vdiImpl_->Release();
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "Release failed.");
    return ret;
}


int32_t LppSyncManagerAdapter::SetTunnelId(uint64_t tunnelId)
{
    int32_t ret = vdiImpl_->SetTunnelId(tunnelId);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "SetTunnelId failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::SetTargetStartFrame(int64_t framePts, uint32_t timeoutMs)
{
    int32_t ret = vdiImpl_->SetTargetStartFrame(framePts, timeoutMs);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "SetTargetStartFrame failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::SetPlaybackSpeed(float mode)
{
    int32_t ret = vdiImpl_->SetPlaybackSpeed(mode);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "SetPlaybackSpeed failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::RegisterCallback(const sptr<ILppSyncManagerCallback>& syncCallback)
{
    int32_t ret = vdiImpl_->RegisterCallback(syncCallback);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "RegisterCallback failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::GetParameter(std::map<std::string, std::string>& parameter)
{
    int32_t ret = vdiImpl_->GetParameter(parameter);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "GetParameter failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::GetShareBuffer(int32_t& fd)
{
    int32_t ret = vdiImpl_->GetShareBuffer(fd);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "GetShareBuffer failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::SetParameter(const std::map<std::string, std::string>& parameter)
{
    int32_t ret = vdiImpl_->SetParameter(parameter);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "SetParameter failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::UpdateTimeAnchor(int64_t anchorPts, uint64_t anchorClk)
{
    int32_t ret = vdiImpl_->UpdateTimeAnchor(anchorPts, anchorClk);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "UpdateTimeAnchor failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::BindOutputBuffers(const std::map<uint32_t, sptr<NativeBuffer>>& outputBuffers)
{
    int32_t ret = vdiImpl_->BindOutputBuffers(outputBuffers);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "BindOutputBuffers failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::UnbindOutputBuffers()
{
    int32_t ret = vdiImpl_->UnbindOutputBuffers();
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "UnbindOutputBuffers failed.");
    return ret;
}

int32_t LppSyncManagerAdapter::GetLatestPts(int64_t& pts)
{
    int32_t ret = vdiImpl_->GetLatestPts(pts);
    CHECK_TRUE_RETURN_RET_LOG(HDF_SUCCESS != ret, HDF_FAILURE, "GetLatestPts failed.");
    return ret;
}

}
}
}
}