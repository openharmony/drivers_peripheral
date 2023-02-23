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

#include "display_composer_service.h"

#include <dlfcn.h>
#include <hdf_base.h>
#include "display_log.h"
#include "hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace Composer {
namespace V1_0 {
extern "C" IDisplayComposer *DisplayComposerImplGetInstance(void)
{
    return new (std::nothrow) DisplayComposerService();
}

DisplayComposerService::DisplayComposerService()
    : libHandle_(nullptr),
    createVdiFunc_(nullptr),
    destroyVdiFunc_(nullptr),
    vdiImpl_(nullptr),
    cmdResponser_(nullptr),
    hotPlugCb_(nullptr),
    vBlankCb_(nullptr)
{
    int32_t ret = LoadVdi();
    if (ret == HDF_SUCCESS) {
        vdiImpl_.reset(createVdiFunc_());
        CHECK_NULLPOINTER_RETURN(vdiImpl_);
        cmdResponser_ = HdiDisplayCmdResponser::Create(vdiImpl_);
        CHECK_NULLPOINTER_RETURN(cmdResponser_);
    } else {
        HDF_LOGE("%{public}s: Load composer VDI failed, lib: %{public}s", __func__, DISPLAY_COMPOSER_VDI_LIBRARY);
    }
}

DisplayComposerService::~DisplayComposerService()
{
    if ((destroyVdiFunc_ != nullptr) && (vdiImpl_ != nullptr)) {
        destroyVdiFunc_(vdiImpl_.get());
        vdiImpl_.reset();
    }
    if (libHandle_ != nullptr) {
        dlclose(libHandle_);
    }
}

int32_t DisplayComposerService::LoadVdi()
{
    const char *errStr = dlerror();
    if (errStr) {
        HDF_LOGI("%{public}s: composer loadvid, clear earlier dlerror: %{public}s", __func__, errStr);
    }
    libHandle_ = dlopen(DISPLAY_COMPOSER_VDI_LIBRARY, RTLD_LAZY);
    CHECK_NULLPOINTER_RETURN_VALUE(libHandle_, HDF_FAILURE);

    createVdiFunc_ = reinterpret_cast<CreateComposerVdiFunc>(dlsym(libHandle_, "CreateComposerVdi"));
    errStr = dlerror();
    if (errStr == nullptr || createVdiFunc_ == nullptr) {
        HDF_LOGE("%{public}s: composer CreateComposerVdi dlsym error: %{public}s", __func__, errStr);
        dlclose(libHandle_);
        return HDF_FAILURE;
    }

    destroyVdiFunc_ = reinterpret_cast<DestroyComposerVdiFunc>(dlsym(libHandle_, "DestroyComposerVdi"));
    errStr = dlerror();
    if (errStr == nullptr || destroyVdiFunc_ == nullptr) {
        HDF_LOGE("%{public}s: composer DestroyComposerVdi dlsym error: %{public}s", __func__, errStr);
        dlclose(libHandle_);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void DisplayComposerService::OnHotPlug(uint32_t outputId, bool connected, void *data)
{
    if (data != nullptr) {
        sptr<IHotPlugCallback> remoteCb = reinterpret_cast<DisplayComposerService *>(data)->hotPlugCb_;
        if (remoteCb != nullptr) {
            remoteCb->OnHotPlug(outputId, connected);
        } else {
            HDF_LOGE("%{public}s: OnHotPlug hotPlugCb_ is nullptr", __func__);
        }
    } else {
        HDF_LOGE("%{public}s: OnHotPlug cb data is nullptr", __func__);
    }
    return;
}

void DisplayComposerService::OnVBlank(unsigned int sequence, uint64_t ns, void *data)
{
    IVBlankCallback *remoteCb;
    if (data != nullptr) {
        remoteCb = reinterpret_cast<IVBlankCallback *>(data);
        if (remoteCb != nullptr) {
            remoteCb->OnVBlank(sequence, ns);
        } else {
            HDF_LOGE("%{public}s: OnVBlank hotPlugCb_ is nullptr", __func__);
        }
    } else {
        HDF_LOGE("%{public}s: OnVBlank cb data si nullptr", __func__);
    }
    return;
}

int32_t DisplayComposerService::RegHotPlugCallback(const sptr<IHotPlugCallback> &cb)
{
    hotPlugCb_ = cb;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->RegHotPlugCallback(OnHotPlug, this);
}

int32_t DisplayComposerService::GetDisplayCapability(uint32_t devId, DisplayCapability &info)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->GetDisplayCapability(devId, info);
}

int32_t DisplayComposerService::GetDisplaySupportedModes(uint32_t devId, std::vector<DisplayModeInfo> &modes)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->GetDisplaySupportedModes(devId, modes);
}

int32_t DisplayComposerService::GetDisplayMode(uint32_t devId, uint32_t &modeId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->GetDisplayMode(devId, modeId);
}

int32_t DisplayComposerService::SetDisplayMode(uint32_t devId, uint32_t modeId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->SetDisplayMode(devId, modeId);
}

int32_t DisplayComposerService::GetDisplayPowerStatus(uint32_t devId, DispPowerStatus &status)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->GetDisplayPowerStatus(devId, status);
}

int32_t DisplayComposerService::SetDisplayPowerStatus(uint32_t devId, DispPowerStatus status)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->SetDisplayPowerStatus(devId, status);
}

int32_t DisplayComposerService::GetDisplayBacklight(uint32_t devId, uint32_t &level)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->GetDisplayBacklight(devId, level);
}

int32_t DisplayComposerService::SetDisplayBacklight(uint32_t devId, uint32_t level)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->SetDisplayBacklight(devId, level);
}

int32_t DisplayComposerService::GetDisplayProperty(uint32_t devId, uint32_t id, uint64_t &value)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->GetDisplayProperty(devId, id, value);
}

int32_t DisplayComposerService::GetDisplayCompChange(
    uint32_t devId, std::vector<uint32_t> &layers, std::vector<int32_t> &type)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->GetDisplayCompChange(devId, layers, type);
}

int32_t DisplayComposerService::SetDisplayClientCrop(uint32_t devId, const IRect &rect)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->SetDisplayClientCrop(devId, rect);
}

int32_t DisplayComposerService::SetDisplayClientDestRect(uint32_t devId, const IRect &rect)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->SetDisplayClientDestRect(devId, rect);
}

int32_t DisplayComposerService::SetDisplayVsyncEnabled(uint32_t devId, bool enabled)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->SetDisplayVsyncEnabled(devId, enabled);
}

int32_t DisplayComposerService::RegDisplayVBlankCallback(uint32_t devId, const sptr<IVBlankCallback> &cb)
{
    vBlankCb_ = cb;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->RegDisplayVBlankCallback(devId, OnVBlank, vBlankCb_.GetRefPtr());
}

int32_t DisplayComposerService::GetDisplayReleaseFence(
    uint32_t devId, std::vector<uint32_t> &layers, std::vector<sptr<HdifdParcelable>> &fences)
{
    std::vector<int32_t> outFences;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ec = vdiImpl_->GetDisplayReleaseFence(devId, layers, outFences);
    for (int i = 0; i < outFences.size(); i++) {
        int32_t dupFd = outFences[i];
        sptr<HdifdParcelable> hdifd(new HdifdParcelable());
        hdifd->Init(dupFd);
        fences.push_back(hdifd);
    }
    return ec;
}

int32_t DisplayComposerService::CreateVirtualDisplay(uint32_t width, uint32_t height, int32_t &format, uint32_t &devId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->CreateVirtualDisplay(width, height, format, devId);
}

int32_t DisplayComposerService::DestroyVirtualDisplay(uint32_t devId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->DestroyVirtualDisplay(devId);
}

int32_t DisplayComposerService::SetVirtualDisplayBuffer(
    uint32_t devId, const sptr<NativeBuffer> &buffer, const sptr<HdifdParcelable> &fence)
{
    BufferHandle *handle = buffer->GetBufferHandle();
    int32_t inFence = fence->GetFd();
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->SetVirtualDisplayBuffer(devId, *handle, inFence);
}

int32_t DisplayComposerService::SetDisplayProperty(uint32_t devId, uint32_t id, uint64_t value)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->SetDisplayProperty(devId, id, value);
}

int32_t DisplayComposerService::CreateLayer(uint32_t devId, const LayerInfo &layerInfo, uint32_t &layerId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->CreateLayer(devId, layerInfo, layerId);
}

int32_t DisplayComposerService::DestroyLayer(uint32_t devId, uint32_t layerId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return vdiImpl_->DestroyLayer(devId, layerId);
}

int32_t DisplayComposerService::InitCmdRequest(const std::shared_ptr<SharedMemQueue<int32_t>> &request)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return cmdResponser_->InitCmdRequest(request);
}

int32_t DisplayComposerService::CmdRequest(
    uint32_t inEleCnt, const std::vector<HdifdInfo> &inFds, uint32_t &outEleCnt, std::vector<HdifdInfo> &outFds)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return cmdResponser_->CmdRequest(inEleCnt, inFds, outEleCnt, outFds);
}

int32_t DisplayComposerService::GetCmdReply(std::shared_ptr<SharedMemQueue<int32_t>> &reply)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    return cmdResponser_->GetCmdReply(reply);
}
} // namespace V1_0
} // namespace Composer
} // namespace Display
} // namespace HDI
} // namespace OHOS
