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
extern "C" IDisplayComposer* DisplayComposerImplGetInstance(void)
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
    const char* errStr = dlerror();
    if (errStr != nullptr) {
        HDF_LOGI("%{public}s: composer loadvid, clear earlier dlerror: %{public}s", __func__, errStr);
    }
    libHandle_ = dlopen(DISPLAY_COMPOSER_VDI_LIBRARY, RTLD_LAZY);
    CHECK_NULLPOINTER_RETURN_VALUE(libHandle_, HDF_FAILURE);

    createVdiFunc_ = reinterpret_cast<CreateComposerVdiFunc>(dlsym(libHandle_, "CreateComposerVdi"));
    errStr = dlerror();
    if (errStr != nullptr || createVdiFunc_ == nullptr) {
        HDF_LOGE("%{public}s: composer CreateComposerVdi dlsym error: %{public}s", __func__, errStr);
        dlclose(libHandle_);
        return HDF_FAILURE;
    }

    destroyVdiFunc_ = reinterpret_cast<DestroyComposerVdiFunc>(dlsym(libHandle_, "DestroyComposerVdi"));
    errStr = dlerror();
    if (errStr != nullptr || destroyVdiFunc_ == nullptr) {
        HDF_LOGE("%{public}s: composer DestroyComposerVdi dlsym error: %{public}s", __func__, errStr);
        dlclose(libHandle_);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void DisplayComposerService::OnHotPlug(uint32_t outputId, bool connected, void* data)
{
    if (data == nullptr) {
        HDF_LOGE("%{public}s: cb data is nullptr", __func__);
        return;
    }

    sptr<IHotPlugCallback> remoteCb = reinterpret_cast<DisplayComposerService*>(data)->hotPlugCb_;
    if (remoteCb == nullptr) {
        HDF_LOGE("%{public}s: hotPlugCb_ is nullptr", __func__);
        return;
    }
    remoteCb->OnHotPlug(outputId, connected);
}

void DisplayComposerService::OnVBlank(unsigned int sequence, uint64_t ns, void* data)
{
    if (data == nullptr) {
        HDF_LOGE("%{public}s: cb data is nullptr", __func__);
        return;
    }

    IVBlankCallback* remoteCb = reinterpret_cast<IVBlankCallback*>(data);
    if (remoteCb == nullptr) {
        HDF_LOGE("%{public}s: vblankCb_ is nullptr", __func__);
        return;
    }
    remoteCb->OnVBlank(sequence, ns);
}

int32_t DisplayComposerService::RegHotPlugCallback(const sptr<IHotPlugCallback>& cb)
{
    hotPlugCb_ = cb;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->RegHotPlugCallback(OnHotPlug, this);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayCapability(uint32_t devId, DisplayCapability& info)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret =  vdiImpl_->GetDisplayCapability(devId, info);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplaySupportedModes(uint32_t devId, std::vector<DisplayModeInfo>& modes)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret =  vdiImpl_->GetDisplaySupportedModes(devId, modes);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayMode(uint32_t devId, uint32_t& modeId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret =  vdiImpl_->GetDisplayMode(devId, modeId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayMode(uint32_t devId, uint32_t modeId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret =  vdiImpl_->SetDisplayMode(devId, modeId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayPowerStatus(uint32_t devId, DispPowerStatus& status)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetDisplayPowerStatus(devId, status);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayPowerStatus(uint32_t devId, DispPowerStatus status)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetDisplayPowerStatus(devId, status);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayBacklight(uint32_t devId, uint32_t& level)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetDisplayBacklight(devId, level);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayBacklight(uint32_t devId, uint32_t level)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetDisplayBacklight(devId, level);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayProperty(uint32_t devId, uint32_t id, uint64_t& value)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetDisplayProperty(devId, id, value);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayCompChange(
    uint32_t devId, std::vector<uint32_t>& layers, std::vector<int32_t>& type)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetDisplayCompChange(devId, layers, type);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayClientCrop(uint32_t devId, const IRect& rect)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetDisplayClientCrop(devId, rect);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayVsyncEnabled(uint32_t devId, bool enabled)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetDisplayVsyncEnabled(devId, enabled);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::RegDisplayVBlankCallback(uint32_t devId, const sptr<IVBlankCallback>& cb)
{
    vBlankCb_ = cb;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->RegDisplayVBlankCallback(devId, OnVBlank, vBlankCb_.GetRefPtr());
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayReleaseFence(
    uint32_t devId, std::vector<uint32_t>& layers, std::vector<sptr<HdifdParcelable>>& fences)
{
    std::vector<int32_t> outFences;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetDisplayReleaseFence(devId, layers, outFences);
    for (int i = 0; i < outFences.size(); i++) {
        int32_t dupFd = outFences[i];
        sptr<HdifdParcelable> hdifd(new HdifdParcelable());
        hdifd->Init(dupFd);
        fences.push_back(hdifd);
    }
    return ret;
}

int32_t DisplayComposerService::CreateVirtualDisplay(uint32_t width, uint32_t height, int32_t& format, uint32_t& devId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->CreateVirtualDisplay(width, height, format, devId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::DestroyVirtualDisplay(uint32_t devId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->DestroyVirtualDisplay(devId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetVirtualDisplayBuffer(
    uint32_t devId, const sptr<NativeBuffer>& buffer, const sptr<HdifdParcelable>& fence)
{
    CHECK_NULLPOINTER_RETURN_VALUE(fence, HDF_FAILURE);
    BufferHandle* handle = buffer->GetBufferHandle();
    int32_t inFence = fence->GetFd();
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetVirtualDisplayBuffer(devId, *handle, inFence);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayProperty(uint32_t devId, uint32_t id, uint64_t value)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetDisplayProperty(devId, id, value);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::CreateLayer(uint32_t devId, const LayerInfo& layerInfo, uint32_t& layerId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->CreateLayer(devId, layerInfo, layerId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::DestroyLayer(uint32_t devId, uint32_t layerId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->DestroyLayer(devId, layerId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::InitCmdRequest(const std::shared_ptr<SharedMemQueue<int32_t>>& request)
{
    CHECK_NULLPOINTER_RETURN_VALUE(request, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = cmdResponser_->InitCmdRequest(request);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::CmdRequest(
    uint32_t inEleCnt, const std::vector<HdifdInfo>& inFds, uint32_t& outEleCnt, std::vector<HdifdInfo>& outFds)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = cmdResponser_->CmdRequest(inEleCnt, inFds, outEleCnt, outFds);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetCmdReply(std::shared_ptr<SharedMemQueue<int32_t>>& reply)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = cmdResponser_->GetCmdReply(reply);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}
} // namespace V1_0
} // namespace Composer
} // namespace Display
} // namespace HDI
} // namespace OHOS
