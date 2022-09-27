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
    createHwiFunc_(nullptr),
    destroyHwiFunc_(nullptr),
    hwiImpl_(nullptr),
    cmdResponser_(nullptr),
    hotPlugCb_(nullptr),
    vBlankCb_(nullptr)
{
    int32_t ret = LoadHwi();
    if (ret == HDF_SUCCESS) {
        hwiImpl_.reset(createHwiFunc_());
        CHECK_NULLPOINTER_RETURN(hwiImpl_);
        cmdResponser_ = HdiDisplayCmdResponser::Create(hwiImpl_);
        CHECK_NULLPOINTER_RETURN(cmdResponser_);
    } else {
        HDF_LOGE("error: LoadHwi failure, lib name:%{public}s", DISPLAY_COMPOSER_HWI_LIBRARY_NAME);
    }
}

DisplayComposerService::~DisplayComposerService()
{
    if (destroyHwiFunc_ != nullptr && hwiImpl_ != nullptr) {
        destroyHwiFunc_(hwiImpl_.get());
        hwiImpl_.reset();
    }
    if (libHandle_ != nullptr) {
        dlclose(libHandle_);
    }
}

int32_t DisplayComposerService::LoadHwi()
{
    const char *errStr = dlerror();
    if (errStr) {
        HDF_LOGI("warning, existing dlerror: %{public}s", errStr);
    }
    libHandle_ = dlopen(DISPLAY_COMPOSER_HWI_LIBRARY_NAME, RTLD_LAZY);
    CHECK_NULLPOINTER_RETURN_VALUE(libHandle_, HDF_FAILURE);

    createHwiFunc_ = reinterpret_cast<CreateComposerHwiFunc_t *>(dlsym(libHandle_, "CreateComposerHwi"));
    errStr = dlerror();
    if (errStr) {
        HDF_LOGE("error: %{public}s", errStr);
        return HDF_FAILURE;
    }

    destroyHwiFunc_ = reinterpret_cast<DestroyComposerHwiFunc_t *>(dlsym(libHandle_, "DestroyComposerHwi"));
    errStr = dlerror();
    if (errStr) {
        HDF_LOGE("error: %{public}s", errStr);
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
            HDF_LOGE("error: OnHotPlug hotPlugCb_ nullptr");
        }
    } else {
        HDF_LOGE("error: OnHotPlug cb data nullptr");
    }
    return;
}

void DisplayComposerService::OnVBlank(unsigned int sequence, uint64_t ns, void *data)
{
    if (data != nullptr) {
        IVBlankCallback *remoteCb = reinterpret_cast<IVBlankCallback *>(data);
        if (remoteCb != nullptr) {
            remoteCb->OnVBlank(sequence, ns);
        } else {
            HDF_LOGE("error: OnVBlank hotPlugCb_ nullptr");
        }
    } else {
        HDF_LOGE("error: OnVBlank cb data nullptr");
    }
    return;
}

int32_t DisplayComposerService::RegHotPlugCallback(const sptr<IHotPlugCallback> &cb)
{
    hotPlugCb_ = cb;
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->RegHotPlugCallback(OnHotPlug, this);
}

int32_t DisplayComposerService::GetDisplayCapability(uint32_t devId, DisplayCapability &info)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->GetDisplayCapability(devId, info);
}

int32_t DisplayComposerService::GetDisplaySupportedModes(uint32_t devId, std::vector<DisplayModeInfo> &modes)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->GetDisplaySupportedModes(devId, modes);
}

int32_t DisplayComposerService::GetDisplayMode(uint32_t devId, uint32_t &modeId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->GetDisplayMode(devId, modeId);
}

int32_t DisplayComposerService::SetDisplayMode(uint32_t devId, uint32_t modeId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->SetDisplayMode(devId, modeId);
}

int32_t DisplayComposerService::GetDisplayPowerStatus(uint32_t devId, DispPowerStatus &status)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->GetDisplayPowerStatus(devId, status);
}

int32_t DisplayComposerService::SetDisplayPowerStatus(uint32_t devId, DispPowerStatus status)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->SetDisplayPowerStatus(devId, status);
}

int32_t DisplayComposerService::GetDisplayBacklight(uint32_t devId, uint32_t &level)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->GetDisplayBacklight(devId, level);
}

int32_t DisplayComposerService::SetDisplayBacklight(uint32_t devId, uint32_t level)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->SetDisplayBacklight(devId, level);
}

int32_t DisplayComposerService::GetDisplayProperty(uint32_t devId, uint32_t id, uint64_t &value)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->GetDisplayProperty(devId, id, value);
}

int32_t DisplayComposerService::GetDisplayCompChange(
    uint32_t devId, std::vector<uint32_t> &layers, std::vector<int32_t> &type)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->GetDisplayCompChange(devId, layers, type);
}

int32_t DisplayComposerService::SetDisplayClientCrop(uint32_t devId, const IRect &rect)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->SetDisplayClientCrop(devId, rect);
}

int32_t DisplayComposerService::SetDisplayClientDestRect(uint32_t devId, const IRect &rect)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->SetDisplayClientDestRect(devId, rect);
}

int32_t DisplayComposerService::SetDisplayVsyncEnabled(uint32_t devId, bool enabled)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->SetDisplayVsyncEnabled(devId, enabled);
}

int32_t DisplayComposerService::RegDisplayVBlankCallback(uint32_t devId, const sptr<IVBlankCallback> &cb)
{
    vBlankCb_ = cb;
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->RegDisplayVBlankCallback(devId, OnVBlank, vBlankCb_.GetRefPtr());
}

int32_t DisplayComposerService::GetDisplayReleaseFence(
    uint32_t devId, std::vector<uint32_t> &layers, std::vector<sptr<HdifdParcelable>> &fences)
{
    std::vector<int32_t> outFences;
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    int32_t ec = hwiImpl_->GetDisplayReleaseFence(devId, layers, outFences);
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
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->CreateVirtualDisplay(width, height, format, devId);
}

int32_t DisplayComposerService::DestroyVirtualDisplay(uint32_t devId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->DestroyVirtualDisplay(devId);
}

int32_t DisplayComposerService::SetVirtualDisplayBuffer(
    uint32_t devId, const sptr<BufferHandleParcelable> &buffer, const sptr<HdifdParcelable> &fence)
{
    BufferHandle *handle = buffer->GetBufferHandle();
    int32_t inFence = fence->GetFd();
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->SetVirtualDisplayBuffer(devId, *handle, inFence);
}

int32_t DisplayComposerService::SetDisplayProperty(uint32_t devId, uint32_t id, uint64_t value)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->SetDisplayProperty(devId, id, value);
}

int32_t DisplayComposerService::CreateLayer(uint32_t devId, const LayerInfo &layerInfo, uint32_t &layerId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->CreateLayer(devId, layerInfo, layerId);
}

int32_t DisplayComposerService::DestroyLayer(uint32_t devId, uint32_t layerId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return hwiImpl_->DestroyLayer(devId, layerId);
}

int32_t DisplayComposerService::InitCmdRequest(const std::shared_ptr<SharedMemQueue<int32_t>> &request)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return cmdResponser_->InitCmdRequest(request);
}

int32_t DisplayComposerService::CmdRequest(
    uint32_t inEleCnt, const std::vector<HdifdInfo> &inFds, uint32_t &outEleCnt, std::vector<HdifdInfo> &outFds)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return cmdResponser_->CmdRequest(inEleCnt, inFds, outEleCnt, outFds);
}

int32_t DisplayComposerService::GetCmdReply(std::shared_ptr<SharedMemQueue<int32_t>> &reply)
{
    CHECK_NULLPOINTER_RETURN_VALUE(hwiImpl_, HDF_FAILURE);
    return cmdResponser_->GetCmdReply(reply);
}
} // namespace V1_0
} // namespace Composer
} // namespace Display
} // namespace HDI
} // namespace OHOS
