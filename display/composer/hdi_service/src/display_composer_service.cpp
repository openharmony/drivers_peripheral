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

#include <mutex>
#include <dlfcn.h>
#include <hdf_base.h>
#include "display_log.h"
#include "hdf_log.h"
#include "hdf_trace.h"

#undef LOG_TAG
#define LOG_TAG "COMPOSER_SRV"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002500

#undef DISPLAY_TRACE
#define DISPLAY_TRACE HdfTrace trace(__func__, "HDI:DISP:")

namespace OHOS {
namespace HDI {
namespace Display {
namespace Composer {
extern "C" V1_1::IDisplayComposer* DisplayComposerImplGetInstance(void)
{
    return new (std::nothrow) DisplayComposerService();
}

DisplayComposerService::DisplayComposerService()
    : libHandle_(nullptr),
    cacheMgr_(nullptr),
    createVdiFunc_(nullptr),
    destroyVdiFunc_(nullptr),
    currentBacklightLevel_(0),
    vdiImpl_(nullptr),
    cmdResponser_(nullptr),
    hotPlugCb_(nullptr),
    vBlankCb_(nullptr)
{
    int32_t ret = LoadVdi();
    if (ret == HDF_SUCCESS) {
        vdiImpl_ = createVdiFunc_();
        CHECK_NULLPOINTER_RETURN(vdiImpl_);
        cacheMgr_ = DeviceCacheManager::GetInstance();
        CHECK_NULLPOINTER_RETURN(cacheMgr_);
        cmdResponser_ = V1_0::HdiDisplayCmdResponser::Create(vdiImpl_, cacheMgr_);
        CHECK_NULLPOINTER_RETURN(cmdResponser_);
    } else {
        DISPLAY_LOGE("Load composer VDI failed, lib: %{public}s", DISPLAY_COMPOSER_VDI_LIBRARY);
    }
}

DisplayComposerService::~DisplayComposerService()
{
    cmdResponser_ = nullptr;
    if ((destroyVdiFunc_ != nullptr) && (vdiImpl_ != nullptr)) {
        destroyVdiFunc_(vdiImpl_);
    }
    if (libHandle_ != nullptr) {
        dlclose(libHandle_);
    }
}

int32_t DisplayComposerService::LoadVdi()
{
    const char* errStr = dlerror();
    if (errStr != nullptr) {
        DISPLAY_LOGI("composer load vdi, clear earlier dlerror: %{public}s", errStr);
    }
#ifdef COMPOSER_VDI_DEFAULT_LIBRARY_ENABLE
    libHandle_ = dlopen(DISPLAY_COMPOSER_VDI_DEFAULT_LIBRARY, RTLD_LAZY);
    if (libHandle_ == nullptr) {
        DISPLAY_LOGE("composer load vendor vdi default library failed: %{public}s",
            DISPLAY_COMPOSER_VDI_DEFAULT_LIBRARY);
#endif // COMPOSER_VDI_DEFAULT_LIBRARY_ENABLE
        libHandle_ = dlopen(DISPLAY_COMPOSER_VDI_LIBRARY, RTLD_LAZY);
        DISPLAY_LOGI("composer load vendor vdi library: %{public}s", DISPLAY_COMPOSER_VDI_LIBRARY);
#ifdef COMPOSER_VDI_DEFAULT_LIBRARY_ENABLE
    } else {
        DISPLAY_LOGI("composer load vendor vdi default library: %{public}s", DISPLAY_COMPOSER_VDI_DEFAULT_LIBRARY);
    }
#endif // COMPOSER_VDI_DEFAULT_LIBRARY_ENABLE
    CHECK_NULLPOINTER_RETURN_VALUE(libHandle_, HDF_FAILURE);

    createVdiFunc_ = reinterpret_cast<CreateComposerVdiFunc>(dlsym(libHandle_, "CreateComposerVdi"));
    if (createVdiFunc_ == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            DISPLAY_LOGE("composer CreateComposerVdi dlsym error: %{public}s", errStr);
        }
        dlclose(libHandle_);
        return HDF_FAILURE;
    }

    destroyVdiFunc_ = reinterpret_cast<DestroyComposerVdiFunc>(dlsym(libHandle_, "DestroyComposerVdi"));
    if (destroyVdiFunc_ == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            DISPLAY_LOGE("composer DestroyComposerVdi dlsym error: %{public}s", errStr);
        }
        dlclose(libHandle_);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void DisplayComposerService::OnHotPlug(uint32_t outputId, bool connected, void* data)
{
    if (data == nullptr) {
        DISPLAY_LOGE("cb data is nullptr");
        return;
    }

    auto cacheMgr = reinterpret_cast<DisplayComposerService*>(data)->cacheMgr_;
    if (cacheMgr == nullptr) {
        DISPLAY_LOGE("CacheMgr_ is nullptr");
        return;
    }
    if (connected) {
        std::lock_guard<std::mutex> lock(cacheMgr->GetCacheMgrMutex());
        // Add new device cache
        if (cacheMgr->AddDeviceCache(outputId) != HDF_SUCCESS) {
            DISPLAY_LOGE("Add device cache failed");
        }
    } else {
        std::lock_guard<std::mutex> lock(cacheMgr->GetCacheMgrMutex());
        // Del new device cache
        if (cacheMgr->RemoveDeviceCache(outputId) != HDF_SUCCESS) {
            DISPLAY_LOGE("Del device cache failed");
        }
    }

    sptr<IHotPlugCallback> remoteCb = reinterpret_cast<DisplayComposerService*>(data)->hotPlugCb_;
    if (remoteCb == nullptr) {
        DISPLAY_LOGE("hotPlugCb_ is nullptr");
        return;
    }
    remoteCb->OnHotPlug(outputId, connected);
}

void DisplayComposerService::OnVBlank(unsigned int sequence, uint64_t ns, void* data)
{
    if (data == nullptr) {
        DISPLAY_LOGE("cb data is nullptr");
        return;
    }

    IVBlankCallback* remoteCb = reinterpret_cast<IVBlankCallback*>(data);
    if (remoteCb == nullptr) {
        DISPLAY_LOGE("vblankCb_ is nullptr");
        return;
    }
    remoteCb->OnVBlank(sequence, ns);
}

int32_t DisplayComposerService::RegHotPlugCallback(const sptr<IHotPlugCallback>& cb)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    hotPlugCb_ = cb;
    int32_t ret = vdiImpl_->RegHotPlugCallback(OnHotPlug, this);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetClientBufferCacheCount(uint32_t devId, uint32_t count)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    std::lock_guard<std::mutex> lock(cacheMgr_->GetCacheMgrMutex());
    DeviceCache* devCache = cacheMgr_->DeviceCacheInstance(devId);
    DISPLAY_CHK_RETURN(devCache == nullptr, HDF_FAILURE, DISPLAY_LOGE("fail"));

    DISPLAY_CHK_RETURN(devCache->SetClientBufferCacheCount(count) != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("fail"));
    return HDF_SUCCESS;
}

int32_t DisplayComposerService::GetDisplayCapability(uint32_t devId, DisplayCapability& info)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret =  vdiImpl_->GetDisplayCapability(devId, info);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return HDF_SUCCESS;
}

int32_t DisplayComposerService::GetDisplaySupportedModes(uint32_t devId, std::vector<DisplayModeInfo>& modes)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret =  vdiImpl_->GetDisplaySupportedModes(devId, modes);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayMode(uint32_t devId, uint32_t& modeId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret =  vdiImpl_->GetDisplayMode(devId, modeId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayMode(uint32_t devId, uint32_t modeId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret =  vdiImpl_->SetDisplayMode(devId, modeId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayPowerStatus(uint32_t devId, DispPowerStatus& status)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetDisplayPowerStatus(devId, status);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayPowerStatus(uint32_t devId, DispPowerStatus status)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetDisplayPowerStatus(devId, status);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayBacklight(uint32_t devId, uint32_t& level)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetDisplayBacklight(devId, level);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_SUCCESS, level = currentBacklightLevel_);
    return ret;
}

int32_t DisplayComposerService::SetDisplayBacklight(uint32_t devId, uint32_t level)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetDisplayBacklight(devId, level);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    currentBacklightLevel_ = level;
    return ret;
}

int32_t DisplayComposerService::GetDisplayProperty(uint32_t devId, uint32_t id, uint64_t& value)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetDisplayProperty(devId, id, value);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayClientCrop(uint32_t devId, const IRect& rect)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetDisplayClientCrop(devId, rect);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayVsyncEnabled(uint32_t devId, bool enabled)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetDisplayVsyncEnabled(devId, enabled);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::RegDisplayVBlankCallback(uint32_t devId, const sptr<IVBlankCallback>& cb)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->RegDisplayVBlankCallback(devId, OnVBlank, cb.GetRefPtr());
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    vBlankCb_ = cb;
    return ret;
}

int32_t DisplayComposerService::GetDisplayReleaseFence(
    uint32_t devId, std::vector<uint32_t>& layers, std::vector<sptr<HdifdParcelable>>& fences)
{
    DISPLAY_TRACE;

    std::vector<int32_t> outFences;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetDisplayReleaseFence(devId, layers, outFences);
    for (uint i = 0; i < outFences.size(); i++) {
        int32_t dupFd = outFences[i];
        sptr<HdifdParcelable> hdifd(new HdifdParcelable());
        hdifd->Init(dupFd);
        fences.push_back(hdifd);
    }
    return ret;
}

int32_t DisplayComposerService::CreateVirtualDisplay(uint32_t width, uint32_t height, int32_t& format, uint32_t& devId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->CreateVirtualDisplay(width, height, format, devId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::DestroyVirtualDisplay(uint32_t devId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->DestroyVirtualDisplay(devId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetVirtualDisplayBuffer(
    uint32_t devId, const sptr<NativeBuffer>& buffer, const sptr<HdifdParcelable>& fence)
{
    DISPLAY_TRACE;

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
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetDisplayProperty(devId, id, value);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::CreateLayer(uint32_t devId, const LayerInfo& layerInfo, uint32_t cacheCount,
    uint32_t& layerId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->CreateLayer(devId, layerInfo, layerId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));

    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    std::lock_guard<std::mutex> lock(cacheMgr_->GetCacheMgrMutex());
    DeviceCache* devCache = cacheMgr_->DeviceCacheInstance(devId);
    DISPLAY_CHK_RETURN(devCache == nullptr, HDF_FAILURE, DISPLAY_LOGE("fail"));

    return devCache->AddLayerCache(layerId, cacheCount);
}

int32_t DisplayComposerService::DestroyLayer(uint32_t devId, uint32_t layerId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->DestroyLayer(devId, layerId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));

    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    std::lock_guard<std::mutex> lock(cacheMgr_->GetCacheMgrMutex());
    DeviceCache* devCache = cacheMgr_->DeviceCacheInstance(devId);
    DISPLAY_CHK_RETURN(devCache == nullptr, HDF_FAILURE, DISPLAY_LOGE("fail"));

    return devCache->RemoveLayerCache(layerId);
}

int32_t DisplayComposerService::GetDisplaySupportedModesExt(uint32_t devId, std::vector<DisplayModeInfoExt>& modes)
{
    DISPLAY_TRACE;
    return HDF_ERR_NOT_SUPPORT;
}

void DisplayComposerService::OnMode(uint32_t modeId, uint64_t vBlankPeriod, void* data)
{
    if (data == nullptr) {
        DISPLAY_LOGE("cb data is nullptr");
        return;
    }

    IModeCallback* remoteCb = reinterpret_cast<IModeCallback*>(data);
    if (remoteCb == nullptr) {
        DISPLAY_LOGE("remoteCb is nullptr");
        return;
    }
    remoteCb->OnMode(modeId, vBlankPeriod);
}

int32_t DisplayComposerService::SetDisplayModeAsync(uint32_t devId, uint32_t modeId, const sptr<IModeCallback>& cb)
{
    DISPLAY_TRACE;
    return HDF_ERR_NOT_SUPPORT;
}

int32_t DisplayComposerService::GetDisplayVBlankPeriod(uint32_t devId, uint64_t& period)
{
    DISPLAY_TRACE;
    return HDF_ERR_NOT_SUPPORT;
}

void DisplayComposerService::OnSeamlessChange(uint32_t devId, void* data)
{
    if (data == nullptr) {
        DISPLAY_LOGE("cb data is nullptr");
        return;
    }

    ISeamlessChangeCallback* remoteCb = reinterpret_cast<ISeamlessChangeCallback*>(data);
    if (remoteCb == nullptr) {
        DISPLAY_LOGE("remoteCb is nullptr");
        return;
    }
    remoteCb->OnSeamlessChange(devId);
}

int32_t DisplayComposerService::RegSeamlessChangeCallback(const sptr<ISeamlessChangeCallback>& cb)
{
    DISPLAY_TRACE;
    return HDF_ERR_NOT_SUPPORT;
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
} // namespace Composer
} // namespace Display
} // namespace HDI
} // namespace OHOS
