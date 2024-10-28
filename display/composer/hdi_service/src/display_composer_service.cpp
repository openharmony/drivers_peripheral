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
#ifdef DISPLAY_COMPOSER_SERVICE_HIDUMPER
    #include "display_dump_service.h"
#endif

#undef LOG_TAG
#define LOG_TAG "COMPOSER_SRV"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002515

#undef DISPLAY_TRACE
#define DISPLAY_TRACE HdfTrace trace(__func__, "HDI:DISP:")

namespace OHOS {
namespace HDI {
namespace Display {
namespace Composer {
extern "C" V1_2::IDisplayComposer* DisplayComposerImplGetInstance(void)
{
    return new (std::nothrow) DisplayComposerService();
}

DisplayComposerService::DisplayComposerService()
    : libHandle_(nullptr),
    cacheMgr_(nullptr),
    currentBacklightLevel_(0),
    hotPlugCb_(nullptr),
    vBlankCb_(nullptr),
    modeCb_(nullptr),
    seamlessChangeCb_(nullptr),
    vdiImpl_(nullptr),
    destroyVdiFunc_(nullptr),
    cmdResponser_(nullptr),
    vdiImplV1_1_(nullptr),
    destroyVdiFuncV1_1_(nullptr),
    cmdResponserV1_1_(nullptr),
    refreshCb_(nullptr),
    VBlankIdleCb_(nullptr)
{
    int32_t ret = LoadVdiSo();
    if (ret != HDF_SUCCESS) {
        DISPLAY_LOGE("Load composer VDI failed, lib: %{public}s", DISPLAY_COMPOSER_VDI_LIBRARY);
        return;
    }

    ret = LoadVdiV1_1();
    if (ret != HDF_SUCCESS) {
        ret = LoadVdiV1_0();
    }

    if (ret != HDF_SUCCESS) {
        dlclose(libHandle_);
        libHandle_ = nullptr;
        DISPLAY_LOGE("Load composer VDI function failed");
    }

    HidumperInit();
}

DisplayComposerService::~DisplayComposerService()
{
    std::lock_guard<std::mutex> lck(mutex_);
    cmdResponser_ = nullptr;
    cmdResponserV1_1_ = nullptr;

    if ((destroyVdiFunc_ != nullptr) && (vdiImpl_ != nullptr)) {
        destroyVdiFunc_(vdiImpl_);
        vdiImpl_ = nullptr;
        destroyVdiFunc_ = nullptr;
    }

    if ((destroyVdiFuncV1_1_ != nullptr) && (vdiImplV1_1_ != nullptr)) {
        destroyVdiFuncV1_1_(vdiImplV1_1_);
        vdiImplV1_1_ = nullptr;
        destroyVdiFuncV1_1_ = nullptr;
    }

    if (libHandle_ != nullptr) {
        dlclose(libHandle_);
        libHandle_ = nullptr;
    }
}

void DisplayComposerService::HidumperInit()
{
#ifdef DISPLAY_COMPOSER_SERVICE_HIDUMPER
    VdiDumper& dumper = VdiDumper::GetInstance();
    dumper.SetDumpInfoFunc(reinterpret_cast<GetDumpInfoFunc>(dlsym(libHandle_, "GetDumpInfo")));
    dumper.SetConfigFunc(reinterpret_cast<UpdateConfigFunc>(dlsym(libHandle_, "UpdateConfig")));
    (void)DevHostRegisterDumpHost(ComposerDumpEvent);
#endif
}

int32_t DisplayComposerService::LoadVdiSo()
{
    const char* errStr = dlerror();
    if (errStr != nullptr) {
        DISPLAY_LOGD("composer load vdi, clear earlier dlerror: %{public}s", errStr);
    }
#ifdef COMPOSER_VDI_DEFAULT_LIBRARY_ENABLE
    libHandle_ = dlopen(DISPLAY_COMPOSER_VDI_DEFAULT_LIBRARY, RTLD_LAZY);
    if (libHandle_ == nullptr) {
        DISPLAY_LOGE("composer load vendor vdi default library failed: %{public}s",
            DISPLAY_COMPOSER_VDI_DEFAULT_LIBRARY);
#endif // COMPOSER_VDI_DEFAULT_LIBRARY_ENABLE
        libHandle_ = dlopen(DISPLAY_COMPOSER_VDI_LIBRARY, RTLD_LAZY);
        DISPLAY_LOGD("composer load vendor vdi library: %{public}s", DISPLAY_COMPOSER_VDI_LIBRARY);
#ifdef COMPOSER_VDI_DEFAULT_LIBRARY_ENABLE
    } else {
        DISPLAY_LOGD("composer load vendor vdi default library: %{public}s", DISPLAY_COMPOSER_VDI_DEFAULT_LIBRARY);
    }
#endif // COMPOSER_VDI_DEFAULT_LIBRARY_ENABLE
    CHECK_NULLPOINTER_RETURN_VALUE(libHandle_, HDF_FAILURE);

    return HDF_SUCCESS;
}

int32_t DisplayComposerService::LoadVdiV1_0()
{
    CreateComposerVdiFunc createVdiFunc = nullptr;
    const char* errStr = nullptr;

    createVdiFunc = reinterpret_cast<CreateComposerVdiFunc>(dlsym(libHandle_, "CreateComposerVdi"));
    if (createVdiFunc == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            DISPLAY_LOGE("CreateVdiFuncV1_0 dlsym error: %{public}s", errStr);
        }
        return HDF_FAILURE;
    }

    destroyVdiFunc_ = reinterpret_cast<DestroyComposerVdiFunc>(dlsym(libHandle_, "DestroyComposerVdi"));
    if (destroyVdiFunc_ == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            DISPLAY_LOGE("DestroyVdiFuncV1_0 dlsym error: %{public}s", errStr);
        }
        return HDF_FAILURE;
    }

    vdiImpl_ = createVdiFunc();
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    cacheMgr_ = DeviceCacheManager::GetInstance();
    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    cacheMgr_->SetNeedMap(false);
    cmdResponser_ = V1_2::HdiDisplayCmdResponser::Create(vdiImpl_, cacheMgr_);
    CHECK_NULLPOINTER_RETURN_VALUE(cmdResponser_, HDF_FAILURE);
    return HDF_SUCCESS;
}

int32_t DisplayComposerService::LoadVdiV1_1()
{
    CreateComposerVdiFuncV1_1 createVdiFunc = nullptr;
    const char* errStr = nullptr;

    createVdiFunc = reinterpret_cast<CreateComposerVdiFuncV1_1>(dlsym(libHandle_, "CreateComposerVdiV1_1"));
    if (createVdiFunc == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            DISPLAY_LOGE("CreateVdiFuncV1_1 dlsym error: %{public}s", errStr);
        }
        return HDF_FAILURE;
    }

    destroyVdiFuncV1_1_ = reinterpret_cast<DestroyComposerVdiFuncV1_1>(dlsym(libHandle_, "DestroyComposerVdiV1_1"));
    if (destroyVdiFuncV1_1_ == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            DISPLAY_LOGE("DestroyVdiFuncV1_1 dlsym error: %{public}s", errStr);
        }
        return HDF_FAILURE;
    }

    vdiImplV1_1_ = createVdiFunc();
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImplV1_1_, HDF_FAILURE);
    vdiImpl_ = dynamic_cast<IDisplayComposerVdi*>(vdiImplV1_1_);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    cacheMgr_ = DeviceCacheManager::GetInstance();
    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    cacheMgr_->SetNeedMap(true);
    cmdResponserV1_1_ = V1_2::HdiDisplayCmdResponser_1_1::CreateV1_1(vdiImplV1_1_, cacheMgr_);
    CHECK_NULLPOINTER_RETURN_VALUE(cmdResponserV1_1_, HDF_FAILURE);
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

int32_t DisplayComposerService::GetDisplayPowerStatus(uint32_t devId, V1_0::DispPowerStatus& status)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetDisplayPowerStatus(devId, status);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayPowerStatus(uint32_t devId, V1_0::DispPowerStatus status)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetDisplayPowerStatus(devId, status);
    DISPLAY_LOGI("devid: %{public}u, status: %{public}u, vdi return %{public}d", devId, status, ret);
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
    DISPLAY_LOGD("devid: %{public}u, level: %{public}u, vdi return %{public}d", devId, level, ret);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    currentBacklightLevel_ = level;
    return ret;
}

int32_t DisplayComposerService::GetDisplayProperty(uint32_t devId, uint32_t id, uint64_t& value)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetDisplayProperty(devId, id, value);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetHardwareCursorPosition(uint32_t devId, int32_t x, int32_t y)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImplV1_1_, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->SetHardwareCursorPosition(devId, x, y);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::EnableHardwareCursorStats(uint32_t devId, bool enable)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImplV1_1_, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->EnableHardwareCursorStats(devId, enable);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetHardwareCursorStats(uint32_t devId, uint32_t& frameCount, uint32_t& vsyncCount)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiImplV1_1_, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->GetHardwareCursorStats(devId, frameCount, vsyncCount);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
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
        CHECK_NULLPOINTER_RETURN_VALUE(hdifd, HDF_FAILURE);
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

    CHECK_NULLPOINTER_RETURN_VALUE(buffer, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(fence, HDF_FAILURE);
    BufferHandle* handle = buffer->GetBufferHandle();
    int32_t inFence = fence->GetFd();
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(handle, HDF_FAILURE);
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

int32_t DisplayComposerService::RegSeamlessChangeCallback(const sptr<ISeamlessChangeCallback>& cb)
{
    DISPLAY_TRACE;
    DISPLAY_CHK_RETURN(vdiImplV1_1_ == nullptr, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->RegSeamlessChangeCallback(OnSeamlessChange, this);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    if (ret == HDF_SUCCESS) {
        seamlessChangeCb_ = cb;
    }
    return ret;
}

int32_t DisplayComposerService::GetDisplaySupportedModesExt(uint32_t devId, std::vector<DisplayModeInfoExt>& modes)
{
    DISPLAY_TRACE;
    DISPLAY_CHK_RETURN(vdiImplV1_1_ == nullptr, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->GetDisplaySupportedModesExt(devId, modes);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

void DisplayComposerService::OnMode(uint32_t modeId, uint64_t vBlankPeriod, void* data)
{
    if (data == nullptr) {
        DISPLAY_LOGE("data is nullptr");
        return;
    }

    sptr<IModeCallback> remoteCb = reinterpret_cast<DisplayComposerService*>(data)->modeCb_;
    if (remoteCb == nullptr) {
        DISPLAY_LOGE("remoteCb is nullptr");
        return;
    }
    remoteCb->OnMode(modeId, vBlankPeriod);
}

int32_t DisplayComposerService::SetDisplayModeAsync(uint32_t devId, uint32_t modeId, const sptr<IModeCallback>& cb)
{
    DISPLAY_TRACE;
    DISPLAY_CHK_RETURN(vdiImplV1_1_ == nullptr, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->SetDisplayModeAsync(devId, modeId, OnMode, this);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    if (ret == HDF_SUCCESS) {
        modeCb_ = cb;
    }
    return ret;
}

int32_t DisplayComposerService::GetDisplayVBlankPeriod(uint32_t devId, uint64_t& period)
{
    DISPLAY_TRACE;
    DISPLAY_CHK_RETURN(vdiImplV1_1_ == nullptr, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->GetDisplayVBlankPeriod(devId, period);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

void DisplayComposerService::OnSeamlessChange(uint32_t devId, void* data)
{
    if (data == nullptr) {
        DISPLAY_LOGE("data is nullptr");
        return;
    }

    sptr<ISeamlessChangeCallback> remoteCb = reinterpret_cast<DisplayComposerService*>(data)->seamlessChangeCb_;
    if (remoteCb == nullptr) {
        DISPLAY_LOGE("remoteCb is nullptr");
        return;
    }
    remoteCb->OnSeamlessChange(devId);
}

int32_t DisplayComposerService::InitCmdRequest(const std::shared_ptr<SharedMemQueue<int32_t>>& request)
{
    CHECK_NULLPOINTER_RETURN_VALUE(request, HDF_FAILURE);
    int32_t ret = HDF_FAILURE;

    if (cmdResponserV1_1_ != nullptr) {
        ret = cmdResponserV1_1_->InitCmdRequest(request);
    } else if (cmdResponser_ != nullptr) {
        ret = cmdResponser_->InitCmdRequest(request);
    }
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::CmdRequest(
    uint32_t inEleCnt, const std::vector<HdifdInfo>& inFds, uint32_t& outEleCnt, std::vector<HdifdInfo>& outFds)
{
    int32_t ret = HDF_FAILURE;

    if (cmdResponserV1_1_ != nullptr) {
        ret = cmdResponserV1_1_->CmdRequest(inEleCnt, inFds, outEleCnt, outFds);
    } else if (cmdResponser_ != nullptr) {
        ret = cmdResponser_->CmdRequest(inEleCnt, inFds, outEleCnt, outFds);
    }
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetCmdReply(std::shared_ptr<SharedMemQueue<int32_t>>& reply)
{
    int32_t ret = HDF_FAILURE;

    if (cmdResponserV1_1_ != nullptr) {
        ret = cmdResponserV1_1_->GetCmdReply(reply);
    } else if (cmdResponser_ != nullptr) {
        ret = cmdResponser_->GetCmdReply(reply);
    }
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetLayerPerFrameParameter(uint32_t devId, uint32_t layerId, const std::string& key,
    const std::vector<int8_t>& value)
{
    DISPLAY_TRACE;
    DISPLAY_CHK_RETURN(vdiImplV1_1_ == nullptr, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->SetLayerPerFrameParameter(devId, layerId, key, value);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetSupportedLayerPerFrameParameterKey(std::vector<std::string>& keys)
{
    DISPLAY_TRACE;
    DISPLAY_CHK_RETURN(vdiImplV1_1_ == nullptr, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->GetSupportedLayerPerFrameParameterKey(keys);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayOverlayResolution(uint32_t devId, uint32_t width, uint32_t height)
{
    DISPLAY_TRACE;
    DISPLAY_CHK_RETURN(vdiImplV1_1_ == nullptr, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->SetDisplayOverlayResolution(devId, width, height);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

void DisplayComposerService::OnRefresh(uint32_t devId, void *data)
{
    if (data == nullptr) {
        DISPLAY_LOGE("cb data is nullptr");
        return;
    }

    sptr<IRefreshCallback> remoteCb = reinterpret_cast<DisplayComposerService*>(data)->refreshCb_;
    if (remoteCb == nullptr) {
        DISPLAY_LOGE("remoteCb is nullptr");
        return;
    }
    remoteCb->OnRefresh(devId);
}

int32_t DisplayComposerService::RegRefreshCallback(const sptr<IRefreshCallback>& cb)
{
    DISPLAY_TRACE;
    DISPLAY_CHK_RETURN(vdiImplV1_1_ == nullptr, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->RegRefreshCallback(OnRefresh, this);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    if (ret == HDF_SUCCESS) {
        refreshCb_ = cb;
    }
    return ret;
}

int32_t DisplayComposerService::GetDisplaySupportedColorGamuts(uint32_t devId, std::vector<ColorGamut>& gamuts)
{
    DISPLAY_TRACE;
    DISPLAY_CHK_RETURN(vdiImplV1_1_ == nullptr, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->GetDisplaySupportedColorGamuts(devId, gamuts);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetHDRCapabilityInfos(uint32_t devId, HDRCapability& info)
{
    DISPLAY_TRACE;
    DISPLAY_CHK_RETURN(vdiImplV1_1_ == nullptr, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiImplV1_1_->GetHDRCapabilityInfos(devId, info);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

void DisplayComposerService::OnVBlankIdleCallback(uint32_t devId, uint64_t ns, void* data)
{
    if (data == nullptr) {
        DISPLAY_LOGE("cb data is nullptr");
        return;
    }

    sptr<IVBlankIdleCallback> remoteCb = reinterpret_cast<DisplayComposerService*>(data)->VBlankIdleCb_;

    if (remoteCb == nullptr) {
        DISPLAY_LOGE("VBlankIdleCb_ is nullptr");
        return;
    }
    remoteCb->OnVBlankIdleCallback(devId, ns);
}

int32_t DisplayComposerService::RegDisplayVBlankIdleCallback(const sptr<IVBlankIdleCallback>& cb)
{
    DISPLAY_TRACE;
    DISPLAY_CHK_RETURN(vdiImplV1_1_ == nullptr, HDF_ERR_NOT_SUPPORT);
    VBlankIdleCb_ = cb;
    int32_t ret = vdiImplV1_1_->RegDisplayVBlankIdleCallback(OnVBlankIdleCallback, this);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::ClearClientBuffer(uint32_t devId)
{
    DISPLAY_LOGI("enter, devId %{public}u", devId);
    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    std::lock_guard<std::mutex> lock(cacheMgr_->GetCacheMgrMutex());
    DeviceCache* devCache = cacheMgr_->DeviceCacheInstance(devId);
    DISPLAY_CHK_RETURN(devCache == nullptr, HDF_FAILURE, DISPLAY_LOGE("fail"));

    return devCache->ClearClientCache();
}

int32_t DisplayComposerService::ClearLayerBuffer(uint32_t devId, uint32_t layerId)
{
    DISPLAY_LOGI("enter, devId %{public}u, layerId %{public}u", devId, layerId);
    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    std::lock_guard<std::mutex> lock(cacheMgr_->GetCacheMgrMutex());
    DeviceCache* devCache = cacheMgr_->DeviceCacheInstance(devId);
    DISPLAY_CHK_RETURN(devCache == nullptr, HDF_FAILURE, DISPLAY_LOGE("fail"));

    return devCache->ClearLayerBuffer(layerId);
}

} // namespace Composer
} // namespace Display
} // namespace HDI
} // namespace OHOS
