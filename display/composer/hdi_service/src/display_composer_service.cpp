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
    vdiAdapter_(new(std::nothrow) DisplayComposerVdiAdapter),
    cacheMgr_(nullptr),
    currentBacklightLevel_(0),
    hotPlugCb_(nullptr),
    vBlankCb_(nullptr),
    modeCb_(nullptr),
    seamlessChangeCb_(nullptr),
    refreshCb_(nullptr),
    VBlankIdleCb_(nullptr)
{
    int32_t ret = LoadVdiSo();
    if (ret != HDF_SUCCESS) {
        DISPLAY_LOGE("LoadVdiSo failed");
        return;
    }

    if (LoadVdiAdapter() != HDF_SUCCESS) {
        ExitService();
        DISPLAY_LOGE("Create DisplayComposerService failed");
        return;
    }

    if (CreateResponser() != HDF_SUCCESS) {
        ExitService();
        DISPLAY_LOGE("CreateResponser failed");
        return;
    }

    HidumperInit();
}

DisplayComposerService::~DisplayComposerService()
{
    std::lock_guard<std::mutex> lck(mutex_);
    ExitService();
}

void DisplayComposerService::ExitService()
{
    if (vdiAdapter_ != nullptr) {
        delete vdiAdapter_;
        vdiAdapter_ = nullptr;
    }

    if (libHandle_ != nullptr) {
        dlclose(libHandle_);
        libHandle_ = nullptr;
    }
}

int32_t DisplayComposerService::LoadVdiAdapter()
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);

    LoadVdiFuncV1_0();
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->RegHotPlugCallback, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplayCapability, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplaySupportedModes, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplayMode, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayMode, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplayPowerStatus, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayPowerStatus, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplayBacklight, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayBacklight, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplayProperty, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplayCompChange, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayClientCrop, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayClientBuffer, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayClientDamage, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayVsyncEnabled, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->RegDisplayVBlankCallback, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplayReleaseFence, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->CreateVirtualDisplay, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->DestroyVirtualDisplay, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetVirtualDisplayBuffer, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayProperty, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->Commit, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->CreateLayer, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->DestroyLayer, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->PrepareDisplayLayers, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerAlpha, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerRegion, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerCrop, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerZorder, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerPreMulti, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerTransformMode, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerDirtyRegion, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerVisibleRegion, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerBuffer, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerCompositionType, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerBlendType, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerMaskInfo, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerColor, HDF_FAILURE);
    LoadVdiFuncV1_1();
    return HDF_SUCCESS;
}

void DisplayComposerService::LoadVdiFuncV1_0()
{
    vdiAdapter_->LoadVdiImpl = (LoadVdiImplFunc)(dlsym(libHandle_, "LoadVdiImpl"));
    vdiAdapter_->DestroyVdiImpl = (DestroyVdiImplFunc)(dlsym(libHandle_, "DestroyVdiImpl"));
    vdiAdapter_->RegHotPlugCallback = (RegHotPlugCallbackFunc)(dlsym(libHandle_, "RegHotPlugCallback"));
    vdiAdapter_->GetDisplayCapability = (GetDisplayCapabilityFunc)(dlsym(libHandle_, "GetDisplayCapability"));
    vdiAdapter_->GetDisplaySupportedModes =
        (GetDisplaySupportedModesFunc)(dlsym(libHandle_, "GetDisplaySupportedModes"));
    vdiAdapter_->GetDisplayMode = (GetDisplayModeFunc)(dlsym(libHandle_, "GetDisplayMode"));
    vdiAdapter_->SetDisplayMode = (SetDisplayModeFunc)(dlsym(libHandle_, "SetDisplayMode"));
    vdiAdapter_->GetDisplayPowerStatus = (GetDisplayPowerStatusFunc)(dlsym(libHandle_, "GetDisplayPowerStatus"));
    vdiAdapter_->SetDisplayPowerStatus = (SetDisplayPowerStatusFunc)(dlsym(libHandle_, "SetDisplayPowerStatus"));
    vdiAdapter_->GetDisplayBacklight = (GetDisplayBacklightFunc)(dlsym(libHandle_, "GetDisplayBacklight"));
    vdiAdapter_->SetDisplayBacklight = (SetDisplayBacklightFunc)(dlsym(libHandle_, "SetDisplayBacklight"));
    vdiAdapter_->GetDisplayProperty = (GetDisplayPropertyFunc)(dlsym(libHandle_, "GetDisplayProperty"));
    vdiAdapter_->GetDisplayCompChange = (GetDisplayCompChangeFunc)(dlsym(libHandle_, "GetDisplayCompChange"));
    vdiAdapter_->SetDisplayClientCrop = (SetDisplayClientCropFunc)(dlsym(libHandle_, "SetDisplayClientCrop"));
    vdiAdapter_->SetDisplayClientBuffer = (SetDisplayClientBufferFunc)(dlsym(libHandle_, "SetDisplayClientBuffer"));
    vdiAdapter_->SetDisplayClientDamage = (SetDisplayClientDamageFunc)(dlsym(libHandle_, "SetDisplayClientDamage"));
    vdiAdapter_->SetDisplayVsyncEnabled = (SetDisplayVsyncEnabledFunc)(dlsym(libHandle_, "SetDisplayVsyncEnabled"));
    vdiAdapter_->RegDisplayVBlankCallback =
        (RegDisplayVBlankCallbackFunc)(dlsym(libHandle_, "RegDisplayVBlankCallback"));
    vdiAdapter_->GetDisplayReleaseFence = (GetDisplayReleaseFenceFunc)(dlsym(libHandle_, "GetDisplayReleaseFence"));
    vdiAdapter_->CreateVirtualDisplay = (CreateVirtualDisplayFunc)(dlsym(libHandle_, "CreateVirtualDisplay"));
    vdiAdapter_->DestroyVirtualDisplay = (DestroyVirtualDisplayFunc)(dlsym(libHandle_, "DestroyVirtualDisplay"));
    vdiAdapter_->SetVirtualDisplayBuffer = (SetVirtualDisplayBufferFunc)(dlsym(libHandle_, "SetVirtualDisplayBuffer"));
    vdiAdapter_->SetDisplayProperty = (SetDisplayPropertyFunc)(dlsym(libHandle_, "SetDisplayProperty"));
    vdiAdapter_->Commit = (CommitFunc)(dlsym(libHandle_, "Commit"));
    vdiAdapter_->CreateLayer = (CreateLayerFunc)(dlsym(libHandle_, "CreateLayer"));
    vdiAdapter_->DestroyLayer = (DestroyLayerFunc)(dlsym(libHandle_, "DestroyLayer"));
    vdiAdapter_->PrepareDisplayLayers = (PrepareDisplayLayersFunc)(dlsym(libHandle_, "PrepareDisplayLayers"));
    vdiAdapter_->SetLayerAlpha = (SetLayerAlphaFunc)(dlsym(libHandle_, "SetLayerAlpha"));
    vdiAdapter_->SetLayerRegion = (SetLayerRegionFunc)(dlsym(libHandle_, "SetLayerRegion"));
    vdiAdapter_->SetLayerCrop = (SetLayerCropFunc)(dlsym(libHandle_, "SetLayerCrop"));
    vdiAdapter_->SetLayerZorder = (SetLayerZorderFunc)(dlsym(libHandle_, "SetLayerZorder"));
    vdiAdapter_->SetLayerPreMulti = (SetLayerPreMultiFunc)(dlsym(libHandle_, "SetLayerPreMulti"));
    vdiAdapter_->SetLayerTransformMode = (SetLayerTransformModeFunc)(dlsym(libHandle_, "SetLayerTransformMode"));
    vdiAdapter_->SetLayerDirtyRegion = (SetLayerDirtyRegionFunc)(dlsym(libHandle_, "SetLayerDirtyRegion"));
    vdiAdapter_->SetLayerVisibleRegion = (SetLayerVisibleRegionFunc)(dlsym(libHandle_, "SetLayerVisibleRegion"));
    vdiAdapter_->SetLayerBuffer = (SetLayerBufferFunc)(dlsym(libHandle_, "SetLayerBuffer"));
    vdiAdapter_->SetLayerCompositionType = (SetLayerCompositionTypeFunc)(dlsym(libHandle_, "SetLayerCompositionType"));
    vdiAdapter_->SetLayerBlendType = (SetLayerBlendTypeFunc)(dlsym(libHandle_, "SetLayerBlendType"));
    vdiAdapter_->SetLayerMaskInfo = (SetLayerMaskInfoFunc)(dlsym(libHandle_, "SetLayerMaskInfo"));
    vdiAdapter_->SetLayerColor = (SetLayerColorFunc)(dlsym(libHandle_, "SetLayerColor"));
}

void DisplayComposerService::LoadVdiFuncV1_1()
{
    vdiAdapter_->RegSeamlessChangeCallback =
        (RegSeamlessChangeCallbackFunc)(dlsym(libHandle_, "RegSeamlessChangeCallback"));
    vdiAdapter_->GetDisplaySupportedModesExt =
        (GetDisplaySupportedModesExtFunc)(dlsym(libHandle_, "GetDisplaySupportedModesExt"));
    vdiAdapter_->SetDisplayModeAsync = (SetDisplayModeAsyncFunc)(dlsym(libHandle_, "SetDisplayModeAsync"));
    vdiAdapter_->GetDisplayVBlankPeriod =
        (GetDisplayVBlankPeriodFunc)(dlsym(libHandle_, "GetDisplayVBlankPeriod"));
    vdiAdapter_->SetLayerPerFrameParameter =
        (SetLayerPerFrameParameterFunc)(dlsym(libHandle_, "SetLayerPerFrameParameter"));
    vdiAdapter_->GetSupportedLayerPerFrameParameterKey =
        (GetSupportedLayerPerFrameParameterKeyFunc)(dlsym(libHandle_, "GetSupportedLayerPerFrameParameterKey"));
    vdiAdapter_->SetDisplayOverlayResolution =
        (SetDisplayOverlayResolutionFunc)(dlsym(libHandle_, "SetDisplayOverlayResolution"));
    vdiAdapter_->RegRefreshCallback = (RegRefreshCallbackFunc)(dlsym(libHandle_, "RegRefreshCallback"));
    vdiAdapter_->GetDisplaySupportedColorGamuts =
        (GetDisplaySupportedColorGamutsFunc)(dlsym(libHandle_, "GetDisplaySupportedColorGamuts"));
    vdiAdapter_->GetHDRCapabilityInfos = (GetHDRCapabilityInfosFunc)(dlsym(libHandle_, "GetHDRCapabilityInfos"));
    vdiAdapter_->RegDisplayVBlankIdleCallback =
        (RegDisplayVBlankIdleCallbackFunc)(dlsym(libHandle_, "RegDisplayVBlankIdleCallback"));
    vdiAdapter_->SetDisplayConstraint = (SetDisplayConstraintFunc)(dlsym(libHandle_, "SetDisplayConstraint"));
    vdiAdapter_->SetHardwareCursorPosition =
        (SetHardwareCursorPositionFunc)(dlsym(libHandle_, "SetHardwareCursorPosition"));
    vdiAdapter_->EnableHardwareCursorStats =
        (EnableHardwareCursorStatsFunc)(dlsym(libHandle_, "EnableHardwareCursorStats"));
    vdiAdapter_->GetHardwareCursorStats = (GetHardwareCursorStatsFunc)(dlsym(libHandle_, "GetHardwareCursorStats"));
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

int32_t DisplayComposerService::DisplayComposerService::CreateResponser()
{
    cacheMgr_ = DeviceCacheManager::GetInstance();
    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    if (vdiAdapter_->RegDisplayVBlankIdleCallback != nullptr) {
        DISPLAY_LOGI("%{public}s Enable Map", __func__);
        cacheMgr_->SetNeedMap(true);
    }
    cmdResponser_ = V1_2::HdiDisplayCmdResponser::Create(vdiAdapter_, cacheMgr_);
    CHECK_NULLPOINTER_RETURN_VALUE(cmdResponser_, HDF_FAILURE);
    DISPLAY_LOGI("%{public}s out", __func__);
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

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    hotPlugCb_ = cb;
    int32_t ret = vdiAdapter_->RegHotPlugCallback(OnHotPlug, this);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetClientBufferCacheCount(uint32_t devId, uint32_t count)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
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

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret =  vdiAdapter_->GetDisplayCapability(devId, info);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return HDF_SUCCESS;
}

int32_t DisplayComposerService::GetDisplaySupportedModes(uint32_t devId, std::vector<DisplayModeInfo>& modes)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret =  vdiAdapter_->GetDisplaySupportedModes(devId, modes);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayMode(uint32_t devId, uint32_t& modeId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret =  vdiAdapter_->GetDisplayMode(devId, modeId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayMode(uint32_t devId, uint32_t modeId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret =  vdiAdapter_->SetDisplayMode(devId, modeId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayPowerStatus(uint32_t devId, V1_0::DispPowerStatus& status)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->GetDisplayPowerStatus(devId, status);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayPowerStatus(uint32_t devId, V1_0::DispPowerStatus status)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->SetDisplayPowerStatus(devId, status);
    DISPLAY_LOGI("devid: %{public}u, status: %{public}u, vdi return %{public}d", devId, status, ret);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetDisplayBacklight(uint32_t devId, uint32_t& level)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->GetDisplayBacklight(devId, level);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_SUCCESS, level = currentBacklightLevel_);
    return ret;
}

int32_t DisplayComposerService::SetDisplayBacklight(uint32_t devId, uint32_t level)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->SetDisplayBacklight(devId, level);
    DISPLAY_LOGD("devid: %{public}u, level: %{public}u, vdi return %{public}d", devId, level, ret);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    currentBacklightLevel_ = level;
    return ret;
}

int32_t DisplayComposerService::GetDisplayProperty(uint32_t devId, uint32_t id, uint64_t& value)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->GetDisplayProperty(devId, id, value);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetHardwareCursorPosition(uint32_t devId, int32_t x, int32_t y)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetHardwareCursorPosition, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->SetHardwareCursorPosition(devId, x, y);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::EnableHardwareCursorStats(uint32_t devId, bool enable)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->EnableHardwareCursorStats, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->EnableHardwareCursorStats(devId, enable);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetHardwareCursorStats(uint32_t devId, uint32_t& frameCount, uint32_t& vsyncCount)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->EnableHardwareCursorStats, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->GetHardwareCursorStats(devId, frameCount, vsyncCount);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayClientCrop(uint32_t devId, const IRect& rect)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->SetDisplayClientCrop(devId, rect);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayVsyncEnabled(uint32_t devId, bool enabled)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->SetDisplayVsyncEnabled(devId, enabled);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::RegDisplayVBlankCallback(uint32_t devId, const sptr<IVBlankCallback>& cb)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->RegDisplayVBlankCallback(devId, OnVBlank, cb.GetRefPtr());
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    vBlankCb_ = cb;
    return ret;
}

int32_t DisplayComposerService::GetDisplayReleaseFence(
    uint32_t devId, std::vector<uint32_t>& layers, std::vector<sptr<HdifdParcelable>>& fences)
{
    DISPLAY_TRACE;

    std::vector<int32_t> outFences;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->GetDisplayReleaseFence(devId, layers, outFences);
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

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->CreateVirtualDisplay(width, height, format, devId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::DestroyVirtualDisplay(uint32_t devId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->DestroyVirtualDisplay(devId);
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
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(handle, HDF_FAILURE);
    int32_t ret = vdiAdapter_->SetVirtualDisplayBuffer(devId, *handle, inFence);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayProperty(uint32_t devId, uint32_t id, uint64_t value)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->SetDisplayProperty(devId, id, value);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::CreateLayer(uint32_t devId, const LayerInfo& layerInfo, uint32_t cacheCount,
    uint32_t& layerId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->CreateLayer(devId, layerInfo, layerId);
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
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->DestroyLayer(devId, layerId);
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
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->RegSeamlessChangeCallback, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->RegSeamlessChangeCallback(OnSeamlessChange, this);
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
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplaySupportedModesExt, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->GetDisplaySupportedModesExt(devId, modes);
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
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayModeAsync, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->SetDisplayModeAsync(devId, modeId, OnMode, this);
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
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplayVBlankPeriod, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->GetDisplayVBlankPeriod(devId, period);
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

    if (cmdResponser_ != nullptr) {
        ret = cmdResponser_->InitCmdRequest(request);
    }
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    DISPLAY_LOGI("%{public}s out", __func__);
    return ret;
}

int32_t DisplayComposerService::CmdRequest(
    uint32_t inEleCnt, const std::vector<HdifdInfo>& inFds, uint32_t& outEleCnt, std::vector<HdifdInfo>& outFds)
{
    int32_t ret = HDF_FAILURE;

    if (cmdResponser_ != nullptr) {
        ret = cmdResponser_->CmdRequest(inEleCnt, inFds, outEleCnt, outFds);
    }
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetCmdReply(std::shared_ptr<SharedMemQueue<int32_t>>& reply)
{
    int32_t ret = HDF_FAILURE;

    if (cmdResponser_ != nullptr) {
        ret = cmdResponser_->GetCmdReply(reply);
    }
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetLayerPerFrameParameter(uint32_t devId, uint32_t layerId, const std::string& key,
    const std::vector<int8_t>& value)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetLayerPerFrameParameter, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->SetLayerPerFrameParameter(devId, layerId, key, value);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetSupportedLayerPerFrameParameterKey(std::vector<std::string>& keys)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetSupportedLayerPerFrameParameterKey, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->GetSupportedLayerPerFrameParameterKey(keys);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::SetDisplayOverlayResolution(uint32_t devId, uint32_t width, uint32_t height)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayOverlayResolution, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->SetDisplayOverlayResolution(devId, width, height);
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
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->RegRefreshCallback, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->RegRefreshCallback(OnRefresh, this);
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
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplaySupportedColorGamuts, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->GetDisplaySupportedColorGamuts(devId, gamuts);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    return ret;
}

int32_t DisplayComposerService::GetHDRCapabilityInfos(uint32_t devId, HDRCapability& info)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetHDRCapabilityInfos, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->GetHDRCapabilityInfos(devId, info);
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
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->RegDisplayVBlankIdleCallback, HDF_ERR_NOT_SUPPORT);
    VBlankIdleCb_ = cb;
    int32_t ret = vdiAdapter_->RegDisplayVBlankIdleCallback(OnVBlankIdleCallback, this);
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
