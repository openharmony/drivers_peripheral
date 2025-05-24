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
#include <parameters.h>
#include <param_wrapper.h>
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

const std::string BOOTEVENT_COMPOSER_HOST_READY = "bootevent.composer_host.ready";

extern "C" V1_2::IDisplayComposer* DisplayComposerImplGetInstance(void)
{
    return new (std::nothrow) DisplayComposerService();
}

DisplayComposerService::DisplayComposerService()
    : libHandle_(nullptr),
    vdiAdapter_(new(std::nothrow) DisplayComposerVdiAdapter),
    cacheMgr_(nullptr),
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

    OHOS::system::SetParameter(BOOTEVENT_COMPOSER_HOST_READY.c_str(), "true");
    vsyncEnableStatus_.clear();
    currentBacklightLevel_.clear();
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

    LoadVdiFuncPart1();
    LoadVdiFuncPart2();
    LoadVdiFuncPart3();
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
    return HDF_SUCCESS;
}

void DisplayComposerService::LoadVdiFuncPart1()
{
    vdiAdapter_->RegHotPlugCallback =
        reinterpret_cast<RegHotPlugCallbackFunc>(dlsym(libHandle_, "RegHotPlugCallback"));
    vdiAdapter_->GetDisplayCapability =
        reinterpret_cast<GetDisplayCapabilityFunc>(dlsym(libHandle_, "GetDisplayCapability"));
    vdiAdapter_->GetDisplaySupportedModes =
        reinterpret_cast<GetDisplaySupportedModesFunc>(dlsym(libHandle_, "GetDisplaySupportedModes"));
    vdiAdapter_->GetDisplayMode = reinterpret_cast<GetDisplayModeFunc>(dlsym(libHandle_, "GetDisplayMode"));
    vdiAdapter_->SetDisplayMode = reinterpret_cast<SetDisplayModeFunc>(dlsym(libHandle_, "SetDisplayMode"));
    vdiAdapter_->GetDisplayPowerStatus =
        reinterpret_cast<GetDisplayPowerStatusFunc>(dlsym(libHandle_, "GetDisplayPowerStatus"));
    vdiAdapter_->SetDisplayPowerStatus =
        reinterpret_cast<SetDisplayPowerStatusFunc>(dlsym(libHandle_, "SetDisplayPowerStatus"));
    vdiAdapter_->GetDisplayBacklight =
        reinterpret_cast<GetDisplayBacklightFunc>(dlsym(libHandle_, "GetDisplayBacklight"));
    vdiAdapter_->SetDisplayBacklight =
        reinterpret_cast<SetDisplayBacklightFunc>(dlsym(libHandle_, "SetDisplayBacklight"));
    vdiAdapter_->GetDisplayProperty =
        reinterpret_cast<GetDisplayPropertyFunc>(dlsym(libHandle_, "GetDisplayProperty"));
    vdiAdapter_->GetDisplayCompChange =
        reinterpret_cast<GetDisplayCompChangeFunc>(dlsym(libHandle_, "GetDisplayCompChange"));
    vdiAdapter_->SetDisplayClientCrop =
        reinterpret_cast<SetDisplayClientCropFunc>(dlsym(libHandle_, "SetDisplayClientCrop"));
    vdiAdapter_->SetDisplayClientBuffer =
        reinterpret_cast<SetDisplayClientBufferFunc>(dlsym(libHandle_, "SetDisplayClientBuffer"));
    vdiAdapter_->SetDisplayClientDamage =
        reinterpret_cast<SetDisplayClientDamageFunc>(dlsym(libHandle_, "SetDisplayClientDamage"));
    vdiAdapter_->SetDisplayVsyncEnabled =
        reinterpret_cast<SetDisplayVsyncEnabledFunc>(dlsym(libHandle_, "SetDisplayVsyncEnabled"));
    vdiAdapter_->RegDisplayVBlankCallback =
        reinterpret_cast<RegDisplayVBlankCallbackFunc>(dlsym(libHandle_, "RegDisplayVBlankCallback"));
    vdiAdapter_->GetDisplayReleaseFence =
        reinterpret_cast<GetDisplayReleaseFenceFunc>(dlsym(libHandle_, "GetDisplayReleaseFence"));
    vdiAdapter_->CreateVirtualDisplay =
        reinterpret_cast<CreateVirtualDisplayFunc>(dlsym(libHandle_, "CreateVirtualDisplay"));
    vdiAdapter_->DestroyVirtualDisplay =
        reinterpret_cast<DestroyVirtualDisplayFunc>(dlsym(libHandle_, "DestroyVirtualDisplay"));
    vdiAdapter_->SetVirtualDisplayBuffer =
        reinterpret_cast<SetVirtualDisplayBufferFunc>(dlsym(libHandle_, "SetVirtualDisplayBuffer"));
    vdiAdapter_->SetDisplayProperty =
        reinterpret_cast<SetDisplayPropertyFunc>(dlsym(libHandle_, "SetDisplayProperty"));
    vdiAdapter_->Commit = reinterpret_cast<CommitFunc>(dlsym(libHandle_, "Commit"));
    vdiAdapter_->CreateLayer = reinterpret_cast<CreateLayerFunc>(dlsym(libHandle_, "CreateLayer"));
    vdiAdapter_->DestroyLayer = reinterpret_cast<DestroyLayerFunc>(dlsym(libHandle_, "DestroyLayer"));
    vdiAdapter_->PrepareDisplayLayers =
        reinterpret_cast<PrepareDisplayLayersFunc>(dlsym(libHandle_, "PrepareDisplayLayers"));
    vdiAdapter_->SetLayerAlpha = reinterpret_cast<SetLayerAlphaFunc>(dlsym(libHandle_, "SetLayerAlpha"));
    vdiAdapter_->SetLayerRegion = reinterpret_cast<SetLayerRegionFunc>(dlsym(libHandle_, "SetLayerRegion"));
}

void DisplayComposerService::LoadVdiFuncPart2()
{
    vdiAdapter_->SetLayerCrop = reinterpret_cast<SetLayerCropFunc>(dlsym(libHandle_, "SetLayerCrop"));
    vdiAdapter_->SetLayerZorder = reinterpret_cast<SetLayerZorderFunc>(dlsym(libHandle_, "SetLayerZorder"));
    vdiAdapter_->SetLayerPreMulti = reinterpret_cast<SetLayerPreMultiFunc>(dlsym(libHandle_, "SetLayerPreMulti"));
    vdiAdapter_->SetLayerTransformMode =
        reinterpret_cast<SetLayerTransformModeFunc>(dlsym(libHandle_, "SetLayerTransformMode"));
    vdiAdapter_->SetLayerDirtyRegion =
        reinterpret_cast<SetLayerDirtyRegionFunc>(dlsym(libHandle_, "SetLayerDirtyRegion"));
    vdiAdapter_->SetLayerVisibleRegion =
        reinterpret_cast<SetLayerVisibleRegionFunc>(dlsym(libHandle_, "SetLayerVisibleRegion"));
    vdiAdapter_->SetLayerBuffer = reinterpret_cast<SetLayerBufferFunc>(dlsym(libHandle_, "SetLayerBuffer"));
    vdiAdapter_->SetLayerCompositionType =
        reinterpret_cast<SetLayerCompositionTypeFunc>(dlsym(libHandle_, "SetLayerCompositionType"));
    vdiAdapter_->SetLayerBlendType =
        reinterpret_cast<SetLayerBlendTypeFunc>(dlsym(libHandle_, "SetLayerBlendType"));
    vdiAdapter_->SetLayerMaskInfo = reinterpret_cast<SetLayerMaskInfoFunc>(dlsym(libHandle_, "SetLayerMaskInfo"));
    vdiAdapter_->SetLayerColor = reinterpret_cast<SetLayerColorFunc>(dlsym(libHandle_, "SetLayerColor"));
    vdiAdapter_->RegSeamlessChangeCallback =
        reinterpret_cast<RegSeamlessChangeCallbackFunc>(dlsym(libHandle_, "RegSeamlessChangeCallback"));
    vdiAdapter_->GetDisplaySupportedModesExt =
        reinterpret_cast<GetDisplaySupportedModesExtFunc>(dlsym(libHandle_, "GetDisplaySupportedModesExt"));
    vdiAdapter_->SetDisplayModeAsync =
        reinterpret_cast<SetDisplayModeAsyncFunc>(dlsym(libHandle_, "SetDisplayModeAsync"));
    vdiAdapter_->GetDisplayVBlankPeriod =
        reinterpret_cast<GetDisplayVBlankPeriodFunc>(dlsym(libHandle_, "GetDisplayVBlankPeriod"));
    vdiAdapter_->SetLayerPerFrameParameter =
        reinterpret_cast<SetLayerPerFrameParameterFunc>(dlsym(libHandle_, "SetLayerPerFrameParameter"));
    vdiAdapter_->GetSupportedLayerPerFrameParameterKey = reinterpret_cast<GetSupportedLayerPerFrameParameterKeyFunc>(
        dlsym(libHandle_, "GetSupportedLayerPerFrameParameterKey"));
    vdiAdapter_->SetDisplayOverlayResolution =
        reinterpret_cast<SetDisplayOverlayResolutionFunc>(dlsym(libHandle_, "SetDisplayOverlayResolution"));
    vdiAdapter_->RegRefreshCallback =
        reinterpret_cast<RegRefreshCallbackFunc>(dlsym(libHandle_, "RegRefreshCallback"));
    vdiAdapter_->GetDisplaySupportedColorGamuts =
        reinterpret_cast<GetDisplaySupportedColorGamutsFunc>(dlsym(libHandle_, "GetDisplaySupportedColorGamuts"));
    vdiAdapter_->GetHDRCapabilityInfos =
        reinterpret_cast<GetHDRCapabilityInfosFunc>(dlsym(libHandle_, "GetHDRCapabilityInfos"));
    vdiAdapter_->RegDisplayVBlankIdleCallback =
        reinterpret_cast<RegDisplayVBlankIdleCallbackFunc>(dlsym(libHandle_, "RegDisplayVBlankIdleCallback"));
    vdiAdapter_->SetDisplayConstraint =
        reinterpret_cast<SetDisplayConstraintFunc>(dlsym(libHandle_, "SetDisplayConstraint"));
    vdiAdapter_->UpdateHardwareCursor =
        reinterpret_cast<UpdateHardwareCursorFunc>(dlsym(libHandle_, "UpdateHardwareCursor"));
    vdiAdapter_->EnableHardwareCursorStats =
        reinterpret_cast<EnableHardwareCursorStatsFunc>(dlsym(libHandle_, "EnableHardwareCursorStats"));
    vdiAdapter_->GetHardwareCursorStats =
        reinterpret_cast<GetHardwareCursorStatsFunc>(dlsym(libHandle_, "GetHardwareCursorStats"));
    vdiAdapter_->FastPresent = reinterpret_cast<FastPresentFunc>(dlsym(libHandle_, "FastPresent"));
}

void DisplayComposerService::LoadVdiFuncPart3()
{
    vdiAdapter_->SetDisplayActiveRegion =
        reinterpret_cast<SetDisplayActiveRegionFunc>(dlsym(libHandle_, "SetDisplayActiveRegion"));
    vdiAdapter_->ClearDisplayClientBuffer =
        reinterpret_cast<ClearDisplayClientBufferFunc>(dlsym(libHandle_, "ClearDisplayClientBuffer"));
    vdiAdapter_->ClearLayerBuffer =
        reinterpret_cast<ClearLayerBufferFunc>(dlsym(libHandle_, "ClearLayerBuffer"));
    vdiAdapter_->SetDisplayPerFrameParameter =
        reinterpret_cast<SetDisplayPerFrameParameterFunc>(dlsym(libHandle_, "SetDisplayPerFrameParameter"));
    vdiAdapter_->GetDisplayIdentificationData =
        reinterpret_cast<GetDisplayIdentificationDataFunc>(dlsym(libHandle_, "GetDisplayIdentificationData"));
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
        DISPLAY_LOGE("cb data is nullptr outputId:%{public}u, connected:%{public}d", outputId, connected);
        return;
    }

    auto cacheMgr = reinterpret_cast<DisplayComposerService*>(data)->cacheMgr_;
    if (cacheMgr == nullptr) {
        DISPLAY_LOGE("CacheMgr_ is nullptr outputId:%{public}u, connected:%{public}d", outputId, connected);
        return;
    }
    if (connected) {
        std::lock_guard<std::mutex> lock(cacheMgr->GetCacheMgrMutex());
        // Add new device cache
        if (cacheMgr->AddDeviceCache(outputId) != HDF_SUCCESS) {
            DISPLAY_LOGE("Add device cache failed outputId:%{public}u, connected:%{public}d", outputId, connected);
        }
    }

    auto vsyncEnableStatus = reinterpret_cast<DisplayComposerService*>(data)->vsyncEnableStatus_;
    auto currentBacklightLevel = reinterpret_cast<DisplayComposerService*>(data)->currentBacklightLevel_;
    vsyncEnableStatus[outputId] = false;
    currentBacklightLevel[outputId] = 0;
	
    sptr<IHotPlugCallback> remoteCb = reinterpret_cast<DisplayComposerService*>(data)->hotPlugCb_;
    if (remoteCb == nullptr) {
        DISPLAY_LOGE("hotPlugCb_ is nullptr outputId:%{public}u, connected:%{public}d", outputId, connected);
        return;
    }
    remoteCb->OnHotPlug(outputId, connected);
}

void DisplayComposerService::OnVBlank(unsigned int sequence, uint64_t ns, void* data)
{
    if (data == nullptr) {
        DISPLAY_LOGE("cb data is nullptr sequence:%{public}u", sequence);
        return;
    }

    IVBlankCallback* remoteCb = reinterpret_cast<IVBlankCallback*>(data);
    if (remoteCb == nullptr) {
        DISPLAY_LOGE("vblankCb_ is nullptr sequence:%{public}u", sequence);
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
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("%{public}s fail", __func__));
    return ret;
}

int32_t DisplayComposerService::SetClientBufferCacheCount(uint32_t devId, uint32_t count)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    std::lock_guard<std::mutex> lock(cacheMgr_->GetCacheMgrMutex());
    DeviceCache* devCache = cacheMgr_->DeviceCacheInstance(devId);
    DISPLAY_CHK_RETURN(devCache == nullptr, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail, devId:%{public}u, count:%{public}u", __func__, devId, count));

    DISPLAY_CHK_RETURN(devCache->SetClientBufferCacheCount(count) != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail, devId:%{public}u, count:%{public}u", __func__, devId, count));
    return HDF_SUCCESS;
}

int32_t DisplayComposerService::GetDisplayCapability(uint32_t devId, DisplayCapability& info)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret =  vdiAdapter_->GetDisplayCapability(devId, info);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));
    DISPLAY_LOGI("%{public}s fail devId:%{public}u, width:%{public}u, height:%{public}u, count:%{public}u",
        __func__, devId, info.phyWidth, info.phyHeight, info.propertyCount);
    return HDF_SUCCESS;
}

int32_t DisplayComposerService::GetDisplaySupportedModes(uint32_t devId, std::vector<DisplayModeInfo>& modes)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret =  vdiAdapter_->GetDisplaySupportedModes(devId, modes);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));
    return ret;
}

int32_t DisplayComposerService::GetDisplayMode(uint32_t devId, uint32_t& modeId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret =  vdiAdapter_->GetDisplayMode(devId, modeId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, modeId:%{public}u", __func__, devId, modeId));
    return ret;
}

int32_t DisplayComposerService::SetDisplayMode(uint32_t devId, uint32_t modeId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret =  vdiAdapter_->SetDisplayMode(devId, modeId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, modeId:%{public}u", __func__, devId, modeId));
    return ret;
}

int32_t DisplayComposerService::GetDisplayPowerStatus(uint32_t devId, V1_0::DispPowerStatus& status)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->GetDisplayPowerStatus(devId, status);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, status:%{public}u", __func__, devId, status));
    return ret;
}

int32_t DisplayComposerService::SetDisplayPowerStatus(uint32_t devId, V1_0::DispPowerStatus status)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->SetDisplayPowerStatus(devId, status);
    DISPLAY_LOGI("devid: %{public}u, status: %{public}u, vdi return %{public}d", devId, status, ret);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(" fail"));
    if (vsyncEnableStatus_[devId]) {
        (void)SetDisplayVsyncEnabled(devId, false);
        vsyncEnableStatus_[devId] = false;
    }

    if (status == V1_0::DispPowerStatus::POWER_STATUS_OFF) {
        currentBacklightLevel_[devId] = 0;
    }

    return ret;
}

int32_t DisplayComposerService::GetDisplayBacklight(uint32_t devId, uint32_t& level)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->GetDisplayBacklight(devId, level);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_SUCCESS, level = currentBacklightLevel_[devId]);
    return ret;
}

int32_t DisplayComposerService::SetDisplayBacklight(uint32_t devId, uint32_t level)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->SetDisplayBacklight(devId, level);
    DISPLAY_LOGD("devid: %{public}u, level: %{public}u, vdi return %{public}d", devId, level, ret);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, level:%{public}u", __func__, devId, level));
    currentBacklightLevel_[devId] = level;
    return ret;
}

int32_t DisplayComposerService::GetDisplayProperty(uint32_t devId, uint32_t id, uint64_t& value)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->GetDisplayProperty(devId, id, value);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, id:%{public}u", __func__, devId, id));
    return ret;
}

int32_t DisplayComposerService::UpdateHardwareCursor(uint32_t devId, int32_t x, int32_t y,
    const sptr<NativeBuffer>& buffer)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->UpdateHardwareCursor, HDF_ERR_NOT_SUPPORT);
    CHECK_NULLPOINTER_RETURN_VALUE(buffer, HDF_ERR_NOT_SUPPORT);
    BufferHandle* handle = buffer->GetBufferHandle();
    int32_t ret = vdiAdapter_->UpdateHardwareCursor(devId, x, y, handle);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));
    return ret;
}

int32_t DisplayComposerService::EnableHardwareCursorStats(uint32_t devId, bool enable)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->EnableHardwareCursorStats, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->EnableHardwareCursorStats(devId, enable);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, enable:%{public}d", __func__, devId, enable));
    return ret;
}

int32_t DisplayComposerService::GetHardwareCursorStats(uint32_t devId, uint32_t& frameCount, uint32_t& vsyncCount)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetHardwareCursorStats, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->GetHardwareCursorStats(devId, frameCount, vsyncCount);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(
        "%{public}s fail Id:%{public}u, frame:%{public}u, vsync:%{public}u", __func__, devId, frameCount, vsyncCount));
    return ret;
}

int32_t DisplayComposerService::SetDisplayClientCrop(uint32_t devId, const IRect& rect)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->SetDisplayClientCrop(devId, rect);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));
    return ret;
}

int32_t DisplayComposerService::SetDisplayVsyncEnabled(uint32_t devId, bool enabled)
{
    DISPLAY_TRACE;

    /*Already enabled, return success */
    if (enabled && vsyncEnableStatus_[devId]) {
        DISPLAY_LOGW("%{public}s:vsyncStatus[%{public}u] = %{public}d, skip",
            __func__, devId, vsyncEnableStatus_[devId]);
        return HDF_SUCCESS;
    }
	
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->SetDisplayVsyncEnabled(devId, enabled);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s: vsyncStatus[%{public}u] = %{public}d, fail", __func__, devId, enabled));
        vsyncEnableStatus_[devId] = enabled;
        return ret;
}

int32_t DisplayComposerService::RegDisplayVBlankCallback(uint32_t devId, const sptr<IVBlankCallback>& cb)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->RegDisplayVBlankCallback(devId, OnVBlank, cb.GetRefPtr());
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));
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
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(
        "%{public}s fail width:%{public}u, height:%{public}u, format:%{public}d, devId:%{public}u",
        __func__, width, height, format, devId));
    return ret;
}

int32_t DisplayComposerService::DestroyVirtualDisplay(uint32_t devId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->DestroyVirtualDisplay(devId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));
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
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, inFence:%{public}d", __func__, devId, inFence));
    return ret;
}

int32_t DisplayComposerService::SetDisplayProperty(uint32_t devId, uint32_t id, uint64_t value)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->SetDisplayProperty(devId, id, value);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, id:%{public}u", __func__, devId, id));
    return ret;
}

int32_t DisplayComposerService::CreateLayer(uint32_t devId, const LayerInfo& layerInfo, uint32_t cacheCount,
    uint32_t& layerId)
{
    DISPLAY_TRACE;

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->CreateLayer(devId, layerInfo, layerId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, cacheCount:%{public}u, layerId:%{public}u",
        __func__, devId, cacheCount, layerId));

    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    std::lock_guard<std::mutex> lock(cacheMgr_->GetCacheMgrMutex());
    DeviceCache* devCache = cacheMgr_->DeviceCacheInstance(devId);
    DISPLAY_CHK_RETURN(devCache == nullptr, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, cacheCount:%{public}u, layerId:%{public}u",
        __func__, devId, cacheCount, layerId));

    return devCache->AddLayerCache(layerId, cacheCount);
}

int32_t DisplayComposerService::DestroyLayer(uint32_t devId, uint32_t layerId)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    int32_t ret = vdiAdapter_->DestroyLayer(devId, layerId);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, layerId:%{public}u", __func__, devId, layerId));

    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    std::lock_guard<std::mutex> lock(cacheMgr_->GetCacheMgrMutex());
    DeviceCache* devCache = cacheMgr_->DeviceCacheInstance(devId);
    DISPLAY_CHK_RETURN(devCache == nullptr, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, layerId:%{public}u", __func__, devId, layerId));

    return devCache->RemoveLayerCache(layerId);
}

int32_t DisplayComposerService::RegSeamlessChangeCallback(const sptr<ISeamlessChangeCallback>& cb)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->RegSeamlessChangeCallback, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->RegSeamlessChangeCallback(OnSeamlessChange, this);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail", __func__));
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
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));
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
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, modeId:%{public}u", __func__, devId, modeId));
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
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));
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
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("%{public}s fail", __func__));
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
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE(
        "%{public}s fail inEleCnt:%{public}u, outEleCnt:%{public}u", __func__, inEleCnt, outEleCnt));
    return ret;
}

int32_t DisplayComposerService::GetCmdReply(std::shared_ptr<SharedMemQueue<int32_t>>& reply)
{
    int32_t ret = HDF_FAILURE;

    if (cmdResponser_ != nullptr) {
        ret = cmdResponser_->GetCmdReply(reply);
    }
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("%{public}s fail", __func__));
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
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u, layerId:%{public}u", __func__, devId, layerId));
    return ret;
}

int32_t DisplayComposerService::GetSupportedLayerPerFrameParameterKey(std::vector<std::string>& keys)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetSupportedLayerPerFrameParameterKey, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->GetSupportedLayerPerFrameParameterKey(keys);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail", __func__));
    return ret;
}

int32_t DisplayComposerService::SetDisplayOverlayResolution(uint32_t devId, uint32_t width, uint32_t height)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayOverlayResolution, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->SetDisplayOverlayResolution(devId, width, height);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE, DISPLAY_LOGE(
        "%{public}s fail devId:%{public}u, width:%{public}u, height:%{public}u", __func__, devId, width, height));
    return ret;
}

void DisplayComposerService::OnRefresh(uint32_t devId, void *data)
{
    if (data == nullptr) {
        DISPLAY_LOGE("cb data is nullptr devId:%{public}u", devId);
        return;
    }

    sptr<IRefreshCallback> remoteCb = reinterpret_cast<DisplayComposerService*>(data)->refreshCb_;
    if (remoteCb == nullptr) {
        DISPLAY_LOGE("remoteCb is nullptr devId:%{public}u", devId);
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
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail", __func__));
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
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));
    return ret;
}

int32_t DisplayComposerService::GetHDRCapabilityInfos(uint32_t devId, HDRCapability& info)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetHDRCapabilityInfos, HDF_ERR_NOT_SUPPORT);
    int32_t ret = vdiAdapter_->GetHDRCapabilityInfos(devId, info);
    DISPLAY_CHK_RETURN(ret == DISPLAY_NOT_SUPPORT, HDF_ERR_NOT_SUPPORT);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));
    return ret;
}

void DisplayComposerService::OnVBlankIdleCallback(uint32_t devId, uint64_t ns, void* data)
{
    if (data == nullptr) {
        DISPLAY_LOGE("cb data is nullptr devId:%{public}u", devId);
        return;
    }

    sptr<IVBlankIdleCallback> remoteCb = reinterpret_cast<DisplayComposerService*>(data)->VBlankIdleCb_;

    if (remoteCb == nullptr) {
        DISPLAY_LOGE("VBlankIdleCb_ is nullptr devId:%{public}u", devId);
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
    DISPLAY_CHK_RETURN(devCache == nullptr, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));

    if (vdiAdapter_ != nullptr && vdiAdapter_->ClearDisplayClientBuffer != nullptr) {
        vdiAdapter_->ClearDisplayClientBuffer(devId);
    }
    return devCache->ClearClientCache();
}

int32_t DisplayComposerService::ClearLayerBuffer(uint32_t devId, uint32_t layerId)
{
    DISPLAY_LOGI("enter, devId %{public}u, layerId %{public}u", devId, layerId);
    CHECK_NULLPOINTER_RETURN_VALUE(cacheMgr_, HDF_FAILURE);
    std::lock_guard<std::mutex> lock(cacheMgr_->GetCacheMgrMutex());
    DeviceCache* devCache = cacheMgr_->DeviceCacheInstance(devId);
    DISPLAY_CHK_RETURN(devCache == nullptr, HDF_FAILURE, DISPLAY_LOGE(
        "%{public}s fail devId:%{public}u layerId %{public}u", __func__, devId, layerId));

    if (vdiAdapter_ != nullptr && vdiAdapter_->ClearLayerBuffer != nullptr) {
        vdiAdapter_->ClearLayerBuffer(devId, layerId);
    }
    return devCache->ClearLayerBuffer(layerId);
}

int32_t DisplayComposerService::SetDisplayActiveRegion(uint32_t devId, const IRect& rect)
{
    HDF_LOGI("%{public}s: devId %{public}u, rect {%{public}u, %{public}u, %{public}u, %{public}u}",
        __func__, devId, rect.x, rect.y, rect.w, rect.h);

    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->SetDisplayActiveRegion, HDF_ERR_NOT_SUPPORT);

    StartTrace(HITRACE_TAG_HDF, "vdiAdapter_->SetDisplayActiveRegion");
    int32_t ret = vdiAdapter_->SetDisplayActiveRegion(devId, rect);
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGI("%{public}s: fail, ret %{public}d", __func__, ret);
    }

    return ret;
}

int32_t DisplayComposerService::GetDisplayIdentificationData(uint32_t devId, uint8_t& portId,
    std::vector<uint8_t>& edidData)
{
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->GetDisplayIdentificationData, HDF_ERR_NOT_SUPPORT);

    StartTrace(HITRACE_TAG_HDF, "vdiAdapter_->GetDisplayIdentificationData");
    int32_t ret = vdiAdapter_->GetDisplayIdentificationData(devId, portId, edidData);
    FinishTrace(HITRACE_TAG_HDF);

    DISPLAY_LOGI("%{public}s: ret %{public}d, devId {%{public}u, the param idx [{%{public}u],"
        "the length of edidData [%{public}zu]", __func__, ret, devId, portId, edidData.size());

    return ret;
}

int32_t DisplayComposerService::FastPresent(uint32_t devId, const PresentParam& param,
    const std::vector<sptr<NativeBuffer>>& inHandles)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiAdapter_->FastPresent, HDF_ERR_NOT_SUPPORT);

    if (param.sliceNum != inHandles.size()) {
        DISPLAY_LOGE("%{public}s fail devId:%{public}u inHandles size not equals sliceNum inHandles size = %{public}zu "
                     "sliceNum = %{public}u", __func__, devId, inHandles.size(), param.sliceNum);
        return HDF_FAILURE;
    }
    std::vector<BufferHandle *> handles;
    for (uint32_t i = 0; i < param.sliceNum; i++) {
        if (!inHandles[i]) {
            DISPLAY_LOGE("%{public}s fail devId:%{public}u inHandle is nullptr i = %{public}u", __func__, devId, i);
            return HDF_FAILURE;
        }
        handles.emplace_back(inHandles[i]->GetBufferHandle());
    }

    int32_t ret = vdiAdapter_->FastPresent(devId, param, handles);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS && ret != HDF_ERR_NOT_SUPPORT, HDF_FAILURE,
        DISPLAY_LOGE("%{public}s fail devId:%{public}u", __func__, devId));
    return ret;
}
} // namespace Composer
} // namespace Display
} // namespace HDI
} // namespace OHOS
