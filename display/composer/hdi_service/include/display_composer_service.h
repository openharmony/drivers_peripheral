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

#ifndef OHOS_HDI_DISPLAY_COMPOSER_SERVICE_H
#define OHOS_HDI_DISPLAY_COMPOSER_SERVICE_H

#include "cache_manager/device_cache_manager.h"
#include "v1_1/display_command/display_cmd_responser.h"
#include "v1_1/idisplay_composer.h"
#include "v1_2/display_command/display_cmd_responser.h"
#include "v1_2/idisplay_composer.h"
#include "v1_2/display_composer_type.h"
#include "common/include/display_vdi_adapter_interface.h"
#include <mutex>

namespace OHOS {
namespace HDI {
namespace Display {
namespace Composer {
using namespace OHOS::HDI::Display::Composer::V1_2;

class DisplayComposerService : public V1_2::IDisplayComposer {
public:
    DisplayComposerService();
    virtual ~DisplayComposerService();
    int32_t RegHotPlugCallback(const sptr<IHotPlugCallback>& cb) override;
    int32_t SetClientBufferCacheCount(uint32_t devId, uint32_t count) override;
    int32_t GetDisplayCapability(uint32_t devId, DisplayCapability& info) override;
    int32_t GetDisplaySupportedModes(uint32_t devId, std::vector<DisplayModeInfo>& modes) override;
    int32_t GetDisplayMode(uint32_t devId, uint32_t& modeId) override;
    int32_t SetDisplayMode(uint32_t devId, uint32_t modeId) override;
    int32_t GetDisplayPowerStatus(uint32_t devId, V1_0::DispPowerStatus& status) override;
    int32_t SetDisplayPowerStatus(uint32_t devId, V1_0::DispPowerStatus status) override;
    int32_t GetDisplayBacklight(uint32_t devId, uint32_t& level) override;
    int32_t SetDisplayBacklight(uint32_t devId, uint32_t level) override;
    int32_t GetDisplayProperty(uint32_t devId, uint32_t id, uint64_t& value) override;
    int32_t UpdateHardwareCursor(uint32_t devId, int32_t x, int32_t y, const sptr<NativeBuffer> buffer) override;
    int32_t EnableHardwareCursorStats(uint32_t devId, bool enable) override;
    int32_t GetHardwareCursorStats(uint32_t devId, uint32_t& frameCount, uint32_t& vsyncCount) override;
    int32_t SetDisplayClientCrop(uint32_t devId, const IRect& rect) override;
    int32_t SetDisplayVsyncEnabled(uint32_t devId, bool enabled) override;
    int32_t RegDisplayVBlankCallback(uint32_t devId, const sptr<IVBlankCallback>& cb) override;
    int32_t GetDisplayReleaseFence(
        uint32_t devId, std::vector<uint32_t>& layers, std::vector<sptr<HdifdParcelable>>& fences) override;
    int32_t CreateVirtualDisplay(uint32_t width, uint32_t height, int32_t& format, uint32_t& devId) override;
    int32_t DestroyVirtualDisplay(uint32_t devId) override;
    int32_t SetVirtualDisplayBuffer(
        uint32_t devId, const sptr<NativeBuffer>& buffer, const sptr<HdifdParcelable>& fence) override;
    int32_t SetDisplayProperty(uint32_t devId, uint32_t id, uint64_t value) override;
    int32_t CreateLayer(uint32_t devId, const LayerInfo& layerInfo, uint32_t cacheCount, uint32_t& layerId) override;
    int32_t DestroyLayer(uint32_t devId, uint32_t layerId) override;
    int32_t InitCmdRequest(const std::shared_ptr<SharedMemQueue<int32_t>>& request) override;
    int32_t CmdRequest(uint32_t inEleCnt, const std::vector<HdifdInfo>& inFds, uint32_t& outEleCnt,
        std::vector<HdifdInfo>& outFds) override;
    int32_t GetCmdReply(std::shared_ptr<SharedMemQueue<int32_t>>& reply) override;

    int32_t RegSeamlessChangeCallback(const sptr<ISeamlessChangeCallback>& cb) override;
    int32_t GetDisplaySupportedModesExt(uint32_t devId, std::vector<DisplayModeInfoExt>& modes) override;
    int32_t SetDisplayModeAsync(uint32_t devId, uint32_t modeId, const sptr<IModeCallback>& cb) override;
    int32_t GetDisplayVBlankPeriod(uint32_t devId, uint64_t &period) override;
    int32_t SetLayerPerFrameParameter(uint32_t devId, uint32_t layerId, const std::string& key,
        const std::vector<int8_t>& value)  override;
    int32_t GetSupportedLayerPerFrameParameterKey(std::vector<std::string>& keys) override;
    int32_t SetDisplayOverlayResolution(uint32_t devId, uint32_t width, uint32_t height) override;
    int32_t GetDisplaySupportedColorGamuts(uint32_t devId, std::vector<ColorGamut>& gamuts) override;
    int32_t GetHDRCapabilityInfos(uint32_t devId, HDRCapability& info) override;
    int32_t RegRefreshCallback(const sptr<IRefreshCallback>& cb) override;
    int32_t RegDisplayVBlankIdleCallback (const sptr<IVBlankIdleCallback>& cb) override;
    int32_t ClearClientBuffer(uint32_t devId) override;
    int32_t ClearLayerBuffer(uint32_t devId, uint32_t layerId) override;
    int32_t SetDisplayActiveRegion(uint32_t devId, const IRect& rect) override;
    int32_t FastPresent(uint32_t devId, const PresentParam& param,
        const std::vector<sptr<NativeBuffer>>& inHandles) override;

private:
    void HidumperInit();
    int32_t LoadVdiSo();
    int32_t LoadVdiAdapter();
    void LoadVdiFuncPart1();
    void LoadVdiFuncPart2();
    void LoadVdiFuncPart3();
    void ExitService();
    int32_t CreateResponser();
    static void OnHotPlug(uint32_t outputId, bool connected, void* data);
    static void OnVBlank(unsigned int sequence, uint64_t ns, void* data);
    static void OnMode(uint32_t modeId, uint64_t vBlankPeriod, void* data);
    static void OnSeamlessChange(uint32_t devId, void* data);
    static void OnRefresh(uint32_t devId, void *data);
    static void OnVBlankIdleCallback(uint32_t devId, uint64_t ns, void* data);
private:
    /* Common */
    void* libHandle_;
    DisplayComposerVdiAdapter* vdiAdapter_;
    std::mutex mutex_;
    std::shared_ptr<DeviceCacheManager> cacheMgr_;
    uint32_t currentBacklightLevel_;
    sptr<IHotPlugCallback> hotPlugCb_;
    sptr<IVBlankCallback> vBlankCb_;
    sptr<IModeCallback> modeCb_;
    sptr<ISeamlessChangeCallback> seamlessChangeCb_;
    std::unique_ptr<V1_2::HdiDisplayCmdResponser> cmdResponser_;
    sptr<IRefreshCallback> refreshCb_;
    sptr<IVBlankIdleCallback> VBlankIdleCb_;
};
} // namespace Composer
} // namespace Display
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_DISPLAY_COMPOSER_SERVICE_H
