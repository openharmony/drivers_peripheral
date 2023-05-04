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

#include "device_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "display_common_fuzzer.h"
#include "v1_0/include/idisplay_composer_interface.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"

namespace OHOS {
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;

static std::shared_ptr<IDisplayComposerInterface> g_composerInterface = nullptr;
static bool g_isInit = false;

const InterfaceType CONVERT_TABLE_INTERFACE_TYPE[] = {
    DISP_INTF_HDMI, DISP_INTF_LCD,
    DISP_INTF_BT1120, DISP_INTF_BT656,
    DISP_INTF_YPBPR, DISP_INTF_RGB,
    DISP_INTF_CVBS, DISP_INTF_SVIDEO,
    DISP_INTF_VGA, DISP_INTF_MIPI,
    DISP_INTF_PANEL, DISP_INTF_BUTT,
};

static int32_t GetDisplayCapability(DisplayCapability& info, uint8_t* data, size_t size)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    std::string tempName = reinterpret_cast<char*>(ShiftPointer(data, 0));
    uint32_t tempType = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempName)));
    uint32_t lenType = GetArrLength(CONVERT_TABLE_INTERFACE_TYPE);
    if (lenType == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_INTERFACE_TYPE length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t tempPhyWidth = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempName) + sizeof(tempType)));
    uint32_t tempPhyHeight = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempName) + sizeof(tempType) +
        sizeof(tempPhyWidth)));
    uint32_t tempSupportLayers = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempName) + sizeof(tempType) +
        sizeof(tempPhyWidth) + sizeof(tempPhyHeight)));
    uint32_t tempVirtualDispCount = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempName) +
        sizeof(tempType) + sizeof(tempPhyWidth) + sizeof(tempPhyHeight) + sizeof(tempSupportLayers)));
    uint32_t tempSupportWriteBack = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempName) +
        sizeof(tempType) + sizeof(tempPhyWidth) + sizeof(tempPhyHeight) + sizeof(tempSupportLayers) +
        sizeof(tempVirtualDispCount)));
    uint32_t tempPropertyCount = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempName) + sizeof(tempType) +
        sizeof(tempPhyWidth) + sizeof(tempPhyHeight) + sizeof(tempSupportLayers) + sizeof(tempVirtualDispCount) +
        sizeof(tempSupportWriteBack)));

    info.name = tempName;
    info.type = CONVERT_TABLE_INTERFACE_TYPE[tempType % lenType];
    info.phyWidth = tempPhyWidth;
    info.phyHeight = tempPhyHeight;
    info.supportLayers = tempSupportLayers;
    info.virtualDispCount = tempVirtualDispCount;
    info.supportWriteBack = tempSupportWriteBack;
    info.propertyCount = tempPropertyCount;
    return DISPLAY_SUCCESS;
}

int32_t TestGetDisplayCapability(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    DisplayCapability info = { 0 };
    int32_t ret = GetDisplayCapability(info, data, size);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayCapability failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->GetDisplayCapability(devId, info);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayCapability failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

static int32_t GetDisplayModeInfo(DisplayModeInfo& info, uint8_t* data, size_t size)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    // This will be read width, height, freshRate and id of display mode info,
    // so we determine whether the size of the data is sufficient.
    size_t usedLen = sizeof(int32_t) + sizeof(int32_t) + sizeof(uint32_t) + sizeof(int32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    int32_t tempWidth = *reinterpret_cast<int32_t*>(ShiftPointer(data, 0));
    int32_t tempHeight = *reinterpret_cast<int32_t*>(ShiftPointer(data, sizeof(tempWidth)));
    uint32_t tempFreshRate = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempWidth) + sizeof(tempHeight)));
    int32_t tempId = *reinterpret_cast<int32_t*>(ShiftPointer(data, sizeof(tempWidth) + sizeof(tempHeight) +
        sizeof(tempFreshRate)));
    info.width = tempWidth % WIDTH;
    info.height = tempHeight % HEIGHT;
    info.freshRate = tempFreshRate;
    info.id = tempId;
    return DISPLAY_SUCCESS;
}

int32_t TestGetDisplaySupportedModes(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    DisplayModeInfo info = { 0 };
    int32_t ret = GetDisplayModeInfo(info, data, size);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayModeInfo failed", __func__);
        return DISPLAY_FAILURE;
    }
    std::vector<DisplayModeInfo> infos;
    infos.push_back(info);
    ret = g_composerInterface->GetDisplaySupportedModes(devId, infos);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplaySupportedModes failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetGetDisplayMode(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t modeId = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    int32_t ret = g_composerInterface->SetDisplayMode(devId, modeId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayMode failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->GetDisplayMode(devId, modeId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayMode failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetGetDisplayPowerStatus(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    static const DispPowerStatus CONVERT_TABLE[] = {
        POWER_STATUS_ON, POWER_STATUS_STANDBY,
        POWER_STATUS_SUSPEND, POWER_STATUS_OFF,
        POWER_STATUS_BUTT,
    };
    uint32_t tableIndex = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    uint32_t len = GetArrLength(CONVERT_TABLE);
    if (len == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    DispPowerStatus status = CONVERT_TABLE[tableIndex % len];
    int32_t ret = g_composerInterface->SetDisplayPowerStatus(devId, status);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayPowerStatus failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->GetDisplayPowerStatus(devId, status);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayPowerStatus failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestPrepareDisplayLayers(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t tempNeedFlushFb = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    bool needFlushFb = GetRandBoolValue(tempNeedFlushFb);
    int32_t ret = g_composerInterface->PrepareDisplayLayers(devId, needFlushFb);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function PrepareDisplayLayers failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetGetDisplayBacklight(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t level = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    int32_t ret = g_composerInterface->SetDisplayBacklight(devId, level);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayBacklight failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->GetDisplayBacklight(devId, level);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayBacklight failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestGetDisplayProperty(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t) + sizeof(uint64_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t id = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    uint64_t value = *reinterpret_cast<uint64_t*>(ShiftPointer(data, sizeof(id)));
    int32_t ret = g_composerInterface->GetDisplayProperty(devId, id, value);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayProperty failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestGetDisplayCompChange(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    // This will be read device id, layer id, and type,
    // so we determine whether the size of the data is sufficient.
    size_t usedLen = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    std::vector<uint32_t> layers;
    layers.push_back(*reinterpret_cast<uint32_t*>(ShiftPointer(data, 0)));
    std::vector<int32_t> types;
    types.push_back(*reinterpret_cast<int32_t*>(ShiftPointer(data, sizeof(layers))));

    int32_t ret = g_composerInterface->GetDisplayCompChange(devId, layers, types);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayCompChange failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetDisplayClientCrop(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    IRect rect;
    int32_t ret = GetIRect(rect, data, size);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetIRect failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->SetDisplayClientCrop(devId, rect);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayClientCrop failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetDisplayClientBuffer(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(int32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    int32_t fence = *reinterpret_cast<int32_t*>(ShiftPointer(data, 0));
    const BufferHandle* BUFFER = UsingAllocmem(data, size);
    if (BUFFER == nullptr) {
        HDF_LOGE("%{public}s: Failed to UsingAllocmem", __func__);
        return DISPLAY_FAILURE;
    }
    int32_t ret = g_composerInterface->SetDisplayClientBuffer(devId, *BUFFER, fence);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerBuffer failed", __func__);
    }
    return ret;
}

int32_t TestSetDisplayClientDamage(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    IRect rect;
    int32_t ret = GetIRect(rect, data, size);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetIRect failed", __func__);
        return DISPLAY_FAILURE;
    }
    std::vector<IRect> rects;
    rects.push_back(rect);
    ret = g_composerInterface->SetDisplayClientDamage(devId, rects);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayClientDamage failed", __func__);
    }
    return ret;
}

int32_t TestSetDisplayVsyncEnabled(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t tempEnabled = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    bool enabled = GetRandBoolValue(tempEnabled);
    int32_t ret = g_composerInterface->SetDisplayVsyncEnabled(devId, enabled);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayVsyncEnabled failed", __func__);
    }
    return ret;
}

int32_t TestRegDisplayVBlankCallback(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t) + sizeof(VBlankCallback);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t param1 = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    VBlankCallback param2 = reinterpret_cast<VBlankCallback>(ShiftPointer(data, sizeof(param1)));
    void* param3 = malloc(PARAM_VOIDPTR_LEN);
    if (param3 == nullptr) {
        HDF_LOGE("%{public}s: void* param3 malloc failed", __func__);
        return DISPLAY_FAILURE;
    }
    int32_t ret = g_composerInterface->RegDisplayVBlankCallback(param1, param2, param3);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function RegDisplayVBlankCallback failed", __func__);
    }
    free(param3);
    param3 = nullptr;
    return ret;
}

int32_t TestGetDisplayReleaseFence(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    // This will be read device id, layer id, and fence,
    // so we determine whether the size of the data is sufficient.
    size_t usedLen = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(int32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }

    std::vector<uint32_t> layers;
    layers.push_back(*reinterpret_cast<uint32_t*>(ShiftPointer(data, 0)));
    std::vector<int32_t> fences;
    fences.push_back(*reinterpret_cast<int32_t*>(ShiftPointer(data, sizeof(layers))));

    int32_t ret = g_composerInterface->GetDisplayReleaseFence(devId, layers, fences);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayReleaseFence failed", __func__);
    }
    return ret;
}

int32_t TestDestroyVirtualDisplay(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    int32_t ret = g_composerInterface->DestroyVirtualDisplay(devId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function DestroyVirtualDisplay failed", __func__);
    }
    return ret;
}

int32_t TestSetVirtualDisplayBuffer(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(int32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    int32_t fence = *reinterpret_cast<int32_t*>(ShiftPointer(data, 0));
    BufferHandle* buffer = UsingAllocmem(data, size);
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: Failed to UsingAllocmem", __func__);
        return DISPLAY_FAILURE;
    }
    int32_t ret = g_composerInterface->SetVirtualDisplayBuffer(devId, *buffer, fence);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetVirtualDisplayBuffer failed", __func__);
    }
    return ret;
}

int32_t TestSetDisplayProperty(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t) + sizeof(uint64_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t id = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    uint64_t value = *reinterpret_cast<uint64_t*>(ShiftPointer(data, sizeof(id)));
    int32_t ret = g_composerInterface->SetDisplayProperty(devId, id, value);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: SetDisplayProperty Commit failed", __func__);
    }
    return ret;
}

int32_t TestCommit(uint8_t* data, size_t size, uint32_t devId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(int32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    int32_t fence = *reinterpret_cast<int32_t*>(ShiftPointer(data, 0));
    int32_t ret = g_composerInterface->Commit(devId, fence);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function Commit failed", __func__);
    }
    return ret;
}

typedef int32_t (*TestFuncs[])(uint8_t*, size_t, uint32_t);

TestFuncs g_testFuncs = {
    TestGetDisplayCapability,
    TestGetDisplaySupportedModes,
    TestSetGetDisplayMode,
    TestSetGetDisplayPowerStatus,
    TestPrepareDisplayLayers,
    TestSetGetDisplayBacklight,
    TestGetDisplayProperty,
    TestGetDisplayCompChange,
    TestSetDisplayClientCrop,
    TestSetDisplayClientBuffer,
    TestSetDisplayClientDamage,
    TestSetDisplayVsyncEnabled,
    TestGetDisplayReleaseFence,
    TestDestroyVirtualDisplay,
    TestSetVirtualDisplayBuffer,
    TestSetDisplayProperty,
    TestCommit,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < (OFFSET + OFFSET)) {
        return false;
    }

    if (!g_isInit) {
        g_isInit = true;
        g_composerInterface.reset(IDisplayComposerInterface::Get());
        if (g_composerInterface == nullptr) {
            HDF_LOGE("%{public}s: get IDisplayComposerInterface failed", __func__);
            return false;
        }
    }

    uint32_t code = Convert2Uint32(rawData, size);
    rawData = rawData + OFFSET;
    size = size - OFFSET;
    uint32_t devId = Convert2Uint32(rawData, size);
    rawData = rawData + OFFSET;

    uint8_t* data = const_cast<uint8_t*>(rawData);
    if (data == nullptr) {
        HDF_LOGE("%{public}s: can not get data", __func__);
        return false;
    }

    uint32_t len = GetArrLength(g_testFuncs);
    if (len == 0) {
        HDF_LOGE("%{public}s: g_testFuncs length is equal to 0", __func__);
        return false;
    }

    int32_t ret = g_testFuncs[code % len](data, size, devId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("function %{public}u failed", code % len);
        return false;
    }

    return true;
}
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    OHOS::FuzzTest(data, size);
    return 0;
}
