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

#include "display_device_proxy.h"
#include "display_device_common.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG DisplayHostProxy

using OHOS::Display::Device::IDisplayDevice;
using OHOS::Display::Device::Client::DisplayDeviceProxy;
using std::map;
using std::move;
using std::pair;
using std::unique_ptr;

static constexpr uint32_t MAX_DEVID = 4;
static const std::string serverName = "display_device_service";
static OHOS::sptr<IDisplayDevice> g_instance;

void IDisplayDevice::Initialize(void)
{
    DISPLAY_START;
    if (g_instance != nullptr) {
        DISPLAY_LOG("initialize was already");
        DISPLAY_END;
        return;
    }
    do {
        using OHOS::sptr;
        using OHOS::HDI::ServiceManager::V1_0::IServiceManager;
        auto servMgr = IServiceManager::Get();
        if (servMgr == nullptr) {
            DISPLAY_LOG("IServiceManager failed!");
            break;
        }
        sptr<IRemoteObject> remote = servMgr->GetService(serverName.c_str());
        if (remote == nullptr) {
            DISPLAY_LOG("IServiceManager IDisplayDevice(%{public}s) failed!", serverName.c_str());
        }
        g_instance = iface_cast<IDisplayDevice>(remote);
        if (g_instance == nullptr) {
            DISPLAY_LOG("failed to iface cast IDisplayDevice");
            break;
        }
        g_instance->m_hotPlugObject_ = new DisplayRegisterCallbackFramework();
        if (g_instance->m_hotPlugObject_ == nullptr) {
            DISPLAY_LOG("create DisplayRegisterCallbackFramework failed!");
            break;
        }
        DISPLAY_END;
        return;
    } while (0);
    return;
}
OHOS::sptr<IDisplayDevice> DisplayDeviceProxy::GetInstance(void)
{
    DISPLAY_START;
    DISPLAY_END;
    if (g_instance == nullptr) {
        Initialize();
    }
    return g_instance;
}
void DisplayDeviceProxy::ReleaseInstance(void)
{
    DISPLAY_START;
    DISPLAY_END;
    g_instance = nullptr;
}

int32_t DisplayDeviceProxy::RegHotPlugCallback(HotPlugCallback callback, void *data)
{
    DISPLAY_LOG("interface start");
    if (callback == nullptr || data == nullptr) {
        DISPLAY_LOG("callback %{public}s nullptr, data %{public}s nullptr", callback == nullptr ? "is" : "is not",
            data == nullptr ? "is" : "is not");
        return DISPLAY_PARAM_ERR;
    }

    m_hotPlugObject_->SetHotplugInData(callback, data);
    SetProxyRemoteCallback(m_hotPlugObject_);
    MessageParcel dataParecel;
    MessageParcel repParecel;
    if (!DisplayDeviceWriteCmdId(&dataParecel, DSP_CMD_REGHOTPLUGCALLBACK)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_REGHOTPLUGCALLBACK, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_REGHOTPLUGCALLBACK)->returnVal;
}
int32_t DisplayDeviceProxy::RegDisplayVBlankCallback(uint32_t devId, VBlankCallback callback, void *data)
{
    DISPLAY_LOG("interface start");
    if (callback == nullptr || (devId > MAX_DEVID)) {
        DISPLAY_LOG("callback %{public}s nullptr, data %{public}s nullptr", callback == nullptr ? "is" : "is not",
            data == nullptr ? "is" : "is not");
        return DISPLAY_PARAM_ERR;
    }

    m_hotPlugObject_->SetVBlankData(callback, data);

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_REGDISPLAYVBLANKCALLBACK)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_REGDISPLAYVBLANKCALLBACK, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_REGDISPLAYVBLANKCALLBACK)->returnVal;
}
int32_t DisplayDeviceProxy::RegDisplayRefreshCallback(uint32_t devId, RefreshCallback callback, void *data)
{
    DISPLAY_LOG("interface start");
    if (callback == nullptr || (devId > MAX_DEVID)) {
        DISPLAY_LOG("callback %{public}s nullptr, data %{public}s nullptr", callback == nullptr ? "is" : "is not",
            data == nullptr ? "is" : "is not");
        return DISPLAY_PARAM_ERR;
    }

    m_hotPlugObject_->SetRefreshData(callback, data);

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_REGDISPLAYREFRESHCALLBACK)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_REGDISPLAYREFRESHCALLBACK, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_REGDISPLAYREFRESHCALLBACK)->returnVal;
}
int32_t DisplayDeviceProxy::GetDisplayCapability(uint32_t devId, DisplayCapability &info)
{
    DISPLAY_LOG("interface start");
    printf("DisplayDeviceProxy:%s %d", __func__, __LINE__);
    if (devId > MAX_DEVID) {
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_GETDISPLAYCAPABILITY)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_GETDISPLAYCAPABILITY, &dataParecel, &repParecel, &info) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_GETDISPLAYCAPABILITY)->returnVal;
}
int32_t DisplayDeviceProxy::GetDisplaySuppportedModes(uint32_t devId, int &num, DisplayModeInfo *modes)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_GETDISPLAYSUPPPORTEDMODES)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteInt32(pTmpData, num)) {
        DISPLAY_LOG("error: write num data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_GETDISPLAYSUPPPORTEDMODES, &dataParecel, &repParecel, modes) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }
    num = GetReturnData(DSP_CMD_GETDISPLAYSUPPPORTEDMODES)->arrayNum;

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_GETDISPLAYSUPPPORTEDMODES)->returnVal;
}
int32_t DisplayDeviceProxy::GetDisplayMode(uint32_t devId, uint32_t &modeId)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_GETDISPLAYMODE)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_GETDISPLAYMODE, &dataParecel, &repParecel, &modeId) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_GETDISPLAYMODE)->returnVal;
}
int32_t DisplayDeviceProxy::SetDisplayMode(uint32_t devId, uint32_t modeId)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("modeId is nullptr");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETDISPLAYMODE)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, modeId)) {
        DISPLAY_LOG("error: write modeId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_SETDISPLAYMODE, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_SETDISPLAYMODE)->returnVal;
}
int32_t DisplayDeviceProxy::GetDisplayPowerStatus(uint32_t devId, DispPowerStatus &status)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("status is nullptr");
        return DISPLAY_PARAM_ERR;
    }

    return DISPLAY_NOT_SUPPORT;
}
int32_t DisplayDeviceProxy::SetDisplayPowerStatus(uint32_t devId, DispPowerStatus status)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("status is nullptr");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETDISPLAYPOWERSTATUS)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(pTmpData, status)) {
        DISPLAY_LOG("error: write status into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_SETDISPLAYPOWERSTATUS, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_SETDISPLAYPOWERSTATUS)->returnVal;
}
int32_t DisplayDeviceProxy::GetDisplayBacklight(uint32_t devId, uint32_t &level)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    return DISPLAY_NOT_SUPPORT;
}
int32_t DisplayDeviceProxy::SetDisplayBacklight(uint32_t devId, uint32_t level)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETDISPLAYBACKLIGHT)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, level)) {
        DISPLAY_LOG("error: write level into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_SETDISPLAYBACKLIGHT, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_SETDISPLAYBACKLIGHT)->returnVal;
}
int32_t DisplayDeviceProxy::GetDisplayProperty(uint32_t devId, uint32_t propertyId, uint64_t &value)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_GETDISPLAYPROPERTY)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, propertyId)) {
        DISPLAY_LOG("error: write id into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_GETDISPLAYPROPERTY, &dataParecel, &repParecel, &value) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_GETDISPLAYPROPERTY)->returnVal;
}
int32_t DisplayDeviceProxy::SetDisplayProperty(uint32_t devId, uint32_t propertyId, uint64_t value)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETDISPLAYPROPERTY)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, propertyId)) {
        DISPLAY_LOG("error: write id into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint64(pTmpData, value)) {
        DISPLAY_LOG("error: write value into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_SETDISPLAYPROPERTY, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_SETDISPLAYPROPERTY)->returnVal;
}
int32_t DisplayDeviceProxy::PrepareDisplayLayers(uint32_t devId, bool &needFlushFb)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_PREPAREDISPLAYLAYERS)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteBool(pTmpData, needFlushFb)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_PREPAREDISPLAYLAYERS, &dataParecel, &repParecel, &needFlushFb) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::GetDisplayCompChange(uint32_t devId, uint32_t &num, uint32_t *layers, int32_t *type)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_GETDISPLAYCOMPCHANGE)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_GETDISPLAYCOMPCHANGE, &dataParecel, &repParecel, layers, type) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }
    num = GetReturnData(DSP_CMD_GETDISPLAYCOMPCHANGE)->arrayNum;

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_GETDISPLAYCOMPCHANGE)->returnVal;
}
int32_t DisplayDeviceProxy::SetDisplayClientCrop(uint32_t devId, const IRect *rect)
{
    DISPLAY_LOG("interface start");
    if (rect == nullptr) {
        DISPLAY_LOG("rect is nullptr");
        return DISPLAY_PARAM_ERR;
    }

    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETDISPLAYCLIENTCROP)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(pTmpData, rect)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_SETDISPLAYCLIENTCROP, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_SETDISPLAYCLIENTCROP)->returnVal;
}

int32_t DisplayDeviceProxy::SetDisplayClientDestRect(uint32_t devId, const IRect &rect)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETDISPLAYCLIENTDESTRECT)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(pTmpData, &rect)) {
        DISPLAY_LOG("error: write rect into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_SETDISPLAYCLIENTDESTRECT, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_SETDISPLAYCLIENTDESTRECT)->returnVal;
}

int32_t DisplayDeviceProxy::SetDisplayClientBuffer(uint32_t devId, const BufferHandle &bufhandle, int32_t fence)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETDISPLAYCLIENTBUFFER)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteBufHdl(pTmpData, &bufhandle)) {
        DISPLAY_LOG("error: write bufferhandle into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteFileDescriptor(pTmpData, fence)) {
        DISPLAY_LOG("error: write size into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETDISPLAYCLIENTBUFFER, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::SetDisplayClientDamage(uint32_t devId, uint32_t num, const IRect &rect)
{
    DISPLAY_LOG("interface start");
    if (num == 0) {
        return DISPLAY_PARAM_ERR;
    }

    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETDISPLAYCLIENTDAMAGE)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, num)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(pTmpData, &rect, num)) {
        DISPLAY_LOG("error: write rect into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETDISPLAYCLIENTDAMAGE, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::SetDisplayVsyncEnabled(uint32_t devId, bool enabled)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETDISPLAYVSYNCENABLED)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteBool(pTmpData, enabled)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_SETDISPLAYVSYNCENABLED, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    auto ret = GetReturnData(DSP_CMD_SETDISPLAYVSYNCENABLED)->returnVal;
    DISPLAY_LOG("interface end, ret = %{public}d", ret);
    return ret;
}

int32_t DisplayDeviceProxy::GetDisplayReleaseFence(uint32_t devId, uint32_t *num, uint32_t *layers, int32_t *fences)
{
    DISPLAY_LOG("interface start");
    if (num == nullptr) {
        DISPLAY_LOG("num %{public}s nullptr, layers %{public}s nullptr, fences %{public}s nullptr",
            (num == nullptr) ? "is" : "is not", (layers == nullptr) ? "is" : "is not",
            (fences == nullptr) ? "is" : "is not");
        return DISPLAY_PARAM_ERR;
    }
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_GETDISPLAYRELEASEFENCE)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_GETDISPLAYRELEASEFENCE, &dataParecel, &repParecel, layers, fences) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }
    *num = GetReturnData(DSP_CMD_GETDISPLAYRELEASEFENCE)->arrayNum;

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_GETDISPLAYRELEASEFENCE)->returnVal;
}
int32_t DisplayDeviceProxy::Commit(uint32_t devId, int32_t &fence)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_COMMIT)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write value into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_COMMIT, &dataParecel, &repParecel, &fence) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_COMMIT)->returnVal;
}
int32_t DisplayDeviceProxy::InvokeDisplayCmd(uint32_t devId, ...)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_INVOKEDISPLAYCMD)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write value into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_INVOKEDISPLAYCMD, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_INVOKEDISPLAYCMD)->returnVal;
}
int32_t DisplayDeviceProxy::CreateVirtualDisplay(uint32_t width, uint32_t height, int32_t &format, uint32_t &devId)
{
    DISPLAY_LOG("interface start");
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_CREATEVIRTUALDISPLAY)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, width)) {
        DISPLAY_LOG("error: write width into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, height)) {
        DISPLAY_LOG("error: write height into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_CREATEVIRTUALDISPLAY, &dataParecel, &repParecel, &format, &devId) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_CREATEVIRTUALDISPLAY)->returnVal;
}
int32_t DisplayDeviceProxy::DestroyVirtualDisplay(uint32_t devId)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_DESTROYVIRTUALDISPLAY)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_DESTROYVIRTUALDISPLAY, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_DESTROYVIRTUALDISPLAY)->returnVal;
}
int32_t DisplayDeviceProxy::SetVirtualDisplayBuffer(uint32_t devId, const BufferHandle *bufhandle, int32_t fence)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    if (bufhandle == nullptr) {
        DISPLAY_LOG("bufhandle is nullptr");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETVIRTUALDISPLAYBUFFER)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteBufHdl(pTmpData, bufhandle)) {
        DISPLAY_LOG("error: write bufferhandle into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteFileDescriptor(pTmpData, fence)) {
        DISPLAY_LOG("error: write size into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_SETVIRTUALDISPLAYBUFFER, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_SETVIRTUALDISPLAYBUFFER)->returnVal;
}
int32_t DisplayDeviceProxy::GetWriteBackFrame(uint32_t devId, BufferHandle &buffer, int32_t &fence)
{
    DISPLAY_LOG("interface start");

    DISPLAY_LOG("interface end");
    return DISPLAY_NOT_SUPPORT;
}
int32_t DisplayDeviceProxy::CreateWriteBack(uint32_t &devId, uint32_t width, uint32_t height, int32_t &format)
{
    DISPLAY_LOG("interface start");
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_CREATEWRITEBACK)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, width)) {
        DISPLAY_LOG("error: write width into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, height)) {
        DISPLAY_LOG("error: write height into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_CREATEWRITEBACK, &dataParecel, &repParecel, &devId, &format) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_CREATEWRITEBACK)->returnVal;
}
int32_t DisplayDeviceProxy::DestroyWriteBack(uint32_t devId)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_DESTROYWRITEBACK)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_DESTROYWRITEBACK, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_DESTROYWRITEBACK)->returnVal;
}
int32_t DisplayDeviceProxy::SetProxyRemoteCallback(const OHOS::sptr<DisplayRegisterCallbackBase> &callback)
{
    DISPLAY_LOG("interface start");
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SET_PROXY_REMOTE_CALLBACK)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!pTmpData->WriteUint32(1)) {
        DISPLAY_LOG("error: write data length into parcel failed");
        return false;
    }
    if (!pTmpData->WriteRemoteObject(callback->AsObject())) {
        DISPLAY_LOG("error: write callback into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_SET_PROXY_REMOTE_CALLBACK, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_SET_PROXY_REMOTE_CALLBACK)->returnVal;
}
int32_t DisplayDeviceProxy::InitDisplay(uint32_t devId)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_INITDISPLAY)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_INITDISPLAY, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_INITDISPLAY)->returnVal;
}
int32_t DisplayDeviceProxy::DeinitDisplay(uint32_t devId)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_DEINITDISPLAY)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_DEINITDISPLAY, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_DEINITDISPLAY)->returnVal;
}
int32_t DisplayDeviceProxy::GetDisplayInfo(uint32_t devId, DisplayInfo &dispInfo)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_GETDISPLAYINFO)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_GETDISPLAYINFO, &dataParecel, &repParecel, &dispInfo) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_GETDISPLAYINFO)->returnVal;
}
int32_t DisplayDeviceProxy::CreateLayer(uint32_t devId, const LayerInfo &layerInfo, uint32_t &layerId)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_CREATELAYER)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(pTmpData, &layerInfo)) {
        DISPLAY_LOG("error: write rect into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_CREATELAYER, &dataParecel, &repParecel, &layerId) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_CREATELAYER)->returnVal;
}
int32_t DisplayDeviceProxy::CloseLayer(uint32_t devId, uint32_t layerId)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_CLOSELAYER)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_CLOSELAYER, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_CLOSELAYER)->returnVal;
}
int32_t DisplayDeviceProxy::SetLayerVisible(uint32_t devId, uint32_t layerId, bool visible)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERVISIBLE)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteBool(pTmpData, visible)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERVISIBLE, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::GetLayerVisibleState(uint32_t devId, uint32_t layerId, bool &visible)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    return DISPLAY_NOT_SUPPORT;
}

int32_t DisplayDeviceProxy::SetLayerSize(uint32_t devId, uint32_t layerId, const IRect *rect)
{
    DISPLAY_LOG("interface start");
    if (rect == nullptr) {
        DISPLAY_LOG("rect is nullptr");
        return DISPLAY_PARAM_ERR;
    }
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERSIZE)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(pTmpData, rect)) {
        DISPLAY_LOG("error: write rect into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERSIZE, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceProxy::GetLayerSize(uint32_t devId, uint32_t layerId, IRect &rect)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    return DISPLAY_NOT_SUPPORT;
}
int32_t DisplayDeviceProxy::SetLayerCrop(uint32_t devId, uint32_t layerId, const IRect *rect)
{
    DISPLAY_LOG("interface start");
    if (rect == nullptr) {
        DISPLAY_LOG("rect is nullptr");
        return DISPLAY_PARAM_ERR;
    }

    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERCROP)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(pTmpData, rect)) {
        DISPLAY_LOG("error: write rect into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERCROP, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::SetLayerZorder(uint32_t devId, uint32_t layerId, uint32_t zorder)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERZORDER)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, zorder)) {
        DISPLAY_LOG("error: write zorder into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERZORDER, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::GetLayerZorder(uint32_t devId, uint32_t layerId, uint32_t &zorder)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    return DISPLAY_NOT_SUPPORT;
}
int32_t DisplayDeviceProxy::SetLayerPreMulti(uint32_t devId, uint32_t layerId, bool preMul)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERPREMULTI)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteBool(pTmpData, preMul)) {
        DISPLAY_LOG("error: write preMul into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERPREMULTI, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::GetLayerPreMulti(uint32_t devId, uint32_t layerId, bool &preMul)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    return DISPLAY_NOT_SUPPORT;
}
int32_t DisplayDeviceProxy::SetLayerAlpha(uint32_t devId, uint32_t layerId, const LayerAlpha &alpha)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERALPHA)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(pTmpData, &alpha)) {
        DISPLAY_LOG("error: write alpha into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERALPHA, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::GetLayerAlpha(uint32_t devId, uint32_t layerId, LayerAlpha &alpha)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    return DISPLAY_NOT_SUPPORT;
}
int32_t DisplayDeviceProxy::SetLayerColorKey(uint32_t devId, uint32_t layerId, bool enable, uint32_t key)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERCOLORKEY)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteBool(pTmpData, enable)) {
        DISPLAY_LOG("error: write enable into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, key)) {
        DISPLAY_LOG("error: write enable into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERCOLORKEY, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::GetLayerColorKey(uint32_t devId, uint32_t layerId, bool *enable, uint32_t *key)
{
    DISPLAY_LOG("interface start");
    if (key == nullptr || enable == nullptr) {
        DISPLAY_LOG("key is nullptr");
        return DISPLAY_PARAM_ERR;
    }

    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    return DISPLAY_NOT_SUPPORT;
}
int32_t DisplayDeviceProxy::SetLayerPalette(uint32_t devId, uint32_t layerId, const uint32_t *palette, uint32_t len)
{
    DISPLAY_LOG("interface start");
    if (palette == nullptr) {
        DISPLAY_LOG("palette is nullptr");
        return DISPLAY_PARAM_ERR;
    }

    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    uint32_t minLen = 0;
    uint32_t maxLen = 4;
    if ((len < minLen) || (len > maxLen)) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERPALETTE)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, len)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(pTmpData, &palette[0], len)) {
        DISPLAY_LOG("error: write enable into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERPALETTE, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::GetLayerPalette(uint32_t devId, uint32_t layerId, uint32_t &palette, uint32_t len)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    return DISPLAY_NOT_SUPPORT;
}
int32_t DisplayDeviceProxy::SetTransformMode(uint32_t devId, uint32_t layerId, TransformType type)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETTRANSFORMMODE)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(pTmpData, type)) {
        DISPLAY_LOG("error: write type into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETTRANSFORMMODE, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::SetLayerCompression(uint32_t devId, uint32_t layerId, int32_t compType)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERCOMPRESSION)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(pTmpData, compType)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERCOMPRESSION, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::GetLayerCompression(uint32_t devId, uint32_t layerId, int32_t &compType)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    return DISPLAY_NOT_SUPPORT;
}
int32_t DisplayDeviceProxy::SetLayerDirtyRegion(uint32_t devId, uint32_t layerId, uint32_t num, const IRect &region)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERDIRTYREGION)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, num)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(pTmpData, &region, num)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERDIRTYREGION, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::GetLayerBuffer(uint32_t devId, uint32_t layerId, LayerBuffer *buffer)
{
    DISPLAY_LOG("interface start");
    if (buffer == nullptr) {
        DISPLAY_LOG("buffer is nullptr");
        return DISPLAY_PARAM_ERR;
    }

    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_GETLAYERBUFFER)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_GETLAYERBUFFER, &dataParecel, &repParecel, buffer) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_GETLAYERBUFFER)->returnVal;
}
int32_t DisplayDeviceProxy::Flush(uint32_t devId, uint32_t layerId, LayerBuffer &buffer)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_FLUSH)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(pTmpData, &buffer)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_FLUSH, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::WaitForVBlank(uint32_t devId, uint32_t layerId, int32_t timeOut)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_WAITFORVBLANK)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(pTmpData, timeOut)) {
        DISPLAY_LOG("error: write timeOut into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_WAITFORVBLANK, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_WAITFORVBLANK)->returnVal;
}
int32_t DisplayDeviceProxy::SnapShot(uint32_t devId, LayerBuffer &buffer)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SNAPSHOT)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }

    if (DisplayComposerExecuteCmd(DSP_CMD_SNAPSHOT, &dataParecel, &repParecel, &buffer) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return GetReturnData(DSP_CMD_SNAPSHOT)->returnVal;
}
int32_t DisplayDeviceProxy::SetLayerVisibleRegion(uint32_t devId, uint32_t layerId, uint32_t num, const IRect &rect)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    if (num <= 0) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERVISIBLEREGION)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, num)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(pTmpData, &rect, num)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERVISIBLEREGION, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::SetLayerBuffer(uint32_t devId, uint32_t layerId, const BufferHandle &buffer, int32_t fence)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }

    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERBUFFER)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteBufHdl(pTmpData, &buffer)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteFileDescriptor(pTmpData, fence)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERBUFFER, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::InvokeLayerCmd(uint32_t devId, uint32_t layerId, uint32_t cmd, ...)
{
    (void)devId;
    (void)layerId;
    (void)cmd;
    DISPLAY_LOG("interface start");
    return DISPLAY_NOT_SUPPORT;
}
int32_t DisplayDeviceProxy::SetLayerCompositionType(uint32_t devId, uint32_t layerId, CompositionType type)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERCOMPOSITIONTYPE)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(pTmpData, type)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERCOMPOSITIONTYPE, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceProxy::SetLayerBlendType(uint32_t devId, uint32_t layerId, BlendType type)
{
    DISPLAY_LOG("interface start");
    if (devId > MAX_DEVID) {
        DISPLAY_LOG("param error");
        return DISPLAY_PARAM_ERR;
    }
    MessageParcel dataParecel;
    MessageParcel repParecel;

    MessageParcel *pTmpData = &dataParecel;
    if (!DisplayDeviceWriteCmdId(pTmpData, DSP_CMD_SETLAYERBLENDTYPE)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, devId)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(pTmpData, layerId)) {
        DISPLAY_LOG("error: write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(pTmpData, type)) {
        DISPLAY_LOG("error: write type into data failed");
        return DISPLAY_FAILURE;
    }
    if (DisplayComposerExecuteCmd(DSP_CMD_SETLAYERBLENDTYPE, &dataParecel, &repParecel) != 0) {
        DISPLAY_LOG("fatal error: IPC called failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("interface end");
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceProxy::DisplayComposerExecuteCmd(
    DisplayDeviceCommandId cmdId, MessageParcel *dataParcel, MessageParcel *repParcel, void *data1, void *data2)
{
    DISPLAY_START;
    if (!DisplayDeviceWriteCmdId(dataParcel, DSP_CMD_EXECUTECMD)) {
        DISPLAY_LOG("error: write cmdId into data failed");
        return DISPLAY_FAILURE;
    }
    MessageOption option;
    int32_t ret = Remote()->SendRequest(cmdId, *dataParcel, *repParcel, option);

    DisplayDeviceCommandId receiveCmd = DSP_CMD_INVALID;
    DisplayDeviceCommandId verifyCmd = DSP_CMD_INVALID;
    int32_t cmdNum = 0;
    while (DSP_CMD_EXECUTECMD != (receiveCmd = DisplayDeviceReadCmdId(repParcel)) && ++cmdNum < COMPOSER_CMD_MAX_NUM) {
        DeviceReplyDataDistributer(verifyCmd = receiveCmd, repParcel, data1, data2);
    }
    DISPLAY_LOG("proxy receive return value number: %{public}d, command verify %{public}s!", cmdNum,
        ((cmdId & ~BATCH_CMD_FLAG) == verifyCmd) ? "successed" : "failed");
    DISPLAY_END;
    return ret;
}

static ComposerServerTmp g_serverRetTempValue;
static map<DisplayDeviceCommandId, int32_t> g_batchCmdRetVal;
static map<DisplayDeviceCommandId, uint32_t> g_batchCmdArrayNum;
void DisplayDeviceProxy::DeviceReplyDataDistributer(
    DisplayDeviceCommandId cmdId, MessageParcel *pReplay, void *data1, void *data2)
{
    DISPLAY_START;
    DISPLAY_LOG("read reply successed, command: %{public}x", cmdId);
    g_serverRetTempValue.cmdId = cmdId;
    g_serverRetTempValue.returnVal = -1;
    g_serverRetTempValue.arrayNum = -1;
    int32_t *pRectTmpVal = &g_serverRetTempValue.returnVal;
    int32_t *pRectTmpNum = &g_serverRetTempValue.arrayNum;
    uint32_t *pData1 = static_cast<uint32_t *>(data1);
    int32_t *pIntData1 = static_cast<int32_t *>(data1);
    bool *pDatab = static_cast<bool *>(data1);

    if (!DisplayDeviceReadInt32(pRectTmpVal, pReplay)) {
        DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
        return;
    }
    if (BATCH_CMD_FLAG == (cmdId & BATCH_CMD_FLAG)) {
        g_batchCmdRetVal.insert(pair<DisplayDeviceCommandId, int32_t>(
            static_cast<DisplayDeviceCommandId>(cmdId), g_serverRetTempValue.returnVal));
    }
    switch ((uint32_t)cmdId) {
        case ~BATCH_CMD_FLAG &DSP_CMD_REGHOTPLUGCALLBACK:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETDISPLAYMODE:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETDISPLAYPOWERSTATUS:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETDISPLAYBACKLIGHT:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETDISPLAYPROPERTY:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETDISPLAYCLIENTCROP:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETDISPLAYCLIENTDESTRECT:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETDISPLAYCLIENTBUFFER:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETDISPLAYCLIENTDAMAGE:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETDISPLAYVSYNCENABLED:
        case ~BATCH_CMD_FLAG &DSP_CMD_REGDISPLAYVBLANKCALLBACK:
        case ~BATCH_CMD_FLAG &DSP_CMD_INVOKEDISPLAYCMD:
        case ~BATCH_CMD_FLAG &DSP_CMD_DESTROYVIRTUALDISPLAY:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETVIRTUALDISPLAYBUFFER:
        case ~BATCH_CMD_FLAG &DSP_CMD_REGDISPLAYREFRESHCALLBACK:
        case ~BATCH_CMD_FLAG &DSP_CMD_DESTROYWRITEBACK:
        case ~BATCH_CMD_FLAG &DSP_CMD_SET_PROXY_REMOTE_CALLBACK:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERVISIBLE:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERCROP:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERZORDER:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERPREMULTI:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERALPHA:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERCOLORKEY:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERPALETTE:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERCOMPRESSION:
        case ~BATCH_CMD_FLAG &DSP_CMD_FLUSH:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERVISIBLEREGION:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERDIRTYREGION:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERBUFFER:
        case ~BATCH_CMD_FLAG &DSP_CMD_INVOKELAYERCMD:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERCOMPOSITIONTYPE:
        case ~BATCH_CMD_FLAG &DSP_CMD_INITDISPLAY:
        case ~BATCH_CMD_FLAG &DSP_CMD_DEINITDISPLAY:
        case ~BATCH_CMD_FLAG &DSP_CMD_CLOSELAYER:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERSIZE:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETTRANSFORMMODE:
        case ~BATCH_CMD_FLAG &DSP_CMD_WAITFORVBLANK:
        case ~BATCH_CMD_FLAG &DSP_CMD_SETLAYERBLENDTYPE:
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETDISPLAYCAPABILITY:
            if (!DisplayDeviceReadData(static_cast<DisplayCapability *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETDISPLAYSUPPPORTEDMODES:
            if (!DisplayDeviceReadData(&g_serverRetTempValue.arrayNum, pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            if (data1 == nullptr) {
                const int32_t tmpNum = g_serverRetTempValue.arrayNum;
                DisplayModeInfo dataTmp[tmpNum];
                memset_s(dataTmp, sizeof(dataTmp), 0, sizeof(dataTmp));
                if (!DisplayDeviceReadData(
                        static_cast<DisplayModeInfo *>(dataTmp), pReplay, g_serverRetTempValue.arrayNum)) {
                    DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                    return;
                }
            } else {
                if (!DisplayDeviceReadData(
                        static_cast<DisplayModeInfo *>(data1), pReplay, g_serverRetTempValue.arrayNum)) {
                    DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                    return;
                }
            }

            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETDISPLAYMODE:
            if (!DisplayDeviceReadUint32(pData1, pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETDISPLAYPOWERSTATUS:
            if (!DisplayDeviceReadInt32(pIntData1, pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            g_serverRetTempValue.cmdId = DSP_CMD_GETDISPLAYPOWERSTATUS;
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETDISPLAYBACKLIGHT:
            if (!DisplayDeviceReadUint32(pData1, pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETDISPLAYPROPERTY:
            if (!DisplayDeviceReadUint64(static_cast<uint64_t *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_PREPAREDISPLAYLAYERS:
            if (!DisplayDeviceReadBool(pDatab, pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETDISPLAYCOMPCHANGE:
            if (!DisplayDeviceReadInt32(pRectTmpNum, pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            if (g_serverRetTempValue.arrayNum == 0) {
                break;
            }
            if (data1 != nullptr) {
                if (!DisplayDeviceReadData(pData1, pReplay, g_serverRetTempValue.arrayNum)) {
                    DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                    return;
                }
            } else {
                uint32_t layers[g_serverRetTempValue.arrayNum];
                if (!DisplayDeviceReadData(static_cast<uint32_t *>(layers), pReplay, g_serverRetTempValue.arrayNum)) {
                    DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                    return;
                }
            }
            if (data2 != nullptr) {
                if (!DisplayDeviceReadData(static_cast<int32_t *>(data2), pReplay, g_serverRetTempValue.arrayNum)) {
                    DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                    return;
                }
            } else {
                int32_t types[g_serverRetTempValue.arrayNum];
                if (!DisplayDeviceReadData(static_cast<int32_t *>(types), pReplay, g_serverRetTempValue.arrayNum)) {
                    DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                    return;
                }
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETDISPLAYRELEASEFENCE:
            if (!DisplayDeviceReadInt32(pRectTmpNum, pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            if (data1 != nullptr) {
                if (!DisplayDeviceReadData(static_cast<uint32_t *>(data1), pReplay, g_serverRetTempValue.arrayNum)) {
                    DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                    return;
                }
            } else {
                uint32_t fenceLayers[g_serverRetTempValue.arrayNum];
                if (!DisplayDeviceReadData(static_cast<uint32_t *>(fenceLayers), pReplay,
                    g_serverRetTempValue.arrayNum)) {
                    DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                    return;
                }
            }
            if (data2 != nullptr) {
                if (!DisplayDeviceReadFileDescriptorArray(static_cast<int32_t *>(data2), pReplay,
                    g_serverRetTempValue.arrayNum)) {
                    DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                    return;
                }
            } else {
                int32_t fences[g_serverRetTempValue.arrayNum];
                if (!DisplayDeviceReadFileDescriptorArray(static_cast<int32_t *>(fences), pReplay,
                    g_serverRetTempValue.arrayNum)) {
                    DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                    return;
                }
                for (int32_t i = 0; i < g_serverRetTempValue.arrayNum; i++) {
                    if (fences[i] != -1) {
                        close(fences[i]);
                    }
                }
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_COMMIT:
            if (!DisplayDeviceReadFileDescriptor(static_cast<int32_t *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_CREATEVIRTUALDISPLAY:
            if (!DisplayDeviceReadInt32(pIntData1, pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            if (!DisplayDeviceReadUint32(static_cast<uint32_t *>(data2), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETWRITEBACKFRAME:
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_CREATEWRITEBACK:
            if (!DisplayDeviceReadUint32(static_cast<uint32_t *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            if (!DisplayDeviceReadInt32(pIntData1, pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_CREATELAYER:
            if (!DisplayDeviceReadData(static_cast<uint32_t *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETLAYERVISIBLESTATE:
            if (!DisplayDeviceReadData(static_cast<bool *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETLAYERZORDER:
            if (!DisplayDeviceReadData(static_cast<uint32_t *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETLAYERPREMULTI:
            if (!DisplayDeviceReadData(static_cast<bool *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETLAYERALPHA:
            if (!DisplayDeviceReadData(static_cast<LayerAlpha *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETLAYERCOLORKEY:
            if (!DisplayDeviceReadData(static_cast<bool *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            if (!DisplayDeviceReadData(static_cast<uint32_t *>(data2), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETLAYERPALETTE:
            if (!DisplayDeviceReadInt32(pRectTmpNum, pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            if (!DisplayDeviceReadData(static_cast<uint32_t *>(data1), pReplay, g_serverRetTempValue.arrayNum)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETLAYERCOMPRESSION:
            if (!DisplayDeviceReadData(static_cast<int32_t *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETLAYERBUFFER:
            if (!DisplayDeviceReadData(static_cast<LayerBuffer *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETDISPLAYINFO:
            if (!DisplayDeviceReadData(static_cast<DisplayInfo *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_GETLAYERSIZE:
            if (!DisplayDeviceReadData(static_cast<IRect *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        case ~BATCH_CMD_FLAG &DSP_CMD_SNAPSHOT:
            if (!DisplayDeviceReadData(static_cast<LayerBuffer *>(data1), pReplay)) {
                DISPLAY_LOG("error: read reply failed, command: %{public}d", cmdId);
                return;
            }
            break;
        default:
            break;
    }
    DISPLAY_END;
}
static ComposerServerTmp g_serverRetTempValueWrong = { DSP_CMD_RESERVED_1001, -1, -1 };
ComposerServerTmp *DisplayDeviceProxy::GetReturnData(DisplayDeviceCommandId cmdId) const
{
    DISPLAY_START;
    DISPLAY_LOG("%{public}s request cmd = %{public}x, verify cmd = %{public}x",
        ((cmdId & ~BATCH_CMD_FLAG) == g_serverRetTempValue.cmdId) ? "" : "error:", (cmdId & ~BATCH_CMD_FLAG),
        g_serverRetTempValue.cmdId);
    DISPLAY_END;
    return (g_serverRetTempValue.cmdId != (cmdId & ~BATCH_CMD_FLAG)) ? &g_serverRetTempValueWrong
                                                                     : &g_serverRetTempValue;
}
