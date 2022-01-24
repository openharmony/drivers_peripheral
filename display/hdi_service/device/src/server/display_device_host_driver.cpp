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

#include <hdf_remote_service.h>
#include <hdf_sbuf_ipc.h>
#include "display_device_common.h"
#include "display_device_service.h"
#include "display_device_stub.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG DisplayHostDriver

#define DDSS &DisplayDeviceServerStub

using OHOS::MessageParcel;
using OHOS::Display::Device::Server::DisplayDeviceServerStub;
using OHOS::Display::Device::Server::DisplayDeviceServerStubFunc;
using OHOS::Display::Device::Server::DisplayDeviceService;

struct HDF_CPS_SRV {
    struct IDeviceIoService ioservice;
    std::unique_ptr<DisplayDeviceServerStub> serviceStub;
};

static const DisplayDeviceServerStubFunc g_displayDeviceServerFuncTbl[HDF_DISPLAY_DRIVER_FUNC_TYPE_MAX]
                                                                     [HDF_DISPLAY_DRIVER_FUNC_NUM_MAX]
    = {
          /* reserved */
          {},
          /* DEVICE */
          { nullptr, nullptr, nullptr, DDSS::RegHotPlugCallback, DDSS::GetDisplayCapability,
              DDSS::GetDisplaySuppportedModes, DDSS::GetDisplayMode, DDSS::SetDisplayMode, DDSS::GetDisplayPowerStatus,
              DDSS::SetDisplayPowerStatus, DDSS::GetDisplayBackLight, DDSS::SetDisplayBackLight,
              DDSS::GetDisplayProperty, DDSS::SetDisplayProperty, DDSS::PrepareDisplayLayers, nullptr,
              DDSS::GetDisplayCompChange, nullptr, DDSS::SetDisplayClientCrop, DDSS::SetDisplayClientDestRect,
              DDSS::SetDisplayClientBuffer, DDSS::SetDisplayClientDamage, DDSS::SetDisplayVsyncEnabled, nullptr,
              nullptr, DDSS::RegDisplayVBlankCallback, nullptr, DDSS::GetDisplayReleaseFence, DDSS::Commit,
              DDSS::InvokeDisplayCmd, DDSS::CreateVirtualDisplay, DDSS::DestroyVirtualDisplay,
              DDSS::SetVirtualDisplayBuffer, DDSS::RegDisplayRefreshCallback, DDSS::GetWriteBackFrame,
              DDSS::CreateWriteBack, DDSS::DestroyWriteBack, DDSS::SetProxyRemoteCallback, DDSS::FileTest },
          /* LAYER */
          { nullptr, nullptr, nullptr, DDSS::CreateLayer, nullptr, DDSS::SetLayerVisible, DDSS::GetLayerVisibleState,
              nullptr, nullptr, DDSS::SetLayerCrop, DDSS::SetLayerZorder, DDSS::GetLayerZorder, DDSS::SetLayerPreMulti,
              DDSS::GetLayerPreMulti, DDSS::SetLayerAlpha, DDSS::GetLayerAlpha, DDSS::SetLayerColorKey,
              DDSS::GetLayerColorKey, DDSS::SetLayerPalette, DDSS::GetLayerPalette, nullptr, DDSS::SetLayerCompression,
              DDSS::GetLayerCompression, nullptr, DDSS::Flush, DDSS::SetLayerVisibleRegion, DDSS::SetLayerDirtyRegion,
              DDSS::GetLayerBuffer, DDSS::SetLayerBuffer, DDSS::InvokeLayerCmd, DDSS::SetLayerCompositionType, nullptr,
              DDSS::InitDisplay, DDSS::DeinitDisplay, DDSS::GetDisplayInfo, DDSS::CloseLayer, DDSS::SetLayerSize,
              DDSS::GetLayerSize, DDSS::SetTransformMode, DDSS::WaitForVBlank, DDSS::SnapShot, DDSS::SetLayerBlendType,
              DDSS::FileTest },
      };

static int32_t DisplayDeviceServiceDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    DISPLAY_START;
    DISPLAY_LOG("receive cmdId = %{public}0x", cmdId);
    do {
        if (client == nullptr || data == nullptr || reply == nullptr) {
            break;
        }

        HDF_CPS_SRV *displayDeviceSrv = CONTAINER_OF(client->device->service, HDF_CPS_SRV, ioservice);
        if (displayDeviceSrv == nullptr) {
            DISPLAY_LOG("error: invalid data sbuf object to dispatch");
            break;
        }

        if (displayDeviceSrv->serviceStub == nullptr) {
            displayDeviceSrv->serviceStub = std::make_unique<DisplayDeviceServerStub>();
        }

        MessageParcel *dataParcel = nullptr;
        MessageParcel *replyParcel = nullptr;
        if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS || SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
            DISPLAY_LOG("error: invalid data or reply sbuf object to dispatch");
            break;
        }

        DISPLAY_END;
        return displayDeviceSrv->serviceStub->OnRemoteRequest(cmdId, dataParcel, replyParcel);
    } while (0);

    DISPLAY_LOG("error: dispatch no matched");
    return HDF_ERR_INVALID_PARAM;
}

void DisplayDeviceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    DISPLAY_START;
    (void)deviceObject;
    DISPLAY_END;
}

int DisplayDeviceDriverBind(struct HdfDeviceObject *deviceObject)
{
    DISPLAY_START;
    static HDF_CPS_SRV displayDeviceSrv = {
        .ioservice = {
            .Open = nullptr,
            .Dispatch = DisplayDeviceServiceDispatch,
            .Release = nullptr,
        },
        .serviceStub = nullptr,
    };

    deviceObject->service = &displayDeviceSrv.ioservice;
    DISPLAY_END;
    return HDF_SUCCESS;
}

int DisplayDeviceDriverInit(struct HdfDeviceObject *deviceObject)
{
    DISPLAY_START;
    DISPLAY_END;
    return HDF_SUCCESS;
}

static struct HdfDriverEntry g_DisplayDeviceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "display_layer_driver",
    .Bind = DisplayDeviceDriverBind,
    .Init = DisplayDeviceDriverInit,
    .Release = DisplayDeviceDriverRelease,
};

extern "C" {
HDF_INIT(g_DisplayDeviceDriverEntry);
}

DisplayDeviceServerStub::DisplayDeviceServerStub()
{
    DISPLAY_START;
    device_ = std::make_unique<DisplayDeviceService>();
    DISPLAY_END;
}

int32_t DisplayDeviceServerStub::OnRemoteRequest(int cmdId, MessageParcel *data, MessageParcel *reply)
{
    DISPLAY_START;
    if (device_ == nullptr || !device_->IsValid()) {
        DISPLAY_LOG("display device service is not valid");
        return HDF_DEV_ERR_NO_DEVICE_SERVICE;
    }
    DISPLAY_LOG("YDEBUG: display device service good");
    DisplayDeviceCommandId currentCmd = DSP_CMD_INVALID;
    DisplayDeviceCommandId verifyCmd = DSP_CMD_INVALID;
    int32_t cmdNum = 0;
    while (DSP_CMD_EXECUTECMD != (currentCmd = DisplayDeviceReadCmdId(data)) && ++cmdNum < COMPOSER_CMD_MAX_NUM) {
        uint32_t functionType = (currentCmd >> 16) & 0xF;
        uint32_t functionNum = currentCmd & 0xFF;
        DisplayDeviceServerStubFunc functionPtr = nullptr;

        DISPLAY_LOG("received cmdId = %{public}0x", currentCmd);
        if ((functionPtr = g_displayDeviceServerFuncTbl[functionType][functionNum]) == nullptr) {
            DISPLAY_LOG("error : cmdId is undefined or deleted");
            break;
        }
        (this->*functionPtr)(data, reply, BATCH_CMD_FLAG == ((verifyCmd = currentCmd) & BATCH_CMD_FLAG));
    }
    DISPLAY_LOG("server receive cmd number: %{public}d, [0x%{public}x, 0x%{public}x] command verify %{public}s!",
        cmdNum, cmdId, verifyCmd, ((cmdId & ~BATCH_CMD_FLAG) == verifyCmd) ? "successed" : "failed");
    if (!reply->WriteUint32(DSP_CMD_EXECUTECMD)) {
        DISPLAY_LOG("error: write end command failed!");
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

static void HotPlugCallbackFunc(uint32_t devId, bool connected, void *data)
{
    HDF_LOGI("hotplug callback %{public}d %{public}d", devId, connected);
    auto callbackRemote = reinterpret_cast<DisplayDeviceCallbackProxy *>(data);
    auto ret = callbackRemote->OnHotplugIn(devId, connected);
    if (ret != 0) {
        HDF_LOGE("failed to hotplug callback %{public}d %{public}d", devId, connected);
    } else {
        HDF_LOGE("succ to hotplug callback %{public}d %{public}d", devId, connected);
    }
}

int32_t DisplayDeviceServerStub::RegHotPlugCallback(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    if (callbackRemote_ == nullptr) {
        DISPLAY_LOG("callback remote object is invalid");
        return HDF_ERR_INVALID_OBJECT;
    }
    int32_t ret = device_->RegHotPlugCallback(HotPlugCallbackFunc, callbackRemote_.GetRefPtr());
    DISPLAY_LOG("call RegHotPlugCallback impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_REGHOTPLUGCALLBACK)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_REGHOTPLUGCALLBACK);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetDisplayCapability(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;

    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DisplayCapability infoTmp = {};
    int32_t ret = device_->GetDisplayCapability(devIdTmp, infoTmp);
    DISPLAY_LOG("call GetDisplayCapability impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETDISPLAYCAPABILITY)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETDISPLAYCAPABILITY);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    if (!DisplayDeviceWriteData(reply, &infoTmp)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply phyWidth = %{public}u, propertyCount  %{public}u", infoTmp.phyWidth,
        infoTmp.propertyCount);
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetDisplaySuppportedModes(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;

    uint32_t devIdTmp = 0;
    int32_t modesNum = 1;
    if (!DisplayDeviceReadUint32(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceReadInt32(&modesNum, data) || modesNum > COMPOSER_SERVER_ARRAY_NUMBER_MAX) {
        DISPLAY_LOG("read devId numTmp data failed!");
        return DISPLAY_FAILURE;
    }
    DisplayModeInfo modesTmp[COMPOSER_SERVER_ARRAY_NUMBER_MAX];
    memset_s(&modesTmp, sizeof(modesTmp), 0, sizeof(modesTmp));

    int32_t ret = device_->GetDisplaySuppportedModes(devIdTmp, modesNum, modesTmp);
    DISPLAY_LOG("call GetDisplaySuppportedModes impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETDISPLAYSUPPPORTEDMODES)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETDISPLAYSUPPPORTEDMODES);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    if (!DisplayDeviceWriteInt32(reply, modesNum)) {
        DISPLAY_LOG("error: server write num into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write num into reply = %{public}d", modesNum);

    if (!DisplayDeviceWriteData(reply, modesTmp, modesNum)) {
        DISPLAY_LOG("error: server write DisplayModeInfo array into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetDisplayMode(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t modeTmp = 0;
    int32_t ret = device_->GetDisplayMode(devIdTmp, modeTmp);
    DISPLAY_LOG("call GetDisplayMode impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETDISPLAYMODE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETDISPLAYMODE);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);

    if (!DisplayDeviceWriteUint32(reply, modeTmp)) {
        HDF_LOGD("GetDisplayMode write data into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetDisplayMode(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t modeTmp = 0;
    if (!DisplayDeviceReadUint32(&modeTmp, data)) {
        DISPLAY_LOG("read mode from data failed!");
        return DISPLAY_FAILURE;
    }

    int32_t ret = device_->SetDisplayMode(devIdTmp, modeTmp);
    DISPLAY_LOG("call SetDisplayMode impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETDISPLAYMODE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETDISPLAYMODE);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetDisplayPowerStatus(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadUint32(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DispPowerStatus statusTmp = POWER_STATUS_BUTT;

    int32_t ret = device_->GetDisplayPowerStatus(devIdTmp, statusTmp);
    DISPLAY_LOG("call SetDisplayMode impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETDISPLAYPOWERSTATUS)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETDISPLAYPOWERSTATUS);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);

    if (!DisplayDeviceWriteInt32(reply, statusTmp)) {
        DISPLAY_LOG("error: server write status into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write status into reply = %{public}d", statusTmp);
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetDisplayPowerStatus(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t enumTmp = 0;
    if (!DisplayDeviceReadInt32(&enumTmp, data)) {
        DISPLAY_LOG("read enum from data failed!");
        return DISPLAY_FAILURE;
    }
    DispPowerStatus statusTmp = Convert2PowerStatus(enumTmp);

    int32_t ret = device_->SetDisplayPowerStatus(devIdTmp, statusTmp);
    DISPLAY_LOG("call SetDisplayPowerStatus impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETDISPLAYPOWERSTATUS)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETDISPLAYPOWERSTATUS);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetDisplayBackLight(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t valueTmp = 0;
    int32_t ret = device_->GetDisplayBacklight(devIdTmp, valueTmp);
    DISPLAY_LOG("call GetDisplayBackLight impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETDISPLAYBACKLIGHT)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETDISPLAYBACKLIGHT);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);

    if (!DisplayDeviceWriteUint32(reply, valueTmp)) {
        DISPLAY_LOG("error: server write value into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetDisplayBackLight(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;

    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t valueTmp = 0;
    if (!DisplayDeviceReadUint32(&valueTmp, data)) {
        DISPLAY_LOG("read value from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetDisplayBacklight(devIdTmp, valueTmp);
    DISPLAY_LOG("call SetDisplayBackLight impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETDISPLAYBACKLIGHT)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETDISPLAYBACKLIGHT);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetDisplayProperty(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t propertyIdTmp = 0;
    if (!DisplayDeviceReadUint32(&propertyIdTmp, data)) {
        DISPLAY_LOG("read propertyId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint64_t valueTmp = 0;
    int32_t ret = device_->GetDisplayProperty(devIdTmp, propertyIdTmp, valueTmp);
    DISPLAY_LOG("call GetDisplayProperty impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETDISPLAYPROPERTY)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETDISPLAYPROPERTY);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteUint64(reply, valueTmp)) {
        DISPLAY_LOG("error: server write value into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetDisplayProperty(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t propertyIdTmp = 0;
    if (!DisplayDeviceReadUint32(&propertyIdTmp, data)) {
        DISPLAY_LOG("read propertyId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint64_t valueTmp = 0;
    if (!DisplayDeviceReadUint64(&valueTmp, data)) {
        DISPLAY_LOG("read value from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetDisplayProperty(devIdTmp, propertyIdTmp, valueTmp);
    DISPLAY_LOG("call GetDisplayProperty impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETDISPLAYPROPERTY)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETDISPLAYPROPERTY);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::PrepareDisplayLayers(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;

    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    bool needFlushFbTmp = false;

    int32_t ret = device_->PrepareDisplayLayers(devIdTmp, needFlushFbTmp);
    DISPLAY_LOG("call PrepareDisplayLayers impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_PREPAREDISPLAYLAYERS)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_PREPAREDISPLAYLAYERS);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteBool(reply, needFlushFbTmp)) {
        DISPLAY_LOG("error: server write needFlushFb into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::GetDisplayCompChange(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t numTmp = 0;
    uint32_t layersTmp[COMPOSER_SERVER_ARRAY_NUMBER_MAX];
    int32_t typeTmp[COMPOSER_SERVER_ARRAY_NUMBER_MAX];
    memset_s(layersTmp, sizeof(layersTmp), 0, sizeof(layersTmp));
    memset_s(typeTmp, sizeof(typeTmp), 0, sizeof(typeTmp));

    int32_t ret = device_->GetDisplayCompChange(devIdTmp, numTmp, layersTmp, typeTmp);
    DISPLAY_LOG("call GetDisplayCompChange impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETDISPLAYCOMPCHANGE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETDISPLAYCOMPCHANGE);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteUint32(reply, numTmp)) {
        DISPLAY_LOG("error: server write num into data failed");
        return DISPLAY_FAILURE;
    }
    if (numTmp != 0) {
        if (!DisplayDeviceWriteData(reply, &layersTmp[0], numTmp)) {
            DISPLAY_LOG("error: server write layers array into data failed");
            return DISPLAY_FAILURE;
        }
        if (!DisplayDeviceWriteData(reply, &typeTmp[0], numTmp)) {
            DISPLAY_LOG("error: server write type array into data failed");
            return DISPLAY_FAILURE;
        }
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::SetDisplayClientCrop(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    IRect rectTmp;
    memset_s(&rectTmp, sizeof(rectTmp), 0, sizeof(rectTmp));
    if (!DisplayDeviceReadData(&rectTmp, data)) {
        DISPLAY_LOG("read rect from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("receive devIdTmp = %{public}u, x = %{public}d, y = %{public}d, w = %{public}d, h = %{public}d",
        devIdTmp, rectTmp.x, rectTmp.y, rectTmp.w, rectTmp.h);
    int32_t ret = device_->SetDisplayClientCrop(devIdTmp, &rectTmp);
    DISPLAY_LOG("call SetDisplayClientCrop impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETDISPLAYCLIENTCROP)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETDISPLAYCLIENTCROP);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetDisplayClientDestRect(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    IRect rectTmp;
    memset_s(&rectTmp, sizeof(rectTmp), 0, sizeof(rectTmp));
    if (!DisplayDeviceReadData(&rectTmp, data)) {
        DISPLAY_LOG("read rect from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("receive devIdTmp = %{public}u, x = %{public}d, y = %{public}d, w = %{public}d, h = %{public}d",
        devIdTmp, rectTmp.x, rectTmp.y, rectTmp.w, rectTmp.h);

    int32_t ret = device_->SetDisplayClientDestRect(devIdTmp, rectTmp);
    DISPLAY_LOG("call SetDisplayClientDestRect impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETDISPLAYCLIENTDESTRECT)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("write ret into reply failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetDisplayClientBuffer(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    BufferHandle *bufhandle = nullptr;
    if (!DisplayDeviceReadBufHdl(bufhandle, data)) {
        DISPLAY_LOG("read bufferhandle from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive bufferhandle fd = %{public}d, format = %{public}d", bufhandle->fd, bufhandle->format);

    int32_t fenceTmp = -1;
    if (!DisplayDeviceReadFileDescriptor(&fenceTmp, data)) {
        DISPLAY_LOG("read fence from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive fence = %{public}d", fenceTmp);
    int32_t ret = device_->SetDisplayClientBuffer(devIdTmp, *bufhandle, fenceTmp);
    DISPLAY_LOG("call SetDisplayClientDestRect impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETDISPLAYCLIENTBUFFER)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETDISPLAYCLIENTBUFFER);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("write ret into reply failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetDisplayClientDamage(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t numTmp = 0;
    if (!DisplayDeviceReadUint32(&numTmp, data)) {
        DISPLAY_LOG("read num from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive num = %{public}u", numTmp);
    const uint32_t arrayNum = numTmp;
    IRect rectTmp[arrayNum];
    memset_s(&rectTmp, sizeof(rectTmp), 0, sizeof(rectTmp));
    if (!DisplayDeviceReadData(rectTmp, data, numTmp)) {
        DISPLAY_LOG("read rect from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("receive rect array successed");
    int32_t ret = device_->SetDisplayClientDamage(devIdTmp, numTmp, rectTmp[0]);
    DISPLAY_LOG("call SetDisplayClientDestRect impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETDISPLAYCLIENTDAMAGE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETDISPLAYCLIENTDAMAGE);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("write data into reply failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetDisplayVsyncEnabled(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    bool enableTmp = false;
    if (!DisplayDeviceReadBool(&enableTmp, data)) {
        DISPLAY_LOG("read enable from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive enable = %{public}s", enableTmp ? "true" : "false");
    int32_t ret = device_->SetDisplayVsyncEnabled(devIdTmp, enableTmp);
    DISPLAY_LOG("call SetDisplayVsyncEnabled impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETDISPLAYVSYNCENABLED)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETDISPLAYVSYNCENABLED);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("write ret into reply failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

static void VBlankCallbackFunc(unsigned int sequence, uint64_t ns, void *data)
{
    HDF_LOGI("hotplug callback %{public}d", sequence);
    if (data == nullptr) {
        HDF_LOGI("vblank callback data nullptr");
        return;
    }
    auto callbackRemote = reinterpret_cast<DisplayDeviceCallbackProxy *>(data);
    auto ret = callbackRemote->OnVBlankCallback(sequence, ns);
    if (ret != 0) {
        HDF_LOGE("failed to vblank callback %{public}d", ret);
    } else {
        HDF_LOGE("succ to vblank callback");
    }
}

int32_t DisplayDeviceServerStub::RegDisplayVBlankCallback(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    if (callbackRemote_ == nullptr) {
        DISPLAY_LOG("callback remote object is invalid");
        return HDF_ERR_INVALID_OBJECT;
    }
    uint32_t devId = 0;
    if (!DisplayDeviceReadUint32(&devId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->RegDisplayVBlankCallback(devId, VBlankCallbackFunc, callbackRemote_.GetRefPtr());

    DISPLAY_LOG("call RegDisplayVBlankCallback impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_REGDISPLAYVBLANKCALLBACK)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_REGDISPLAYVBLANKCALLBACK);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::GetDisplayReleaseFence(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t numTmp = 0;
    uint32_t layersTmp[COMPOSER_SERVER_ARRAY_NUMBER_MAX];
    int32_t fenceTmp[COMPOSER_SERVER_ARRAY_NUMBER_MAX];
    memset_s(layersTmp, sizeof(layersTmp), 0, sizeof(layersTmp));
    memset_s(fenceTmp, sizeof(fenceTmp), 0, sizeof(fenceTmp));
    int32_t ret = device_->GetDisplayReleaseFence(devIdTmp, &numTmp, layersTmp, fenceTmp);
    DISPLAY_LOG("call GetDisplayReleaseFence impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETDISPLAYRELEASEFENCE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETDISPLAYRELEASEFENCE);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteUint32(reply, numTmp)) {
        DISPLAY_LOG("error: server write num into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(reply, layersTmp, numTmp)) {
        DISPLAY_LOG("error: server write layers array into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteFileDescriptorArray(reply, fenceTmp, numTmp)) {
        DISPLAY_LOG("error: server write fence array into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::Commit(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    int32_t fenceTmp = -1;

    int32_t ret = device_->Commit(devIdTmp, fenceTmp);
    DISPLAY_LOG("call Commit impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_COMMIT)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteFileDescriptor(reply, fenceTmp)) {
        DISPLAY_LOG("error: write value into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::InvokeDisplayCmd(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->InvokeDisplayCmd(devIdTmp);
    DISPLAY_LOG("call InvokeDisplayCmd impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_INVOKEDISPLAYCMD)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_INVOKEDISPLAYCMD);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::CreateVirtualDisplay(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t widthTmp = 0;
    if (!DisplayDeviceReadUint32(&widthTmp, data)) {
        DISPLAY_LOG("read width from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t heightTmp = 0;
    if (!DisplayDeviceReadUint32(&heightTmp, data)) {
        DISPLAY_LOG("read height from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t formatTmp = 0;
    uint32_t devIdTmp = 0;

    int32_t ret = device_->CreateVirtualDisplay(widthTmp, heightTmp, formatTmp, devIdTmp);
    DISPLAY_LOG("call CreateVirtualDisplay impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_CREATEVIRTUALDISPLAY)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_CREATEVIRTUALDISPLAY);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(reply, formatTmp)) {
        DISPLAY_LOG("error: write value into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write format into reply = %{public}d", formatTmp);
    if (!DisplayDeviceWriteUint32(reply, devIdTmp)) {
        DISPLAY_LOG("error: write devId into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write devId into reply = %{public}u", devIdTmp);
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::DestroyVirtualDisplay(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->DestroyVirtualDisplay(devIdTmp);
    DISPLAY_LOG("call CreateVirtualDisplay impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_DESTROYVIRTUALDISPLAY)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_DESTROYVIRTUALDISPLAY);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetVirtualDisplayBuffer(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    BufferHandle *bufhandleTmp = nullptr;
    if (!DisplayDeviceReadBufHdl(bufhandleTmp, data)) {
        DISPLAY_LOG("read bufferhandle from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t fenceTmp = -1;
    if (!DisplayDeviceReadFileDescriptor(&fenceTmp, data)) {
        DISPLAY_LOG("read fence from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetVirtualDisplayBuffer(devIdTmp, bufhandleTmp, fenceTmp);
    DISPLAY_LOG("call SetVirtualDisplayBuffer impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETVIRTUALDISPLAYBUFFER)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETVIRTUALDISPLAYBUFFER);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

static void RefreshCallbackFunc(uint32_t devId, void *data)
{
    HDF_LOGI("hotplug callback %{public}d", devId);
    if (data == nullptr) {
        HDF_LOGE("refresh callback data nullptr");
        return;
    }
    auto callbackRemote = reinterpret_cast<DisplayDeviceCallbackProxy *>(data);
    auto ret = callbackRemote->OnRefreshCallback(devId);
    if (ret != 0) {
        HDF_LOGE("failed to hotplug callback %{public}d %{public}d", devId, ret);
    } else {
        HDF_LOGE("succ to hotplug callback");
    }
}

int32_t DisplayDeviceServerStub::RegDisplayRefreshCallback(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    if (callbackRemote_ == nullptr) {
        DISPLAY_LOG("callback remote object is invalid");
        return HDF_ERR_INVALID_OBJECT;
    }
    uint32_t devId = 0;
    if (!DisplayDeviceReadUint32(&devId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->RegDisplayRefreshCallback(devId, RefreshCallbackFunc, callbackRemote_.GetRefPtr());

    DISPLAY_LOG("call RegDisplayRefreshCallback impl ret = %{public}d", ret);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_REGDISPLAYREFRESHCALLBACK)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::GetWriteBackFrame(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    BufferHandle bufferTmp;
    memset_s(&bufferTmp, sizeof(bufferTmp), 0, sizeof(bufferTmp));
    int32_t fenceTmp = 0;

    int32_t ret = 0;
    DISPLAY_LOG("call GetWriteBackFrame impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETWRITEBACKFRAME)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETWRITEBACKFRAME);
    if (!DisplayDeviceWriteBufHdl(data, (const BufferHandle *)&bufferTmp)) {
        DISPLAY_LOG("read buffer from data failed!");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteInt32(reply, fenceTmp)) {
        DISPLAY_LOG("error: server write fence into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write fence into reply = %{public}d", fenceTmp);

    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::CreateWriteBack(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t widthTmp = 0;
    if (!DisplayDeviceReadUint32(&widthTmp, data)) {
        DISPLAY_LOG("read width from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive width = %{public}u", widthTmp);

    uint32_t heightTmp = 0;
    if (!DisplayDeviceReadUint32(&heightTmp, data)) {
        DISPLAY_LOG("read height from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive height = %{public}u", heightTmp);

    int32_t formatTmp = 0;

    int32_t ret = 0;
    DISPLAY_LOG("call CreateWriteBack impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_CREATEWRITEBACK)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_CREATEWRITEBACK);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteUint32(reply, devIdTmp)) {
        DISPLAY_LOG("error: server write devId into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write devId into reply = %{public}u", devIdTmp);

    if (!DisplayDeviceWriteInt32(reply, formatTmp)) {
        DISPLAY_LOG("error: server write format into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write format into reply = %{public}d", formatTmp);

    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::DestroyWriteBack(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    int32_t ret = 0;
    DISPLAY_LOG("call DestroyWriteBack impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_DESTROYWRITEBACK)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_DESTROYWRITEBACK);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);

    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::FileTest(MessageParcel *data, MessageParcel *reply, bool)
{
    HDF_LOGD("testIF 04");
    bool receiveData = data->ReadBool();
    if (receiveData) {
        HDF_LOGD("stub receive true");
    } else {
        HDF_LOGD("stub receive false");
    }
    if (!reply->WriteBool(receiveData)) {
        HDF_LOGD("testIF error 04 write failed!");
    }
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::SetCallBackObject(sptr<IRemoteObject> callbackRemote)
{
    callbackRemote_ = iface_cast<DisplayDeviceCallbackProxy>(callbackRemote);
    if (callbackRemote_ == nullptr) {
        HDF_LOGE("failed to iface_cast DisplayDeviceCallbackProxy");
        return HDF_ERR_INVALID_OBJECT;
    }

    return HDF_SUCCESS;
}

int32_t DisplayDeviceServerStub::SetProxyRemoteCallback(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;

    if (data->ReadUint32() != 1) {
        DISPLAY_LOG("read Remote Object size from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive Remote Object size = %{public}d", 1);
    sptr<IRemoteObject> remoteObj = data->ReadRemoteObject();
    if (remoteObj == nullptr) {
        DISPLAY_LOG("read Remote Object from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = SetCallBackObject(remoteObj);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SET_PROXY_REMOTE_CALLBACK)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    DISPLAY_END;
    return ret;
}

int32_t DisplayDeviceServerStub::CreateLayer(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    LayerInfo layerinfoTmp;
    memset_s(&layerinfoTmp, sizeof(layerinfoTmp), 0, sizeof(layerinfoTmp));
    if (!DisplayDeviceReadData(&layerinfoTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }

    uint32_t layerIdTmp = 0;
    int32_t ret = device_->CreateLayer(devIdTmp, layerinfoTmp, layerIdTmp);
    DISPLAY_LOG("call CreateLayer impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_CREATELAYER)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_CREATELAYER);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    if (!DisplayDeviceWriteUint32(reply, layerIdTmp)) {
        DISPLAY_LOG("error: server write layerId into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write layerId into reply = %{public}d", layerIdTmp);
    DISPLAY_END;
    return ret;
}

int32_t DisplayDeviceServerStub::SetLayerVisible(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }

    bool visibleTmp = 0;
    if (!DisplayDeviceReadData(&visibleTmp, data)) {
        DISPLAY_LOG("read visible from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetLayerVisible(devIdTmp, layerIdTmp, visibleTmp);
    DISPLAY_LOG("call SetLayerVisible impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERVISIBLE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETLAYERVISIBLE);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetLayerVisibleState(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    bool visibleTmp = false;
    int32_t ret = device_->GetLayerVisibleState(devIdTmp, layerIdTmp, visibleTmp);
    DISPLAY_LOG("call GetLayerVisibleState impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETLAYERVISIBLESTATE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETLAYERVISIBLESTATE);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write format into reply = %{public}d", ret);
    if (!DisplayDeviceWriteData(reply, &visibleTmp)) {
        DISPLAY_LOG("error: server write visible into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::SetLayerCrop(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    IRect rectTmp;
    memset_s(&rectTmp, sizeof(rectTmp), 0, sizeof(rectTmp));
    if (!DisplayDeviceReadData(&rectTmp, data)) {
        DISPLAY_LOG("read rect from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetLayerCrop(devIdTmp, layerIdTmp, &rectTmp);
    DISPLAY_LOG("call SetLayerCrop impl ret = %{public}d", ret);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERCROP)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETLAYERCROP);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetLayerZorder(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t zorderTmp = 0;
    if (!DisplayDeviceReadData(&zorderTmp, data)) {
        DISPLAY_LOG("read zorder from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetLayerZorder(devIdTmp, layerIdTmp, zorderTmp);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERZORDER)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETLAYERZORDER);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return ret;
}
int32_t DisplayDeviceServerStub::GetLayerZorder(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t zorderTmp = 0;
    int32_t ret = device_->GetLayerZorder(devIdTmp, layerIdTmp, zorderTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETLAYERZORDER)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETLAYERZORDER);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(reply, zorderTmp)) {
        DISPLAY_LOG("error: server write zorder into data failed");
        return DISPLAY_FAILURE;
    }

    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetLayerPreMulti(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    bool preMulTmp = 0;
    if (!DisplayDeviceReadData(&preMulTmp, data)) {
        DISPLAY_LOG("read preMul from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetLayerPreMulti(devIdTmp, layerIdTmp, preMulTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERPREMULTI)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETLAYERPREMULTI);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetLayerPreMulti(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    bool preMulTmp = 0;
    int32_t ret = device_->GetLayerPreMulti(devIdTmp, layerIdTmp, preMulTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETLAYERPREMULTI)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETLAYERPREMULTI);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteBool(reply, preMulTmp)) {
        DISPLAY_LOG("error: server write preMul into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetLayerAlpha(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devId = 0;
    if (!DisplayDeviceReadUint32(&devId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }

    uint32_t layerId = 0;
    if (!DisplayDeviceReadUint32(&layerId, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    LayerAlpha alpha;
    memset_s(&alpha, sizeof(alpha), 0, sizeof(alpha));
    if (!DisplayDeviceReadData(&alpha, data)) {
        DISPLAY_LOG("read alpha from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetLayerAlpha(devId, layerId, alpha);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERALPHA)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETLAYERALPHA);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetLayerAlpha(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    LayerAlpha alphaTmp;
    memset_s(&alphaTmp, sizeof(alphaTmp), 0, sizeof(alphaTmp));
    int32_t ret = device_->GetLayerAlpha(devIdTmp, layerIdTmp, alphaTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETLAYERALPHA)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETLAYERALPHA);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(reply, &alphaTmp)) {
        DISPLAY_LOG("error: server write zorder into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetLayerColorKey(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    bool enableTmp = false;
    if (!DisplayDeviceReadData(&enableTmp, data)) {
        DISPLAY_LOG("read enable from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t keyTmp = 0;
    if (!DisplayDeviceReadData(&keyTmp, data)) {
        DISPLAY_LOG("read key from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetLayerColorKey(devIdTmp, layerIdTmp, enableTmp, keyTmp);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERCOLORKEY)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETLAYERCOLORKEY);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetLayerColorKey(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    bool enableTmp = false;
    uint32_t keyTmp = 0;
    int32_t ret = device_->GetLayerColorKey(devIdTmp, layerIdTmp, &enableTmp, &keyTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETLAYERCOLORKEY)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETLAYERCOLORKEY);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(reply, &enableTmp)) {
        DISPLAY_LOG("error: server write enable into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(reply, &keyTmp)) {
        DISPLAY_LOG("error: server write key into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetLayerPalette(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t lenTmp = 0;
    if (!DisplayDeviceReadData(&lenTmp, data)) {
        DISPLAY_LOG("read len from data failed!");
        return DISPLAY_FAILURE;
    }
    const uint32_t arrayNum = lenTmp;
    uint32_t paletteTmp[arrayNum];
    memset_s(&paletteTmp, sizeof(paletteTmp), 0, sizeof(paletteTmp));
    if (!DisplayDeviceReadData(&paletteTmp[0], data, lenTmp)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetLayerPalette(devIdTmp, layerIdTmp, paletteTmp, lenTmp);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERPALETTE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETLAYERPALETTE);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetLayerPalette(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t lenTmp = 0;
    if (!DisplayDeviceReadData(&lenTmp, data)) {
        DISPLAY_LOG("read len from data failed!");
        return DISPLAY_FAILURE;
    }
    const uint32_t arrayNum = lenTmp;
    uint32_t palette[arrayNum];
    memset_s(palette, sizeof(palette), 0, sizeof(palette));
    int32_t ret = device_->GetLayerPalette(devIdTmp, layerIdTmp, palette[0], lenTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETLAYERPALETTE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETLAYERPALETTE);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(reply, lenTmp)) {
        DISPLAY_LOG("error: server write len into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(reply, &palette[0], lenTmp)) {
        DISPLAY_LOG("error: server write palette array into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::SetLayerCompression(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t compTypeTmp = 0;
    if (!DisplayDeviceReadData(&compTypeTmp, data)) {
        DISPLAY_LOG("read compTypeTmp from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetLayerCompression(devIdTmp, layerIdTmp, compTypeTmp);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERCOMPRESSION)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETLAYERCOMPRESSION);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetLayerCompression(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t compTypeTmp = 0;
    int32_t ret = device_->GetLayerCompression(devIdTmp, layerIdTmp, compTypeTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETLAYERCOMPRESSION)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETLAYERCOMPRESSION);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteInt32(reply, compTypeTmp)) {
        DISPLAY_LOG("error: server compType ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::Flush(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    LayerBuffer bufferTmp;
    memset_s(&bufferTmp, sizeof(bufferTmp), 0, sizeof(bufferTmp));
    if (!DisplayDeviceReadData(&bufferTmp, data)) {
        DISPLAY_LOG("read bufferTmp from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->Flush(devIdTmp, layerIdTmp, bufferTmp);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_FLUSH)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_FLUSH);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetLayerVisibleRegion(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t numTmp = 0;
    if (!DisplayDeviceReadData(&numTmp, data)) {
        DISPLAY_LOG("read num from data failed!");
        return DISPLAY_FAILURE;
    }
    const uint32_t arrayNum = numTmp;
    IRect rectTmp[arrayNum];
    memset_s(rectTmp, sizeof(rectTmp), 0, sizeof(rectTmp));
    if (!DisplayDeviceReadData(&rectTmp[0], data, numTmp)) {
        DISPLAY_LOG("read rect from data failed!");
        return DISPLAY_FAILURE;
    }

    int32_t ret = device_->SetLayerDirtyRegion(devIdTmp, layerIdTmp, numTmp, rectTmp[0]);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERVISIBLEREGION)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetLayerDirtyRegion(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t numTmp = 0;
    if (!DisplayDeviceReadData(&numTmp, data)) {
        DISPLAY_LOG("read num from data failed!");
        return DISPLAY_FAILURE;
    }
    const uint32_t arrayNum = numTmp;
    IRect regionTmp[arrayNum];
    memset_s(&regionTmp, sizeof(regionTmp), 0, sizeof(regionTmp));
    if (!DisplayDeviceReadData(&regionTmp[0], data, numTmp)) {
        DISPLAY_LOG("read region from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->SetLayerDirtyRegion(devIdTmp, layerIdTmp, numTmp, regionTmp[0]);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERDIRTYREGION)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETLAYERDIRTYREGION);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::GetLayerBuffer(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    LayerBuffer bufferTmp;
    memset_s(&bufferTmp, sizeof(bufferTmp), 0, sizeof(bufferTmp));
    int32_t ret = 0;

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETLAYERBUFFER)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETLAYERBUFFER);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    if (!DisplayDeviceWriteData(reply, &bufferTmp)) {
        DISPLAY_LOG("error: server write buffer into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetLayerBuffer(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    BufferHandle *bufhandleTmp = nullptr;
    if (!DisplayDeviceReadBufHdl(bufhandleTmp, data)) {
        DISPLAY_LOG("read bufhandle from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t fenceTmp = -1;
    if (!DisplayDeviceReadFileDescriptor(&fenceTmp, data)) {
        DISPLAY_LOG("read fence from data failed!");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("xxx Read FileDescriptor fd:%{public}d", fenceTmp);
    int32_t ret = device_->SetLayerBuffer(devIdTmp, layerIdTmp, *bufhandleTmp, fenceTmp);
    DISPLAY_LOG("sss Read FileDescriptor fd:%{public}d", fenceTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERBUFFER)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }

    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::InvokeLayerCmd(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t cmdTmp = 0;
    if (!DisplayDeviceReadData(&cmdTmp, data)) {
        DISPLAY_LOG("read cmd from data failed!");
        return DISPLAY_FAILURE;
    }
    int32_t ret = device_->InvokeLayerCmd(devIdTmp, layerIdTmp, cmdTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_INVOKELAYERCMD)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }

    DISPLAY_END;
    return DISPLAY_SUCCESS;
}
int32_t DisplayDeviceServerStub::SetLayerCompositionType(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    if (!DisplayDeviceReadData(&devIdTmp, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadData(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    uint32_t enumTmp = 0;
    if (!DisplayDeviceReadData(&enumTmp, data)) {
        DISPLAY_LOG("read CompositionType from data failed!");
        return DISPLAY_FAILURE;
    }
    CompositionType compositiontypeTmp = Convert2CompositionType(enumTmp);

    int32_t ret = device_->SetLayerCompositionType(devIdTmp, layerIdTmp, compositiontypeTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERCOMPOSITIONTYPE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }

    DISPLAY_END;
    return ret;
}

int32_t DisplayDeviceServerStub::InitDisplay(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    int32_t ret = 0;

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_INITDISPLAY)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_INITDISPLAY);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);

    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::DeinitDisplay(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    int32_t ret = 0;

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_DEINITDISPLAY)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_DEINITDISPLAY);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);

    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::GetDisplayInfo(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    DisplayInfo dispInfoTmp;
    memset_s(&dispInfoTmp, sizeof(dispInfoTmp), 0, sizeof(dispInfoTmp));

    int32_t ret = 0;

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETDISPLAYINFO)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETDISPLAYINFO);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    if (!DisplayDeviceWriteData(reply, &dispInfoTmp)) {
        DISPLAY_LOG("error: server write dispInfo into data failed");
        return DISPLAY_FAILURE;
    }

    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::CloseLayer(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    uint32_t layerTmp = 0;
    if (!DisplayDeviceReadUint32(&layerTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive layer = %{public}u", layerTmp);

    int32_t ret = device_->CloseLayer(devIdTmp, layerTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_CLOSELAYER)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_CLOSELAYER);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);

    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::SetLayerSize(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devId = 0;
    if (!DisplayDeviceReadUint32(&devId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devId);

    uint32_t layerId = 0;
    if (!DisplayDeviceReadUint32(&layerId, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive layer = %{public}u", layerId);

    IRect rectTmp = {};
    if (!DisplayDeviceReadData(&rectTmp, data)) {
        DISPLAY_LOG("read rect from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("receive devId = %{public}d, x = %{public}d, y = %{public}d, w = %{public}d, h = %{public}d", devId,
        rectTmp.x, rectTmp.y, rectTmp.w, rectTmp.h);

    int32_t ret = device_->SetLayerSize(devId, layerId, &rectTmp);

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERSIZE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETLAYERSIZE);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::GetLayerSize(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadUint32(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive layer = %{public}u", layerIdTmp);

    IRect rect = {};
    int32_t ret = device_->GetLayerSize(devIdTmp, layerIdTmp, rect);
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_GETLAYERSIZE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_GETLAYERSIZE);
    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);

    if (!DisplayDeviceWriteData(reply, &rect)) {
        DISPLAY_LOG("write data into reply failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("write rect into reply: x = %{public}d, y = %{public}d, w = %{public}d, h = %{public}d", rect.x, rect.y,
        rect.w, rect.h);
    DISPLAY_END;
    return ret;
}

int32_t DisplayDeviceServerStub::SetTransformMode(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadUint32(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive layer = %{public}u", layerIdTmp);

    int32_t enumTmp = 0;
    if (!DisplayDeviceReadInt32(&enumTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive type = %{public}d", enumTmp);
    TransformType typeTmp = Convert2TransformType(enumTmp);

    int32_t ret = device_->SetTransformMode(devIdTmp, layerIdTmp, typeTmp);
    typeTmp = ROTATE_BUTT;
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETTRANSFORMMODE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETTRANSFORMMODE);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    DISPLAY_END;
    return ret;
}

int32_t DisplayDeviceServerStub::WaitForVBlank(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadUint32(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive layer = %{public}u", layerIdTmp);

    int32_t timeOutTmp = 0;
    int32_t *pTimeTmp = &timeOutTmp;
    if (!DisplayDeviceReadInt32(pTimeTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive timeOut = %{public}d", timeOutTmp);

    int32_t ret = 0;

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_WAITFORVBLANK)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_WAITFORVBLANK);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    DISPLAY_END;
    return ret;
}

int32_t DisplayDeviceServerStub::SnapShot(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    LayerBuffer bufferTmp;
    memset_s(&bufferTmp, sizeof(bufferTmp), 0, sizeof(bufferTmp));
    if (!DisplayDeviceReadData(&bufferTmp, data)) {
        DISPLAY_LOG("read LayerBuffer from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("receive displayInfo fenceId = %{public}d, pitch = %{public}d", bufferTmp.fenceId, bufferTmp.pitch);

    int32_t ret = 0;

    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SNAPSHOT)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SNAPSHOT);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write ret into reply = %{public}d", ret);

    DISPLAY_END;
    return DISPLAY_SUCCESS;
}

int32_t DisplayDeviceServerStub::SetLayerBlendType(MessageParcel *data, MessageParcel *reply, bool isBatchCmd)
{
    DISPLAY_START;
    uint32_t devIdTmp = 0;
    uint32_t *pDevId = &devIdTmp;
    if (!DisplayDeviceReadUint32(pDevId, data)) {
        DISPLAY_LOG("read devId from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive devId = %{public}u", devIdTmp);

    uint32_t layerIdTmp = 0;
    if (!DisplayDeviceReadUint32(&layerIdTmp, data)) {
        DISPLAY_LOG("read layer from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive layer = %{public}u", layerIdTmp);

    int32_t enumTmp = 0;
    int32_t *pEnumTmp = &enumTmp;
    if (!DisplayDeviceReadInt32(pEnumTmp, data)) {
        DISPLAY_LOG("read BlendType from data failed!");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server receive type = %{public}d", enumTmp);
    BlendType typeTmp = Convert2BlendTypeType(enumTmp);

    int32_t ret = 0;
    typeTmp = BLEND_NONE;
    if (!DisplayDeviceWriteCmdId(reply, DSP_CMD_SETLAYERBLENDTYPE)) {
        DISPLAY_LOG("error: write cmdId into reply failed");
        return DISPLAY_FAILURE;
    }
    DISPLAY_LOG("server write cmd into reply = %{public}0x", DSP_CMD_SETLAYERBLENDTYPE);

    if (!DisplayDeviceWriteInt32(reply, ret)) {
        DISPLAY_LOG("error: server write ret into data failed");
        return DISPLAY_FAILURE;
    }

    DISPLAY_LOG("server write ret into reply = %{public}d", ret);
    DISPLAY_END;
    return ret;
}
