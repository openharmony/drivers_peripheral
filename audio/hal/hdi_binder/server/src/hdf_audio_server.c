/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hdf_audio_server.h"
#include "hdf_audio_server_common.h"

#define HDF_LOG_TAG hdf_audio_server
struct AudioAdapterDescriptor *g_descs = NULL;
struct AudioManager *g_serverManager = NULL;

/**************************public************************/
int32_t HdiServiceGetFuncs()
{
    HDF_LOGE("%{public}s", "enter to HdiServiceGetFuncs ");
    if (g_serverManager != NULL) {
        return HDF_SUCCESS;
    }
    g_serverManager = GetAudioManagerFuncs();
    if (g_serverManager == NULL) {
        HDF_LOGE("%{public}s", "GetAudioManagerFuncs FAIL!\n");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t HdiServiceGetAllAdapter(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    HDF_LOGE("%{public}s", "enter to HdiServiceGetAllAdapter ");
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioAdapterDescriptor *descs = NULL;
    struct AudioManager *manager = g_serverManager;
    int32_t size = 0;
    if (manager == NULL) {
        HDF_LOGE("%{public}s", "Manager is NULL");
        return HDF_FAILURE;
    }
    int32_t ret = manager->GetAllAdapters(manager, &descs, &size);
    if (ret < 0) {
        HDF_LOGE("%{public}s", "g_manager->GetAllAdapters error");
        return HDF_FAILURE;
    }
    if (size > MAX_AUDIO_ADAPTER_NUM_SERVER || size == 0 || descs == NULL || ret < 0) {
        HDF_LOGE("%{public}s", "size or g_descs is error");
        return HDF_ERR_NOT_SUPPORT;
    }
    g_descs = descs;
    HDF_LOGE("%{public}s", "GetAllAdapters out");
    return HDF_SUCCESS;
}

int SwitchAdapter(struct AudioAdapterDescriptor *descs, const char *adapterNameCase, enum AudioPortDirection portFlag,
                  struct AudioPort *renderPort, const int size)
{
    if (descs == NULL || adapterNameCase == NULL || renderPort == NULL) {
        return HDF_FAILURE;
    }
    for (int index = 0; index < size; index++) {
        struct AudioAdapterDescriptor *desc = &descs[index];
        if (strcmp(desc->adapterName, adapterNameCase)) {
            continue;
        }
        for (uint32_t port = 0; ((desc != NULL) && (port < desc->portNum)); port++) {
            if (desc->ports[port].dir == portFlag) {
                *renderPort = desc->ports[port];
                HDF_LOGE("%{public}s,%{public}d", "SwitchAdapter success!", portFlag);
                return index;
            }
        }
    }
    HDF_LOGE("%{public}s", "SwitchAdapter out!");
    return HDF_FAILURE;
}

/* Adapter Check */

static int32_t HdiServiceLoadAdapter(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioAdapter *adapter = NULL;
    struct AudioPort renderPort;
    const char *adapterName = NULL;
    uint32_t tempDir;
    if ((adapterName = HdfSbufReadString(data)) == NULL) {
        HDF_LOGE("%{public}s", "adapterNameCase Is NULL");
        return HDF_FAILURE;
    }
    int32_t ret = AudioAdapterCheckListExist(adapterName);
    if (ret == HDF_ERR_INVALID_PARAM) {
        return HDF_FAILURE;
    }
    if (ret == HDF_SUCCESS) {
        HDF_LOGE("%{public}s", "HdiServiceLoadAdapter: adapte already exist !");
        return HDF_SUCCESS;
    }
    if (!HdfSbufReadUint32(data, &tempDir)) {
        HDF_LOGE("%{public}s", "HdiServiceLoadAdapter: adapter need Load!");
        return HDF_FAILURE;
    }
    enum AudioPortDirection port = (enum AudioPortDirection)tempDir;
    struct AudioManager *manager = g_serverManager;
    if (adapterName == NULL || manager == NULL || g_descs == NULL) {
        HDF_LOGE("%{public}s", "Point is NULL!");
        return HDF_FAILURE;
    }
    int index = SwitchAdapter(g_descs, adapterName, port, &renderPort, MAX_AUDIO_ADAPTER_NUM_SERVER);
    if (index < 0) {
        return HDF_ERR_NOT_SUPPORT;
    }
    struct AudioAdapterDescriptor *desc = &g_descs[index];
    ret = manager->LoadAdapter(manager, desc, &adapter);
    if (ret < 0) {
        return HDF_ERR_NOT_SUPPORT;
    }
    if (adapter == NULL) {
        HDF_LOGE("%{public}s", "load audio device failed");
        return HDF_FAILURE;
    }
    if (AudioAdapterListAdd(adapterName, adapter)) {
        HDF_LOGE("%{public}s", "AudioAdapterListAdd error!");
        manager->UnloadAdapter(manager, adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t HdiServiceInitAllPorts(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    HDF_LOGE("%{public}s", "HdiServiceInitAllPorts");
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    const char *adapterName = NULL;
    struct AudioAdapter *adapter = NULL;
    if ((adapterName = HdfSbufReadString(data)) == NULL) {
        HDF_LOGE("%{public}s", "adapterNameCase Is NULL");
        return HDF_FAILURE;
    }
    if (AudioAdapterListGetAdapter(adapterName, &adapter)) {
        HDF_LOGE("%{public}s", "AudioAdapterListGetAdapter fail");
        return HDF_FAILURE;
    }
    if (adapter->InitAllPorts(adapter)) {
        HDF_LOGE("%{public}s", "InitAllPorts fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t HdiServiceUnloadAdapter(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioAdapter *adapter = NULL;
    const char *adapterName = NULL;
    int ret;
    struct AudioManager *manager = g_serverManager;
    if (manager == NULL) {
        HDF_LOGE("%{public}s", "Point is NULL!");
        return HDF_FAILURE;
    }
    if ((adapterName = HdfSbufReadString(data)) == NULL) {
        HDF_LOGE("%{public}s", "adapterNameCase Is NULL");
        return HDF_FAILURE;
    }
    ret = AudioAdapterListDestory(adapterName, &adapter);
    if (ret == HDF_FAILURE) {
        HDF_LOGE("%{public}s", "Other dev Use the adapter");
        return HDF_SUCCESS;
    } else if (ret == HDF_ERR_INVALID_PARAM) {
        HDF_LOGE("%{public}s", "HdiServiceUnloadAdapter: param invalid!");
        return HDF_FAILURE;
    } else {
        HDF_LOGE("%{public}s", "HdiServiceUnloadAdapter: Unload the adapter!");
    }
    if (adapter == NULL) {
        return HDF_FAILURE;
    }
    manager->UnloadAdapter(manager, adapter);
    return HDF_SUCCESS;
}

static int32_t HdiServiceGetPortCapability(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    HDF_LOGE("%{public}s", "HdiServiceGetPortCapability in!");
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioPort port;
    struct AudioPortCapability capability;
    struct AudioAdapter *adapter = NULL;
    const char *adapterName = NULL;
    uint32_t tempDir;
    if ((adapterName = HdfSbufReadString(data)) == NULL) {
        HDF_LOGE("%{public}s", "adapterNameCase Is NULL");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempDir)) {
        return HDF_FAILURE;
    }
    port.dir = (enum AudioPortDirection)tempDir;
    if (!HdfSbufReadUint32(data, &port.portId)) {
        return HDF_FAILURE;
    }
    if ((port.portName = HdfSbufReadString(data)) == NULL) {
        return HDF_FAILURE;
    }
    HDF_LOGE("port.portName = %{public}s", port.portName);
    if (AudioAdapterListGetAdapter(adapterName, &adapter)) {
        HDF_LOGE("%{public}s", "AudioAdapterListGetAdapter fail");
        return HDF_FAILURE;
    }
    if (adapter == NULL) {
        HDF_LOGE("%{public}s", "HdiServiceCreatRender adapter is NULL!");
        return HDF_FAILURE;
    }
    int32_t ret = adapter->GetPortCapability(adapter, &port, &capability);
    if (ret < 0) {
        HDF_LOGE("%{public}s", "HdiServiceGetPortCapability ret failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t HdiServiceSetPassthroughMode(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    HDF_LOGE("%{public}s", "HdiServiceSetPassthroughMode in");
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioPort port;
    enum AudioPortPassthroughMode mode;
    struct AudioAdapter *adapter = NULL;
    const char *adapterName = NULL;
    if ((adapterName = HdfSbufReadString(data)) == NULL) {
        HDF_LOGE("%{public}s", "adapterNameCase Is NULL");
        return HDF_FAILURE;
    }
    uint32_t tempDir;
    if (!HdfSbufReadUint32(data, &tempDir)) {
        return HDF_FAILURE;
    }
    port.dir = (enum AudioPortDirection)tempDir;
    HDF_LOGE("port.dir = %{public}d", port.dir);
    if (!HdfSbufReadUint32(data, &port.portId)) {
        return HDF_FAILURE;
    }
    if ((port.portName = HdfSbufReadString(data)) == NULL) {
        HDF_LOGE("port.portName = %{public}s", port.portName);
        return HDF_FAILURE;
    }
    HDF_LOGE("port.portName = %{public}s", port.portName);
    uint32_t tempMode = 0;
    if (!HdfSbufReadUint32(data, &tempMode)) {
        return HDF_FAILURE;
    }
    mode = (enum AudioPortPassthroughMode)tempMode;
    HDF_LOGE("%{public}s mode = %{public}d", "SetPassthroughMode ready in", mode);
    if (AudioAdapterListGetAdapter(adapterName, &adapter)) {
        HDF_LOGE("%{public}s", "AudioAdapterListGetAdapter fail");
        return HDF_FAILURE;
    }
    if (adapter == NULL) {
        HDF_LOGE("%{public}s", "HdiServiceCreatRender adapter is NULL!");
        return HDF_FAILURE;
    }
    int ret = adapter->SetPassthroughMode(adapter, &port, mode);
    return ret;
}
static int32_t HdiServiceGetPassthroughMode(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioPort port;
    enum AudioPortPassthroughMode mode;
    struct AudioAdapter *adapter = NULL;
    const char *adapterName = NULL;
    if ((adapterName = HdfSbufReadString(data)) == NULL) {
        HDF_LOGE("%{public}s", "adapterNameCase Is NULL");
        return HDF_FAILURE;
    }
    uint32_t tempDir = port.dir;
    if (!HdfSbufReadUint32(data, &tempDir)) {
        return HDF_FAILURE;
    }
    port.dir = (enum AudioPortDirection)tempDir;
    if (!HdfSbufReadUint32(data, &port.portId)) {
        return HDF_FAILURE;
    }
    if ((port.portName = HdfSbufReadString(data)) == NULL) {
        HDF_LOGE("port.portName = %{public}s", port.portName);
        return HDF_FAILURE;
    }
    if (AudioAdapterListGetAdapter(adapterName, &adapter)) {
        HDF_LOGE("%{public}s", "AudioAdapterListGetAdapter fail");
        return HDF_FAILURE;
    }
    if (adapter == NULL) {
        HDF_LOGE("%{public}s", "adapter is NULL!");
        return HDF_FAILURE;
    }
    int ret = adapter->GetPassthroughMode(adapter, &port, &mode);
    if (ret < 0) {
        HDF_LOGE("%{public}s", "GetPassthroughMode ret failed");
        return HDF_FAILURE;
    }
    uint32_t tempMode = (uint32_t)mode;
    if (!HdfSbufWriteUint32(reply, tempMode)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/*****************************end*************************/
struct HdiServiceDispatchCmdHandleList g_hdiServiceDispatchCmdHandleList[] = {
    {AUDIO_HDI_MGR_GET_FUNCS, HdiServiceGetFuncs},
    {AUDIO_HDI_MGR_GET_ALL_ADAPTER, HdiServiceGetAllAdapter},
    {AUDIO_HDI_MGR_LOAD_ADAPTER, HdiServiceLoadAdapter},
    {AUDIO_HDI_MGR_UNLOAD_ADAPTER, HdiServiceUnloadAdapter},
    {AUDIO_HDI_ADT_INIT_PORTS, HdiServiceInitAllPorts},
    {AUDIO_HDI_ADT_GET_PORT_CAPABILITY, HdiServiceGetPortCapability},
    {AUDIO_HDI_ADT_SET_PASS_MODE, HdiServiceSetPassthroughMode},
    {AUDIO_HDI_ADT_GET_PASS_MODE, HdiServiceGetPassthroughMode},
    {AUDIO_HDI_RENDER_CREATE_RENDER, HdiServiceCreatRender},
    {AUDIO_HDI_RENDER_DESTROY, HdiServiceRenderDestory},
    {AUDIO_HDI_RENDER_START, HdiServiceRenderStart},
    {AUDIO_HDI_RENDER_STOP, HdiServiceRenderStop},
    {AUDIO_HDI_RENDER_PAUSE, HdiServiceRenderPause},
    {AUDIO_HDI_RENDER_RESUME, HdiServiceRenderResume},
    {AUDIO_HDI_RENDER_FLUSH, HdiServiceRenderFlush},
    {AUDIO_HDI_RENDER_GET_FRAME_SIZE, HdiServiceRenderGetFrameSize},
    {AUDIO_HDI_RENDER_GET_FRAME_COUNT, HdiServiceRenderGetFrameCount},
    {AUDIO_HDI_RENDER_SET_SAMPLE_ATTR, HdiServiceRenderSetSampleAttr},
    {AUDIO_HDI_RENDER_GET_SAMPLE_ATTR, HdiServiceRenderGetSampleAttr},
    {AUDIO_HDI_RENDER_GET_CUR_CHANNEL_ID, HdiServiceRenderGetCurChannelId},
    {AUDIO_HDI_RENDER_CHECK_SCENE_CAPABILITY, HdiServiceRenderCheckSceneCapability},
    {AUDIO_HDI_RENDER_SELECT_SCENE, HdiServiceRenderSelectScene},
    {AUDIO_HDI_RENDER_GET_MUTE, HdiServiceRenderGetMute},
    {AUDIO_HDI_RENDER_SET_MUTE, HdiServiceRenderSetMute},
    {AUDIO_HDI_RENDER_SET_VOLUME, HdiServiceRenderSetVolume},
    {AUDIO_HDI_RENDER_GET_VOLUME, HdiServiceRenderGetVolume},
    {AUDIO_HDI_RENDER_GET_GAIN_THRESHOLD, HdiServiceRenderGetGainThreshold},
    {AUDIO_HDI_RENDER_GET_GAIN, HdiServiceRenderGetGain},
    {AUDIO_HDI_RENDER_SET_GAIN, HdiServiceRenderSetGain},
    {AUDIO_HDI_RENDER_GET_LATENCY, HdiServiceRenderGetLatency},
    {AUDIO_HDI_RENDER_RENDER_FRAME, HdiServiceRenderRenderFrame},
    {AUDIO_HDI_RENDER_GET_RENDER_POSITION, HdiServiceRenderGetRenderPosition},
    {AUDIO_HDI_RENDER_GET_SPEED, HdiServiceRenderGetSpeed},
    {AUDIO_HDI_RENDER_SET_SPEED, HdiServiceRenderSetSpeed},
    {AUDIO_HDI_RENDER_SET_CHANNEL_MODE, HdiServiceRenderSetChannelMode},
    {AUDIO_HDI_RENDER_GET_CHANNEL_MODE, HdiServiceRenderGetChannelMode},
};

static struct HdiServiceDispatchCmdHandleList g_hdiServiceDispatchCmdHandleCapList[] = {
    {AUDIO_HDI_CAPTURE_CREATE_CAPTURE, HdiServiceCreatCapture},
    {AUDIO_HDI_CAPTURE_DESTROY, HdiServiceCaptureDestory},
    {AUDIO_HDI_CAPTURE_START, HdiServiceCaptureStart},
    {AUDIO_HDI_CAPTURE_STOP, HdiServiceCaptureStop},
    {AUDIO_HDI_CAPTURE_PAUSE, HdiServiceCapturePause},
    {AUDIO_HDI_CAPTURE_RESUME, HdiServiceCaptureResume},
    {AUDIO_HDI_CAPTURE_FLUSH, HdiServiceCaptureFlush},
    {AUDIO_HDI_CAPTURE_GET_FRAME_SIZE, HdiServiceCaptureGetFrameSize},
    {AUDIO_HDI_CAPTURE_GET_FRAME_COUNT, HdiServiceCaptureGetFrameCount},
    {AUDIO_HDI_CAPTURE_SET_SAMPLE_ATTR, HdiServiceCaptureSetSampleAttr},
    {AUDIO_HDI_CAPTURE_GET_SAMPLE_ATTR, HdiServiceCaptureGetSampleAttr},
    {AUDIO_HDI_CAPTURE_GET_CUR_CHANNEL_ID, HdiServiceCaptureGetCurChannelId},
    {AUDIO_HDI_CAPTURE_CHECK_SCENE_CAPABILITY, HdiServiceCaptureCheckSceneCapability},
    {AUDIO_HDI_CAPTURE_SELECT_SCENE, HdiServiceCaptureSelectScene},
    {AUDIO_HDI_CAPTURE_GET_MUTE, HdiServiceCaptureGetMute},
    {AUDIO_HDI_CAPTURE_SET_MUTE, HdiServiceCaptureSetMute},
    {AUDIO_HDI_CAPTURE_SET_VOLUME, HdiServiceCaptureSetVolume},
    {AUDIO_HDI_CAPTURE_GET_VOLUME, HdiServiceCaptureGetVolume},
    {AUDIO_HDI_CAPTURE_GET_GAIN_THRESHOLD, HdiServiceCaptureGetGainThreshold},
    {AUDIO_HDI_CAPTURE_GET_GAIN, HdiServiceCaptureGetGain},
    {AUDIO_HDI_CAPTURE_SET_GAIN, HdiServiceCaptureSetGain},
    {AUDIO_HDI_CAPTURE_CAPTURE_FRAME, HdiServiceCaptureCaptureFrame},
    {AUDIO_HDI_CAPTURE_GET_CAPTURE_POSITION, HdiServiceCaptureGetCapturePosition},
};

static int32_t HdiServiceDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
                                  struct HdfSBuf *reply)
{
    unsigned int i;
    if (client == NULL || data == NULL || reply == NULL) {
        HDF_LOGE("%{public}s", "ControlDispatch: input para is NULL.");
        return HDF_FAILURE;
    }
    HDF_LOGE("ControlDispatch: valid cmdId = %{public}d", cmdId);

    if (cmdId > AUDIO_HDI_CAPTURE_GET_CAPTURE_POSITION || cmdId < 0) {
        HDF_LOGE("ControlDispatch: invalid cmdId = %{public}d", cmdId);
        return HDF_FAILURE;
    } else if (cmdId <= AUDIO_HDI_RENDER_GET_CHANNEL_MODE) {
        for (i = 0; i < sizeof(g_hdiServiceDispatchCmdHandleList) /
            sizeof(g_hdiServiceDispatchCmdHandleList[0]); ++i) {
            if ((cmdId == (int)(g_hdiServiceDispatchCmdHandleList[i].cmd)) &&
                (g_hdiServiceDispatchCmdHandleList[i].func != NULL)) {
                return g_hdiServiceDispatchCmdHandleList[i].func(client, data, reply);
            }
        }
    } else {
        for (i = 0; i < sizeof(g_hdiServiceDispatchCmdHandleCapList) /
            sizeof(g_hdiServiceDispatchCmdHandleCapList[0]); ++i) {
            if ((cmdId == (int)(g_hdiServiceDispatchCmdHandleCapList[i].cmd)) &&
                (g_hdiServiceDispatchCmdHandleCapList[i].func != NULL)) {
                return g_hdiServiceDispatchCmdHandleCapList[i].func(client, data, reply);
            }
        }
    }
    return HDF_FAILURE;
}

void AudioHdiServerRelease(struct HdfDeviceObject *deviceObject)
{
    LOG_FUN_INFO();
    if (deviceObject == NULL) {
        HDF_LOGE("deviceObject is null!");
        return;
    }
    deviceObject->service = NULL;
    return;
}

int AudioHdiServerBind(struct HdfDeviceObject *deviceObject)
{
    LOG_FUN_INFO();
    if (deviceObject == NULL) {
        HDF_LOGE("deviceObject is null!");
        return HDF_FAILURE;
    }
    static struct IDeviceIoService hdiService = {
        .Dispatch = HdiServiceDispatch,
        .Open = NULL,
        .Release = NULL,
    };
    if (HdiServiceGetFuncs()) {
        return HDF_FAILURE;
    }
    deviceObject->service = &hdiService;
    return HDF_SUCCESS;
}

int AudioHdiServerInit(struct HdfDeviceObject *deviceObject)
{
    LOG_FUN_INFO();
    if (deviceObject == NULL) {
        HDF_LOGE("deviceObject is null!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

struct HdfDriverEntry g_hdiServerEntry = {
    .moduleVersion = 1,
    .moduleName = "audio_hdi_adapter_server",
    .Bind = AudioHdiServerBind,
    .Init = AudioHdiServerInit,
    .Release = AudioHdiServerRelease,
};

HDF_INIT(g_hdiServerEntry);

