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
#include "audio_proxy_manager.h"
#include <servmgr_hdi.h>
#include "audio_hal_log.h"
#include "audio_proxy_common.h"
#include "audio_proxy_internal.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_PROXY

#define HDI_SERVER_PRIMARY_NAME     "audio_hdi_service"
#define HDI_SERVER_USB_NAME         "audio_hdi_usb_service"
#define HDI_SERVER_A2DP_NAME        "audio_hdi_a2dp_service"

#define CONFIG_FRAME_SIZE      (1024 * 2 * 1)
#define FRAME_SIZE              1024
#define CONFIG_FRAME_COUNT     ((8000 * 2 * 1 + (CONFIG_FRAME_SIZE - 1)) / CONFIG_FRAME_SIZE)
#define AUDIO_MAGIC            (0xAAAAAAAAAAAAAAAA)

static bool audioProxyAdapterAddrMgrFlag = false;
static struct AudioAdapterDescriptor *g_localAudioProxyAdapterAddrOut = NULL; // add for Fuzz
int g_localAudioProxyAdapterNum = 0; // add for Fuzz
static struct AudioProxyManager g_localAudioProxyMgr = {0}; // serverManager

int32_t AudioProxySendGetAllAdapter(struct HdfRemoteService *remoteHandle)
{
    if (remoteHandle == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    int32_t ret;
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(remoteHandle, data)) {
        LOG_FUN_ERR("write interface token failed");
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AudioProxyDispatchCall(remoteHandle, AUDIO_HDI_MGR_GET_ALL_ADAPTER, data, reply);
    if (ret != AUDIO_HAL_SUCCESS) {
        AudioProxyBufReplyRecycle(data, reply);
        LOG_FUN_ERR("AudioProxyDispatchCallsend service fail!");
        return ret;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioProxyManagerGetAllAdapters(struct AudioManager *manager,
                                        struct AudioAdapterDescriptor **descs, int *size)
{
    LOG_FUN_INFO();
    int32_t ret;
    if (manager == NULL || descs == NULL || size == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioProxyManager *proxyManager = CONTAINER_OF(manager, struct AudioProxyManager, impl);
    if ((&g_localAudioProxyMgr) != proxyManager || proxyManager == NULL || (proxyManager->remote == NULL &&
        proxyManager->usbRemote == NULL && proxyManager->a2dpRemote == NULL) ||
        proxyManager->audioMagic != AUDIO_MAGIC) {
        LOG_FUN_ERR("Param is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    ret = AudioAdaptersForUser(descs, size);
    if (ret < 0) {
        LOG_FUN_ERR("AudioAdaptersForUser FAIL!");
        return AUDIO_HAL_ERR_NOTREADY; // Failed to read sound card configuration file
    }
    /* add for Fuzz. */
    if (*descs && size && (*size) > 0) {
        g_localAudioProxyAdapterAddrOut  = *descs;
        g_localAudioProxyAdapterNum = *size;
    } else {
        LOG_FUN_ERR("Get AudioAdapterDescriptor Failed");
        return AUDIO_HAL_ERR_INVALID_OBJECT;
    }

    int32_t retPri = AudioProxySendGetAllAdapter(proxyManager->remote);
    int32_t retUsb = AudioProxySendGetAllAdapter(proxyManager->usbRemote);
    int32_t retA2dp = AudioProxySendGetAllAdapter(proxyManager->a2dpRemote);
    if (retPri != AUDIO_HAL_SUCCESS && retUsb != AUDIO_HAL_SUCCESS && retA2dp != AUDIO_HAL_SUCCESS) {
        LOG_FUN_ERR("Failed to send service call!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t LoadAdapterPrepareParameters(struct HdfRemoteService * remoteObj, const struct AudioAdapterDescriptor *desc,
    struct HdfSBuf **data, struct HdfSBuf **reply)
{
    if (remoteObj == NULL || desc == NULL || desc->adapterName == NULL || desc->ports == NULL || data == NULL ||
        reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    bool descFlag = false;
    if (g_localAudioProxyAdapterNum <= 0 || g_localAudioProxyAdapterNum > SUPPORT_ADAPTER_NUM_MAX) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (g_localAudioProxyAdapterAddrOut != NULL) { // add for Fuzz
        for (int index = 0; index < g_localAudioProxyAdapterNum; index++) {
            if (&g_localAudioProxyAdapterAddrOut[index] == desc) {
                descFlag = true;
                break;
            }
        }
        if (!descFlag) {
            LOG_FUN_ERR("The proxy desc address passed in is invalid");
            return AUDIO_HAL_ERR_INVALID_OBJECT;
        }
    }
    if (AudioAdapterExist(desc->adapterName)) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (AudioProxyPreprocessSBuf(data, reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(remoteObj, *data)) {
        LOG_FUN_ERR("write interface token failed");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    // adapterName
    if (!HdfSbufWriteString(*data, desc->adapterName)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    // dir
    uint32_t tempDir = (uint32_t)desc->ports->dir;
    if (!HdfSbufWriteUint32(*data, tempDir)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t GetAudioProxyAdapterFunc(struct AudioHwAdapter *hwAdapter)
{
    if (hwAdapter == NULL) {
        return HDF_FAILURE;
    }
    hwAdapter->common.InitAllPorts = AudioProxyAdapterInitAllPorts;
    hwAdapter->common.CreateRender = AudioProxyAdapterCreateRender;
    hwAdapter->common.DestroyRender = AudioProxyAdapterDestroyRender;
    hwAdapter->common.CreateCapture = AudioProxyAdapterCreateCapture;
    hwAdapter->common.DestroyCapture = AudioProxyAdapterDestroyCapture;
    hwAdapter->common.GetPortCapability = AudioProxyAdapterGetPortCapability;
    hwAdapter->common.SetPassthroughMode = AudioProxyAdapterSetPassthroughMode;
    hwAdapter->common.GetPassthroughMode = AudioProxyAdapterGetPassthroughMode;
    return HDF_SUCCESS;
}
int32_t AudioProxyManagerLoadAdapterDispatch(struct AudioHwAdapter *hwAdapter, struct AudioProxyManager *proxyManager,
    const struct AudioAdapterDescriptor *desc, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (hwAdapter == NULL || proxyManager == NULL || desc == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = AudioAddAdapterAddrToList((AudioHandle)((&hwAdapter->common)), desc);
    if (ret < 0) { // add for Fuzz test
        LOG_FUN_ERR("The proxy AudioProxyAdapterAddrGet check Failed");
        return ret;
    }
    ret = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_MGR_LOAD_ADAPTER, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("Failed to send service call!!");
        if (AudioDelAdapterAddrFromList((AudioHandle)(&hwAdapter->common))) {
            LOG_FUN_ERR("The proxy Adapter or proxyRender not in MgrList");
        }
        return ret;
    }
    return AUDIO_HAL_SUCCESS;
}
int32_t AudioProxyManagerLoadAdapter(struct AudioManager *manager, const struct AudioAdapterDescriptor *desc,
    struct AudioAdapter **adapter)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (manager == NULL || desc == NULL || adapter == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioProxyManager *proxyManager = CONTAINER_OF(manager, struct AudioProxyManager, impl);
    if ((&g_localAudioProxyMgr) != proxyManager || proxyManager == NULL || proxyManager->remote == NULL ||
        proxyManager->audioMagic != AUDIO_MAGIC) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)calloc(1, sizeof(struct AudioHwAdapter));
    if (hwAdapter == NULL) {
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    if (AudioProxyAdapterGetRemoteHandle(proxyManager, hwAdapter, desc->adapterName) < 0) {
        AudioMemFree((void **)&hwAdapter);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = LoadAdapterPrepareParameters(hwAdapter->proxyRemoteHandle, desc, &data, &reply);
    if (ret < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        AudioMemFree((void **)&hwAdapter);
        return ret;
    }
    if (GetAudioProxyAdapterFunc(hwAdapter) < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        AudioMemFree((void **)&hwAdapter);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    hwAdapter->adapterDescriptor = *desc;
    ret = AudioProxyManagerLoadAdapterDispatch(hwAdapter, proxyManager, desc, data, reply);
    if (ret < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        AudioMemFree((void **)&hwAdapter);
        return ret;
    }
    *adapter = &hwAdapter->common;
    AudioProxyBufReplyRecycle(data, reply);
    return AUDIO_HAL_SUCCESS;
}

void AudioProxyManagerUnloadAdapter(struct AudioManager *manager, struct AudioAdapter *adapter)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    const char *adapterName = NULL;
    int32_t i = 0;
    int32_t portNum;
    if (manager == NULL || adapter == NULL) {
        return;
    }
    int32_t ret = AudioCheckAdapterAddr((AudioHandle)adapter);
    if (ret < 0) {
        LOG_FUN_ERR("The proxy Adapter address passed in is invalid");
        return;
    }

    struct AudioProxyManager *proxyManager = CONTAINER_OF(manager, struct AudioProxyManager, impl);
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if ((&g_localAudioProxyMgr) != proxyManager || proxyManager == NULL ||
        proxyManager->audioMagic != AUDIO_MAGIC || proxyManager->remote == NULL) {
        return;
    }
    if (hwAdapter->portCapabilitys != NULL) {
        portNum = hwAdapter->adapterDescriptor.portNum;
        while (i < portNum) {
            if (&hwAdapter->portCapabilitys[i] != NULL) {
                AudioMemFree((void **)&hwAdapter->portCapabilitys[i].capability.subPorts);
            }
            i++;
        }
        AudioMemFree((void **)&hwAdapter->portCapabilitys);
    }
    if (AudioProxyPreprocessSBuf(&data, &reply) == AUDIO_HAL_SUCCESS) {
        if (!HdfRemoteServiceWriteInterfaceToken(hwAdapter->proxyRemoteHandle, data)) {
            LOG_FUN_ERR("write interface token failed");
            AudioProxyBufReplyRecycle(data, reply);
            return;
        }
        adapterName = hwAdapter->adapterDescriptor.adapterName;
        if (HdfSbufWriteString(data, adapterName)) {
            ret = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_MGR_UNLOAD_ADAPTER, data, reply);
            if (ret < 0) {
                LOG_FUN_ERR("Send Server fail!");
            }
        }
        AudioProxyBufReplyRecycle(data, reply);
    }
    if (AudioDelAdapterAddrFromList((AudioHandle)adapter) < 0) {
        LOG_FUN_ERR("The proxy Adapter or proxyRender not in MgrList");
    }
    AudioMemFree((void **)&adapter);
    return;
}

bool ReleaseProxyAudioManagerObject(struct AudioManager *object)
{
    if (object == NULL) {
        LOG_FUN_ERR("Input pointer is null!");
        return false;
    }
    struct AudioProxyManager *proxyManager = CONTAINER_OF(object, struct AudioProxyManager, impl);
    if ((&g_localAudioProxyMgr) != proxyManager ||
        proxyManager == NULL || proxyManager->audioMagic != AUDIO_MAGIC) {
        return false;
    }
    ReleaseAudioManagerObjectComm(&(proxyManager->impl));
    audioProxyAdapterAddrMgrFlag = false;
    return true;
}

static void ProxyAudioMgrConstruct(struct AudioProxyManager *proxyMgr)
{
    if (proxyMgr == NULL) {
        LOG_FUN_ERR("Input pointer is null!");
        return;
    }
    proxyMgr->impl.GetAllAdapters = AudioProxyManagerGetAllAdapters;
    proxyMgr->impl.LoadAdapter = AudioProxyManagerLoadAdapter;
    proxyMgr->impl.UnloadAdapter = AudioProxyManagerUnloadAdapter;
    proxyMgr->impl.ReleaseAudioManagerObject = ReleaseProxyAudioManagerObject;
    proxyMgr->audioMagic = AUDIO_MAGIC;
}

struct AudioManager *GetAudioProxyManagerFuncs(void)
{
    LOG_FUN_INFO();
    if (audioProxyAdapterAddrMgrFlag) {
        return (&(g_localAudioProxyMgr.impl));
    }
    struct HDIServiceManager *serviceMgr = HDIServiceManagerGet();
    if (serviceMgr == NULL) {
        LOG_FUN_ERR("HDIServiceManagerGet failed!");
        return NULL;
    }
    (void)memset_s(&g_localAudioProxyMgr, sizeof(struct AudioProxyManager), 0, sizeof(struct AudioProxyManager));
    g_localAudioProxyMgr.remote = serviceMgr->GetService(serviceMgr, HDI_SERVER_PRIMARY_NAME);
    g_localAudioProxyMgr.usbRemote = serviceMgr->GetService(serviceMgr, HDI_SERVER_USB_NAME);
    g_localAudioProxyMgr.a2dpRemote  = serviceMgr->GetService(serviceMgr, HDI_SERVER_A2DP_NAME);
    HDIServiceManagerRelease(serviceMgr);
    if (g_localAudioProxyMgr.remote == NULL &&
        g_localAudioProxyMgr.usbRemote == NULL &&
        g_localAudioProxyMgr.a2dpRemote == NULL) {
        LOG_FUN_ERR("Remote GetService failed!");
        return NULL;
    }
    bool remoteRet = HdfRemoteServiceSetInterfaceDesc(g_localAudioProxyMgr.remote, "ohos.hdi.audio_service");
    bool usbRemoteRet = HdfRemoteServiceSetInterfaceDesc(g_localAudioProxyMgr.usbRemote, "ohos.hdi.audio_service");
    bool a2dpRemoteRet = HdfRemoteServiceSetInterfaceDesc(g_localAudioProxyMgr.a2dpRemote, "ohos.hdi.audio_service");
    if (!remoteRet && !usbRemoteRet && !a2dpRemoteRet) {
        LOG_FUN_ERR("failed to init interface desc!");
        HdfRemoteServiceRecycle(g_localAudioProxyMgr.remote);
        HdfRemoteServiceRecycle(g_localAudioProxyMgr.usbRemote);
        HdfRemoteServiceRecycle(g_localAudioProxyMgr.a2dpRemote);
        return NULL;
    }

    ProxyAudioMgrConstruct(&g_localAudioProxyMgr);

    AudioAdapterAddrMgrInit(); // memset for Fuzz
    audioProxyAdapterAddrMgrFlag = true;
    return (&(g_localAudioProxyMgr.impl));
}
