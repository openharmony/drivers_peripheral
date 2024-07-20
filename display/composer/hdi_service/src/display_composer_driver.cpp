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
#include <pthread.h>
#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_log.h>
#include <hdf_sbuf_ipc.h>
#include "v1_2/display_composer_stub.h"
#ifdef DISPLAY_HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#endif

#undef LOG_TAG
#define LOG_TAG "COMPOSER_DRV"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002515
#define HICOLLIE_TIMEOUT 5

struct HdfDisplayComposerHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static pthread_rwlock_t g_rwLock = PTHREAD_RWLOCK_INITIALIZER;
static bool g_stop = true;

static int32_t DisplayComposerDriverDispatch(
    struct HdfDeviceIoClient* client, int cmdId, struct HdfSBuf* data, struct HdfSBuf* reply)
{
    if ((client == nullptr) || (client->device == nullptr)) {
        HDF_LOGE("%{public}s: param is nullptr", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    
    OHOS::MessageParcel* dataParcel = nullptr;
    OHOS::MessageParcel* replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    pthread_rwlock_rdlock(&g_rwLock);
    auto* hdfDisplayComposerHost = CONTAINER_OF(client->device->service, struct HdfDisplayComposerHost, ioService);
    if (hdfDisplayComposerHost == nullptr || g_stop) {
        pthread_rwlock_unlock(&g_rwLock);
        HDF_LOGE("%{public}s:hdfDisplayComposerHost nullptr, stop: %{public}d", __func__, g_stop);
        return HDF_FAILURE;
    }
#ifdef DISPLAY_HICOLLIE_ENABLE
    int32_t id = HiviewDFX::XCollie::GetInstance().SetTimer("HDI::Display::Composer::SendRequest",
        HICOLLIE_TIMEOUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY);
#endif
    int32_t ret = hdfDisplayComposerHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
#ifdef DISPLAY_HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(id);
#endif
    pthread_rwlock_unlock(&g_rwLock);
    return ret;
}

static int HdfDisplayComposerDriverInit(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGI("%{public}s: enter", __func__);
    return HDF_SUCCESS;
}

static int HdfDisplayComposerDriverBind(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGI("%{public}s: enter", __func__);
    static auto* hdfDisplayComposerHost = new (std::nothrow) HdfDisplayComposerHost;
    if (hdfDisplayComposerHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfDisplayComposerHost object", __func__);
        return HDF_FAILURE;
    }

    hdfDisplayComposerHost->ioService.Dispatch = DisplayComposerDriverDispatch;
    hdfDisplayComposerHost->ioService.Open = NULL;
    hdfDisplayComposerHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::Display::Composer::V1_2::IDisplayComposer::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get the implement of service", __func__);
        delete hdfDisplayComposerHost;
        return HDF_FAILURE;
    }

    hdfDisplayComposerHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Display::Composer::V1_2::IDisplayComposer::GetDescriptor());
    if (hdfDisplayComposerHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfDisplayComposerHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfDisplayComposerHost->ioService;
    g_stop = false;
    return HDF_SUCCESS;
}

static void HdfDisplayComposerDriverRelease(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGI("%{public}s: enter", __func__);
    pthread_rwlock_wrlock(&g_rwLock);
    g_stop = true;
    pthread_rwlock_unlock(&g_rwLock);
}

static struct HdfDriverEntry g_displaycomposerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "display_composer",
    .Bind = HdfDisplayComposerDriverBind,
    .Init = HdfDisplayComposerDriverInit,
    .Release = HdfDisplayComposerDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif
HDF_INIT(g_displaycomposerDriverEntry);
#ifdef __cplusplus
}
#endif
