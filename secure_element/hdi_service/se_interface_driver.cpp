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

#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_log.h>
#include <hdf_sbuf_ipc.h>
#include "v1_0/secure_element_interface_stub.h"

#ifdef SE_DRIVER_USE_CA
#include "secure_element_ca_proxy.h"
#endif

#define HDF_LOG_TAG hdf_se

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD000305

using OHOS::HDI::SecureElement::V1_0::ISecureElementInterface;

struct HdfSeInterfaceHost {
    struct IDeviceIoService ioservice;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t SeInterfaceDriverDispatch(struct HdfDeviceIoClient* client, int cmdId, struct HdfSBuf* data,
    struct HdfSBuf* reply)
{
    auto* hdfSeInterfaceHost =
        CONTAINER_OF(client->device->service, struct HdfSeInterfaceHost, ioservice);

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

    return hdfSeInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfSeInterfaceDriverInit(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGE("%{public}s: Enter", __func__);
#ifdef SE_DRIVER_USE_CA
    int ret = OHOS::HDI::SecureElement::SecureElementCaProxy::GetInstance().VendorSecureElementCaOnStart();
    if (ret != SECURE_ELEMENT_CA_RET_OK) {
        HDF_LOGE("%{public}s: Failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
#endif
    return HDF_SUCCESS;
}

static int HdfSeInterfaceDriverBind(struct HdfDeviceObject* deviceObject)
{
    auto* hdfSeInterfaceHost = new (std::nothrow) HdfSeInterfaceHost;
    if (hdfSeInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfSeInterfaceDriverBind Object!", __func__);
        return HDF_FAILURE;
    }

    hdfSeInterfaceHost->ioservice.Dispatch = SeInterfaceDriverDispatch;
    hdfSeInterfaceHost->ioservice.Open = nullptr;
    hdfSeInterfaceHost->ioservice.Release = nullptr;

    auto serviceImpl = ISecureElementInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfSeInterfaceHost;
        return HDF_FAILURE;
    }

    hdfSeInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        ISecureElementInterface::GetDescriptor());
    if (hdfSeInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfSeInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfSeInterfaceHost->ioservice;
    return HDF_SUCCESS;
}

static void HdfSeInterfaceDriverRelease(struct HdfDeviceObject* deviceObject)
{
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfSeInterfaceDriverRelease not initted");
        return;
    }

    auto* hdfSeInterfaceHost =
        CONTAINER_OF(deviceObject->service, struct HdfSeInterfaceHost, ioservice);
    delete hdfSeInterfaceHost;
}

static struct HdfDriverEntry g_seInterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "secure_element_service",
    .Bind = HdfSeInterfaceDriverBind,
    .Init = HdfSeInterfaceDriverInit,
    .Release = HdfSeInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_seInterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
