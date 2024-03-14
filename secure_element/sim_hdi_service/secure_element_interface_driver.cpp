/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "secure_element_interface_service.h"

#define HDF_LOG_TAG secure_element_interface_driver

using namespace OHOS::HDI::SecureElement::SimSecureElement::V1_0;

struct HdfSecureElementInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t SecureElementInterfaceDriverDispatch(struct HdfDeviceIoClient* client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto* hdfSecureElementInterfaceHost =
        CONTAINER_OF(client->device->service, struct HdfSecureElementInterfaceHost, ioService);

    OHOS::MessageParcel* dataParcel = nullptr;
    OHOS::MessageParcel* replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfSecureElementInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfSecureElementInterfaceDriverInit(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfSecureElementInterfaceDriverBind(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto* hdfSecureElementInterfaceHost = new (std::nothrow) HdfSecureElementInterfaceHost;
    if (hdfSecureElementInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create hdfSecureElementInterfaceHost object!", __func__);
        return HDF_FAILURE;
    }

    hdfSecureElementInterfaceHost->ioService.Dispatch = SecureElementInterfaceDriverDispatch;
    hdfSecureElementInterfaceHost->ioService.Open = nullptr;
    hdfSecureElementInterfaceHost->ioService.Release = nullptr;

    sptr<OHOS::HDI::SecureElement::SimSecureElement::V1_0::ISecureElementInterface> serviceImpl =
        new (std::nothrow) SecureElementInterfaceService();
    HDF_LOGE("%{public}s :serviceImpl fzj", __func__);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfSecureElementInterfaceHost;
        return HDF_FAILURE;
    }

    hdfSecureElementInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::SecureElement::SimSecureElement::V1_0::ISecureElementInterface::GetDescriptor());
    if (hdfSecureElementInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfSecureElementInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfSecureElementInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfSecureElementInterfaceDriverRelease(struct HdfDeviceObject* deviceObject)
{
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfSecureElementInterfaceDriverRelease not initted");
        return;
    }

    auto* hdfSecureElementInterfaceHost =
        CONTAINER_OF(deviceObject->service, struct HdfSecureElementInterfaceHost, ioService);
    if (hdfSecureElementInterfaceHost != nullptr) {
        delete hdfSecureElementInterfaceHost;
    }
}

static struct HdfDriverEntry g_secureelementInterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "sim_secure_element_service",
    .Bind = HdfSecureElementInterfaceDriverBind,
    .Init = HdfSecureElementInterfaceDriverInit,
    .Release = HdfSecureElementInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_secureelementInterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
