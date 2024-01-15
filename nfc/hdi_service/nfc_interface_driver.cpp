/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "v1_1/nfc_interface_stub.h"

#define HDF_LOG_TAG hdf_nfc_dal

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD000306

using namespace OHOS::HDI::Nfc::V1_1;
using namespace OHOS::HDI::Nfc;

struct HdfNfcInterfaceHost {
    struct IDeviceIoService ioservice;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t NfcInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfNfcInterfaceHost =
        CONTAINER_OF(client->device->service, struct HdfNfcInterfaceHost, ioservice);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("NfcInterfaceDriverDispatc, invalid data sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("NfcInterfaceDriverDispatch, invalid reply sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfNfcInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfNfcInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfNfcInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfNfcInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfNfcInterfaceDriverBind enter");

    auto *hdfNfcInterfaceHost = new (std::nothrow) HdfNfcInterfaceHost;
    if (hdfNfcInterfaceHost == nullptr) {
        HDF_LOGE("HdfNfcInterfaceDriverBind, failed to create HdfNfcInterfaceDriverBind Object!");
        return HDF_FAILURE;
    }

    hdfNfcInterfaceHost->ioservice.Dispatch = NfcInterfaceDriverDispatch;
    hdfNfcInterfaceHost->ioservice.Open = nullptr;
    hdfNfcInterfaceHost->ioservice.Release = nullptr;

    auto serviceImpl = OHOS::HDI::Nfc::V1_1::INfcInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("HdfNfcInterfaceDriverBind, failed to get of implement service");
        delete hdfNfcInterfaceHost;
        return HDF_FAILURE;
    }

    hdfNfcInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Nfc::V1_1::INfcInterface::GetDescriptor());
    if (hdfNfcInterfaceHost->stub == nullptr) {
        HDF_LOGE("HdfNfcInterfaceDriverBind, failed to get stub object");
        delete hdfNfcInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfNfcInterfaceHost->ioservice;
    HDF_LOGI("HdfNfcInterfaceDriverBind Success");
    return HDF_SUCCESS;
}

static void HdfNfcInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfNfcInterfaceDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfNfcInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfNfcInterfaceHost =
        CONTAINER_OF(deviceObject->service, struct HdfNfcInterfaceHost, ioservice);
    delete hdfNfcInterfaceHost;
    HDF_LOGI("HdfNfcInterfaceDriverRelease Success");
}

static struct HdfDriverEntry g_nfcinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "nfc_service",
    .Bind = HdfNfcInterfaceDriverBind,
    .Init = HdfNfcInterfaceDriverInit,
    .Release = HdfNfcInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_nfcinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
