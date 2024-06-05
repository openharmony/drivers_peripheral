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

#include "v1_0/usb_ddk_service.h"

#include <hdf_base.h>
#include <iproxy_broker.h>

#include "ddk_pnp_listener_mgr.h"
#include "usb_ddk_hash.h"
#include "usb_ddk_interface.h"
#include "usb_ddk_permission.h"
#include "usb_raw_api.h"
#include "usbd_wrapper.h"
#define HDF_LOG_TAG usb_ddk_service

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Ddk {
namespace V1_0 {
// 32 means size of uint32_t
#define GET_BUS_NUM(devHandle)          ((uint8_t)((devHandle) >> 32))
#define GET_DEV_NUM(devHandle)          ((uint8_t)((devHandle)&0xFFFFFFFF))
#define USB_RECIP_MASK                  0x1F
#define GET_CTRL_REQ_RECIP(requestType) ((requestType)&USB_RECIP_MASK)
#define TRANS_DIRECTION_OFFSET          7
#define GET_CTRL_REQ_DIR(requestType)   ((requestType) >> TRANS_DIRECTION_OFFSET)
#define REQ_TYPE_OFFERT                 5
#define REQ_TYPE_MASK                   0x3
#define GET_CTRL_REQ_TYPE(requestType)  (((requestType) >> REQ_TYPE_OFFERT) & REQ_TYPE_MASK)

#define MAX_BUFF_SIZE         16384
#define MAX_CONTROL_BUFF_SIZE 1024

static const std::string PERMISSION_NAME = "ohos.permission.ACCESS_DDK_USB";

extern "C" IUsbDdk *UsbDdkImplGetInstance(void)
{
    return new (std::nothrow) UsbDdkService();
}

int32_t ReleaseUsbInterface(uint64_t interfaceHandle)
{
    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(interfaceHandle, handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }
    UsbDdkDelHashRecord(interfaceHandle);

    struct UsbInterface *interface = nullptr;
    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    ret = GetInterfaceByHandle(handleConvert, &interface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s get interface failed %{public}d", __func__, ret);
        return ret;
    }

    ret = UsbCloseInterface(handleConvert, false);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s close interface failed %{public}d", __func__, ret);
        return ret;
    }

    return UsbReleaseInterface(interface);
}

static int32_t UsbdPnpEventHandler(void *priv, uint32_t id, HdfSBuf *data)
{
    if (id == USB_PNP_NOTIFY_REMOVE_DEVICE) {
        uint32_t infoSize;
        struct UsbPnpNotifyMatchInfoTable *infoTable = NULL;
        auto flag = HdfSbufReadBuffer(data, (const void **)(&infoTable), &infoSize);
        if ((!flag) || (infoTable == NULL)) {
            HDF_LOGE("%{public}s: fail to read infoTable in event data, flag = %{public}d", __func__, flag);
            return HDF_ERR_INVALID_PARAM;
        }

        uint64_t interfaceHandle = 0;
        if (UsbDdkGetRecordByVal({0, infoTable->busNum, infoTable->devNum}, interfaceHandle)) {
            HDF_LOGD("%{public}s: need release interface", __func__);
            ReleaseUsbInterface(interfaceHandle);
        }
    }
    return HDF_SUCCESS;
}

static HdfDevEventlistener *g_pnpListener = nullptr;

int32_t UsbDdkService::Init()
{
    HDF_LOGI("usb ddk init");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }
    if (g_pnpListener == nullptr) {
        g_pnpListener = new HdfDevEventlistener();
        if (g_pnpListener == nullptr) {
            HDF_LOGE("%{public}s: create listener failed", __func__);
            return HDF_ERR_MALLOC_FAIL;
        }
        g_pnpListener->callBack = UsbdPnpEventHandler;
        if (DdkListenerMgrAdd(g_pnpListener) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: add listener failed", __func__);
            return HDF_FAILURE;
        }
    }

    return UsbInitHostSdk(nullptr);
}

int32_t UsbDdkService::Release()
{
    HDF_LOGI("usb ddk exit");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    return UsbExitHostSdk(nullptr);
}

int32_t UsbDdkService::GetDeviceDescriptor(uint64_t deviceId, UsbDeviceDescriptor &desc)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    UsbRawHandle *rawHandle = UsbRawOpenDevice(nullptr, GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId));
    if (rawHandle == nullptr) {
        HDF_LOGE("%{public}s open device failed", __func__);
        return HDF_FAILURE;
    }

    UsbRawDevice *rawDevice = UsbRawGetDevice(rawHandle);
    if (rawDevice == nullptr) {
        HDF_LOGE("%{public}s get device failed", __func__);
        (void)UsbRawCloseDevice(rawHandle);
        return HDF_FAILURE;
    }

    int32_t ret = UsbRawGetDeviceDescriptor(rawDevice, reinterpret_cast<::UsbDeviceDescriptor *>(&desc));
    if (ret != HDF_SUCCESS) {
        HDF_LOGW("%{public}s get desc failed %{public}d", __func__, ret);
    }
    (void)UsbRawCloseDevice(rawHandle);
    return ret;
}

int32_t UsbDdkService::GetConfigDescriptor(uint64_t deviceId, uint8_t configIndex, std::vector<uint8_t> &configDesc)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    UsbRawHandle *rawHandle = UsbRawOpenDevice(nullptr, GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId));
    if (rawHandle == nullptr) {
        HDF_LOGE("%{public}s open device failed", __func__);
        return HDF_FAILURE;
    }

    struct UsbConfigDescriptor tmpDesc {};
    int32_t ret = GetRawConfigDescriptor(
        rawHandle, configIndex, reinterpret_cast<uint8_t *>(&tmpDesc), sizeof(struct UsbConfigDescriptor));
    if (ret <= 0) {
        HDF_LOGW("%{public}s get config desc failed %{public}d", __func__, ret);
        (void)UsbRawCloseDevice(rawHandle);
        return ret;
    }

    std::vector<uint8_t> tmpBuffer(tmpDesc.wTotalLength);
    ret = GetRawConfigDescriptor(rawHandle, configIndex, tmpBuffer.data(), tmpDesc.wTotalLength);
    if (ret <= 0) {
        HDF_LOGW("%{public}s get config desc failed %{public}d", __func__, ret);
        (void)UsbRawCloseDevice(rawHandle);
        return ret;
    }

    if (static_cast<size_t>(ret) != tmpBuffer.size()) {
        HDF_LOGE("%{public}s config desc invalid length : %{public}d, bufferSize:%{public}zu", __func__, ret,
            tmpBuffer.size());
        return HDF_FAILURE;
    }

    configDesc = tmpBuffer;

    (void)UsbRawCloseDevice(rawHandle);
    return HDF_SUCCESS;
}

int32_t UsbDdkService::ClaimInterface(uint64_t deviceId, uint8_t interfaceIndex, uint64_t &interfaceHandle)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    struct UsbInterface *interface =
        UsbClaimInterface(nullptr, GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId), interfaceIndex);
    if (interface == nullptr) {
        HDF_LOGE("%{public}s claim failed", __func__);
        return HDF_FAILURE;
    }

    UsbInterfaceHandle *handle = UsbOpenInterface(interface);
    if (handle == nullptr) {
        HDF_LOGE("%{public}s open failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = UsbDdkHash({(uint64_t)handle, GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId)}, interfaceHandle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s hash failed %{public}d", __func__, ret);
    }
    return ret;
}

int32_t UsbDdkService::ReleaseInterface(uint64_t interfaceHandle)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    return ReleaseUsbInterface(interfaceHandle);
}

int32_t UsbDdkService::SelectInterfaceSetting(uint64_t interfaceHandle, uint8_t settingIndex)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(interfaceHandle, handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    struct UsbInterface *interface = nullptr;
    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    return UsbSelectInterfaceSetting(handleConvert, settingIndex, &interface);
}

int32_t UsbDdkService::GetCurrentInterfaceSetting(uint64_t interfaceHandle, uint8_t &settingIndex)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(interfaceHandle, handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    return UsbGetInterfaceSetting(handleConvert, &settingIndex);
}

int32_t UsbDdkService::SendControlReadRequest(
    uint64_t interfaceHandle, const UsbControlRequestSetup &setup, uint32_t timeout, std::vector<uint8_t> &data)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(interfaceHandle, handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    struct UsbRequest *request = UsbAllocRequest(handleConvert, 0, MAX_CONTROL_BUFF_SIZE);
    if (request == nullptr) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    (void)memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams));
    params.interfaceId = USB_CTRL_INTERFACE_ID;
    params.requestType = USB_REQUEST_PARAMS_CTRL_TYPE;
    params.timeout = timeout;
    params.ctrlReq.target = static_cast<UsbRequestTargetType>(GET_CTRL_REQ_RECIP(setup.requestType));
    params.ctrlReq.reqType = static_cast<UsbControlRequestType>(GET_CTRL_REQ_TYPE(setup.requestType));
    params.ctrlReq.directon = static_cast<UsbRequestDirection>(GET_CTRL_REQ_DIR(setup.requestType));
    params.ctrlReq.request = setup.requestCmd;
    params.ctrlReq.value = setup.value;
    params.ctrlReq.index = setup.index;
    params.ctrlReq.length = MAX_CONTROL_BUFF_SIZE;

    ret = UsbFillRequest(request, handleConvert, &params);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s fill request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    ret = UsbSubmitRequestSync(request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s submit request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    data.assign(request->compInfo.buffer, request->compInfo.buffer + request->compInfo.actualLength);
FINISHED:
    (void)UsbFreeRequest(request);
    return ret;
}

int32_t UsbDdkService::SendControlWriteRequest(
    uint64_t interfaceHandle, const UsbControlRequestSetup &setup, uint32_t timeout, const std::vector<uint8_t> &data)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(interfaceHandle, handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    struct UsbRequest *request = UsbAllocRequest(handleConvert, 0, MAX_CONTROL_BUFF_SIZE);
    if (request == nullptr) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    (void)memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams));
    params.interfaceId = USB_CTRL_INTERFACE_ID;
    params.pipeAddress = 0;
    params.pipeId = 0;
    params.requestType = USB_REQUEST_PARAMS_CTRL_TYPE;
    params.timeout = timeout;
    params.ctrlReq.target = static_cast<UsbRequestTargetType>(GET_CTRL_REQ_RECIP(setup.requestType));
    params.ctrlReq.reqType = static_cast<UsbControlRequestType>(GET_CTRL_REQ_TYPE(setup.requestType));
    params.ctrlReq.directon = static_cast<UsbRequestDirection>(GET_CTRL_REQ_DIR(setup.requestType));
    params.ctrlReq.request = setup.requestCmd;
    params.ctrlReq.value = setup.value;
    params.ctrlReq.index = setup.index;
    params.ctrlReq.buffer = (void *)data.data();
    params.ctrlReq.length = data.size();

    ret = UsbFillRequest(request, handleConvert, &params);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s fill request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    ret = UsbSubmitRequestSync(request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s submit request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

FINISHED:
    (void)UsbFreeRequest(request);
    return ret;
}

int32_t UsbDdkService::SendPipeRequest(
    const UsbRequestPipe &pipe, uint32_t size, uint32_t offset, uint32_t length, uint32_t &transferedLength)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(pipe.interfaceHandle, handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    struct UsbRequest *request = UsbAllocRequestByMmap(handleConvert, 0, size);
    if (request == nullptr) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    (void)memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams));
    params.pipeId = pipe.endpoint;
    params.pipeAddress = pipe.endpoint;
    params.requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    params.timeout = pipe.timeout;
    params.dataReq.length = length;

    ret = UsbFillRequestByMmap(request, handleConvert, &params);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s fill request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    ret = UsbSubmitRequestSync(request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s submit request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    transferedLength = request->compInfo.actualLength;
FINISHED:
    (void)UsbFreeRequestByMmap(request);
    return ret;
}

int32_t UsbDdkService::SendPipeRequestWithAshmem(
    const UsbRequestPipe &pipe, const UsbAshmem &ashmem, uint32_t &transferredLength)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(pipe.interfaceHandle, handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    struct UsbRequest *request = UsbAllocRequestByAshmem(handleConvert, 0, ashmem.size, ashmem.ashmemFd);
    if (request == nullptr) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    (void)memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams));
    params.pipeId = pipe.endpoint;
    params.pipeAddress = pipe.endpoint;
    params.requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    params.timeout = pipe.timeout;
    params.dataReq.length = ashmem.bufferLength;

    ret = UsbFillRequestByMmap(request, handleConvert, &params);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s fill request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    ret = UsbSubmitRequestSync(request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s submit request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    transferredLength = request->compInfo.actualLength;
FINISHED:
    (void)UsbFreeRequestByMmap(request);
    return ret;
}

int32_t UsbDdkService::GetDeviceMemMapFd(uint64_t deviceId, int &fd)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }
    
    int32_t ret = UsbGetDeviceMemMapFd(nullptr, GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId));
    if (ret < 0) {
        HDF_LOGE("%{public}s UsbGetDeviceMemMapFd failed %{public}d", __func__, ret);
        return ret;
    }
    fd = ret;
    HDF_LOGI("%{public}s:%{public}d fd:%{public}d", __func__, __LINE__, fd);
    return HDF_SUCCESS;
}
} // namespace V1_0
} // namespace Ddk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
