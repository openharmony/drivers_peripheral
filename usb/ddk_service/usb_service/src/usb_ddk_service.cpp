/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "v1_1/usb_ddk_service.h"

#include <hdf_base.h>
#include <iproxy_broker.h>
#include <shared_mutex>

#include "ddk_pnp_listener_mgr.h"
#include "ipc_skeleton.h"
#include "libusb_adapter.h"
#include "usb_ddk_hash.h"
#include "usb_ddk_interface.h"
#include "usb_ddk_permission.h"
#include "usb_driver_manager.h"
#include "usb_raw_api.h"
#include "usbd_wrapper.h"
#define HDF_LOG_TAG usb_ddk_service

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Ddk {
namespace V1_1 {
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
#define DEVICE_DESCRIPROR_LENGTH 18
constexpr int32_t API_VERSION_ID_18 = 18;
static const std::string PERMISSION_NAME = "ohos.permission.ACCESS_DDK_USB";
static pthread_rwlock_t g_rwLock = PTHREAD_RWLOCK_INITIALIZER;
#ifdef LIBUSB_ENABLE
static std::shared_ptr<OHOS::HDI::Usb::V1_2::LibusbAdapter> g_DdkLibusbAdapter =
    V1_2::LibusbAdapter::GetInstance();
constexpr uint8_t INTERFACE_ID_INVALID = 255;
static std::unordered_map<uint64_t, uint8_t> g_InterfaceMap;
std::shared_mutex g_MutexInterfaceMap;
#endif // LIBUSB_ENABLE

extern "C" IUsbDdk *UsbDdkImplGetInstance(void)
{
    return new (std::nothrow) UsbDdkService();
}

void FillReadRequestParams(const UsbControlRequestSetup &setup, const uint32_t length,
    const uint32_t timeout, UsbRequestParams &params)
{
    if (memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams)) != EOK) {
        HDF_LOGW("%{public}s memset_s failed", __func__);
    }
    params.interfaceId = USB_CTRL_INTERFACE_ID;
    params.requestType = USB_REQUEST_PARAMS_CTRL_TYPE;
    params.timeout = timeout;
    params.ctrlReq.target = static_cast<UsbRequestTargetType>(GET_CTRL_REQ_RECIP(setup.requestType));
    params.ctrlReq.reqType = setup.requestType;
    params.ctrlReq.directon = static_cast<UsbRequestDirection>(GET_CTRL_REQ_DIR(setup.requestType));
    params.ctrlReq.request = setup.requestCmd;
    params.ctrlReq.value = setup.value;
    params.ctrlReq.index = setup.index;
    params.ctrlReq.length = length;
}

void FillWriteRequestParams(const UsbControlRequestSetup &setup, const std::vector<uint8_t> &data,
    const uint32_t timeout, UsbRequestParams &params)
{
    if (memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams)) != EOK) {
        HDF_LOGW("%{public}s memset_s failed", __func__);
    }
    params.interfaceId = USB_CTRL_INTERFACE_ID;
    params.pipeAddress = 0;
    params.pipeId = 0;
    params.requestType = USB_REQUEST_PARAMS_CTRL_TYPE;
    params.timeout = timeout;
    params.ctrlReq.target = static_cast<UsbRequestTargetType>(GET_CTRL_REQ_RECIP(setup.requestType));
    params.ctrlReq.reqType = setup.requestType;
    params.ctrlReq.directon = static_cast<UsbRequestDirection>(GET_CTRL_REQ_DIR(setup.requestType));
    params.ctrlReq.request = setup.requestCmd;
    params.ctrlReq.value = setup.value;
    params.ctrlReq.index = setup.index;
    params.ctrlReq.buffer = (void *)data.data();
    params.ctrlReq.length = data.size();
}

void FillPipeRequestParams(const UsbRequestPipe &pipe, const uint32_t length, UsbRequestParams &params)
{
    if (memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams)) != EOK) {
        HDF_LOGW("%{public}s memset_s failed", __func__);
    }
    params.pipeId = pipe.endpoint;
    params.pipeAddress = pipe.endpoint;
    params.requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    params.timeout = pipe.timeout;
    params.dataReq.length = length;
}

void FillPipeRequestParamsWithAshmem(const UsbRequestPipe &pipe, const UsbAshmem &ashmem, UsbRequestParams &params)
{
    if (memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams)) != EOK) {
        HDF_LOGE("%{public}s memset_s failed", __func__);
    }
    params.pipeId = pipe.endpoint;
    params.pipeAddress = pipe.endpoint;
    params.requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    params.timeout = pipe.timeout;
    params.dataReq.length = ashmem.bufferLength;
}

int32_t CheckCompleteStatus(struct UsbRequest *request)
{
    if (request == nullptr) {
        return HDF_FAILURE;
    }
    int32_t apiVersion = 0;
    int32_t ret = DdkPermissionManager::GetHapApiVersion(apiVersion);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s get hap api version failed %{public}d", __func__, ret);
        return ret;
    }

    if (apiVersion >= API_VERSION_ID_18 && request->compInfo.status != USB_REQUEST_COMPLETED) {
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

#ifdef LIBUSB_ENABLE
uint8_t GetInterfaceId(uint64_t interfaceHandle)
{
    std::shared_lock<std::shared_mutex> interfaceLock(g_MutexInterfaceMap);
    auto it = g_InterfaceMap.find(interfaceHandle);
    if (it == g_InterfaceMap.end()) {
        HDF_LOGE("%{public}s find interfaceId failed", __func__);
        return INTERFACE_ID_INVALID;
    }
    HDF_LOGD("%{public}s find interfaceId success. interfaceId=%{public}d", __func__, it->second);
    return it->second;
}

void EraseInterfaceId(uint64_t interfaceHandle)
{
    std::unique_lock<std::shared_mutex> interfaceLock(g_MutexInterfaceMap);
    auto it = g_InterfaceMap.find(interfaceHandle);
    if (it == g_InterfaceMap.end()) {
        HDF_LOGE("%{public}s find interfaceId failed", __func__);
        return ;
    }
    g_InterfaceMap.erase(interfaceHandle);
    HDF_LOGD("%{public}s erase interfaceId success.", __func__);
}
#endif // LIBUSB_ENABLE

int32_t ReleaseUsbInterface(uint64_t interfaceHandle)
{
    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(interfaceHandle, handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }
#ifndef LIBUSB_ENABLE
    pthread_rwlock_wrlock(&g_rwLock);
    UsbDdkDelHashRecord(interfaceHandle);
    struct UsbInterface *interface = nullptr;
    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    ret = GetInterfaceByHandle(handleConvert, &interface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s get interface failed %{public}d", __func__, ret);
        pthread_rwlock_unlock(&g_rwLock);
        return ret;
    }

    ret = UsbCloseInterface(handleConvert, false);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s close interface failed %{public}d", __func__, ret);
        pthread_rwlock_unlock(&g_rwLock);
        return ret;
    }

    ret = UsbReleaseInterface(interface);
    pthread_rwlock_unlock(&g_rwLock);
    return ret;
#else
    struct InterfaceInfo infoTemp;
    ret = GetInterfaceInfoByVal(interfaceHandle, infoTemp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s infoTemp failed", __func__);
        return HDF_FAILURE;
    }
    UsbDdkDelHashRecord(interfaceHandle);
    uint8_t interfaceId = GetInterfaceId(interfaceHandle);
    if (interfaceId == INTERFACE_ID_INVALID) {
        HDF_LOGE("%{public}s get interfaceId failed", __func__);
        return HDF_FAILURE;
    }
    ret = g_DdkLibusbAdapter->ReleaseInterface({infoTemp.busNum, infoTemp.devNum}, interfaceId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed", __func__);
        return ret;
    }
    EraseInterfaceId(interfaceHandle);
    return g_DdkLibusbAdapter->CloseDevice({infoTemp.busNum, infoTemp.devNum});
#endif // LIBUSB_ENABLE
}

static int32_t UsbdPnpEventHandler(void *priv, uint32_t id, HdfSBuf *data)
{
    if (id == USB_PNP_NOTIFY_REMOVE_DEVICE) {
        uint32_t infoSize;
        struct UsbPnpNotifyMatchInfoTable *infoTable = nullptr;
        auto flag = HdfSbufReadBuffer(data, (const void **)(&infoTable), &infoSize);
        if ((!flag) || (infoTable == nullptr)) {
            HDF_LOGE("%{public}s: fail to read infoTable in event data, flag = %{public}d", __func__, flag);
            return HDF_ERR_INVALID_PARAM;
        }

        std::vector<uint64_t> interfaceHandleList;
        if (UsbDdkGetAllRecords({0, infoTable->busNum, infoTable->devNum}, interfaceHandleList)) {
            for (auto interfaceHandle : interfaceHandleList) {
                ReleaseUsbInterface(interfaceHandle);
            }
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
            delete g_pnpListener;
            g_pnpListener = nullptr;
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

    DdkPermissionManager::Reset();
    return UsbExitHostSdk(nullptr);
}

int32_t UsbDdkService::GetDeviceDescriptor(uint64_t deviceId, UsbDeviceDescriptor &desc)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }
#ifndef LIBUSB_ENABLE
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
#else
    HDF_LOGD("%{public}s enter", __func__);
    std::vector<uint8_t> descriptor(DEVICE_DESCRIPROR_LENGTH);
    if (g_DdkLibusbAdapter == nullptr) {
        HDF_LOGE("%{public}s g_DdkLibusbAdapter is nullptr", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = g_DdkLibusbAdapter->GetDeviceDescriptor({GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId)}, descriptor);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s get device descriptor failed", __func__);
        return HDF_FAILURE;
    }
    ret = memcpy_s(&desc, sizeof(desc), descriptor.data(), sizeof(desc));
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGD("%{public}s leave", __func__);
    return HDF_SUCCESS;
#endif // LIBUSB_ENABLE
}

int32_t UsbDdkService::GetConfigDescriptor(uint64_t deviceId, uint8_t configIndex, std::vector<uint8_t> &configDesc)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }
#ifndef LIBUSB_ENABLE
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
#else
    if (g_DdkLibusbAdapter == nullptr) {
        HDF_LOGE("%{public}s g_DdkLibusbAdapter is nullptr", __func__);
        return HDF_FAILURE;
    }
    return g_DdkLibusbAdapter->GetConfigDescriptor({GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId)},
        configIndex, configDesc);
#endif // LIBUSB_ENABLE
}

int32_t UsbDdkService::ClaimInterface(uint64_t deviceId, uint8_t interfaceIndex, uint64_t &interfaceHandle)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }
#ifndef LIBUSB_ENABLE
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
#else
    int32_t ret = g_DdkLibusbAdapter->OpenDevice({GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId)});
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("OpenDevice is error");
        return HDF_FAILURE;
    }
    static std::atomic<int64_t> addr(0);
    int64_t addrNumber = addr.fetch_add(1, std::memory_order_relaxed);
    ret = UsbDdkHash({addrNumber, GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId)}, interfaceHandle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s hash failed %{public}d", __func__, ret);
    }
    ret = g_DdkLibusbAdapter->ClaimInterface({GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId)}, interfaceIndex, true);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("ClaimInterface is failed");
        return HDF_FAILURE;
    }
    std::unique_lock<std::shared_mutex> interfaceLock(g_MutexInterfaceMap);
    g_InterfaceMap[interfaceHandle] = interfaceIndex;
    return HDF_SUCCESS;
#endif // LIBUSB_ENABLE
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
#ifndef LIBUSB_ENABLE
    struct UsbInterface *interface = nullptr;
    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    return UsbSelectInterfaceSetting(handleConvert, settingIndex, &interface);
#else
    struct InterfaceInfo infoTemp;
    ret = GetInterfaceInfoByVal(interfaceHandle, infoTemp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s infoTemp failed", __func__);
        return HDF_FAILURE;
    }
    uint8_t interfaceId = GetInterfaceId(interfaceHandle);
    if (interfaceId == INTERFACE_ID_INVALID) {
        HDF_LOGE("%{public}s get interfaceId failed", __func__);
        return HDF_FAILURE;
    }
    return g_DdkLibusbAdapter->SetInterface({infoTemp.busNum, infoTemp.devNum}, interfaceId, settingIndex);
#endif // LIBUSB_ENABLE
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
#ifndef LIBUSB_ENABLE
    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    return UsbGetInterfaceSetting(handleConvert, &settingIndex);
#else
    struct InterfaceInfo infoTemp;
    ret = GetInterfaceInfoByVal(interfaceHandle, infoTemp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s infoTemp failed", __func__);
        return HDF_FAILURE;
    }
    return g_DdkLibusbAdapter->GetCurrentInterfaceSetting({infoTemp.busNum, infoTemp.devNum}, settingIndex);
#endif // LIBUSB_ENABLE
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
#ifndef LIBUSB_ENABLE
    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    uint32_t length = setup.length > MAX_CONTROL_BUFF_SIZE ? MAX_CONTROL_BUFF_SIZE : setup.length;
    struct UsbRequest *request = UsbAllocRequest(handleConvert, 0, static_cast<int32_t>(length));
    if (request == nullptr) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    FillReadRequestParams(setup, length, timeout, params);
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
#else
    struct InterfaceInfo infoTemp;
    ret = GetInterfaceInfoByVal(interfaceHandle, infoTemp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s infoTemp failed", __func__);
        return HDF_FAILURE;
    }
    uint8_t reqType = static_cast<uint8_t>(setup.requestType);
    uint8_t reqCmd = static_cast<uint8_t>(setup.requestCmd);
    uint32_t length = setup.length > MAX_CONTROL_BUFF_SIZE ? MAX_CONTROL_BUFF_SIZE : setup.length;
    return g_DdkLibusbAdapter->ControlTransferReadwithLength({infoTemp.busNum, infoTemp.devNum},
        {reqType, reqCmd, setup.value, setup.index, length, timeout}, data);
#endif // LIBUSB_ENABLE
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
#ifndef LIBUSB_ENABLE
    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    struct UsbRequest *request = UsbAllocRequest(handleConvert, 0, MAX_CONTROL_BUFF_SIZE);
    if (request == nullptr) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    FillWriteRequestParams(setup, data, timeout, params);
    ret = UsbFillRequest(request, handleConvert, &params);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s fill request failed %{public}d", __func__, ret);
        (void)UsbFreeRequest(request);
        return ret;
    }

    ret = UsbSubmitRequestSync(request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s submit request failed %{public}d", __func__, ret);
        (void)UsbFreeRequest(request);
        return ret;
    }
    ret = CheckCompleteStatus(request);
    (void)UsbFreeRequest(request);
    return ret;
#else
    struct InterfaceInfo infoTemp;
    ret = GetInterfaceInfoByVal(interfaceHandle, infoTemp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s infoTemp failed", __func__);
        return HDF_FAILURE;
    }
    ret = g_DdkLibusbAdapter->ControlTransferWrite({infoTemp.busNum, infoTemp.devNum},
        {setup.requestType, setup.requestCmd, setup.value, setup.index, timeout}, data);
    HDF_LOGD("%{public}s ret%{public}d", __func__, ret);
    return (ret == HDF_SUCCESS) ? HDF_SUCCESS : HDF_ERR_INVALID_PARAM;
#endif // LIBUSB_ENABLE
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
#ifndef LIBUSB_ENABLE
    pthread_rwlock_rdlock(&g_rwLock);
    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    struct UsbRequest *request = UsbAllocRequestByMmap(handleConvert, 0, size);
    if (request == nullptr) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        pthread_rwlock_unlock(&g_rwLock);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    FillPipeRequestParams(pipe, length, params);
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
    pthread_rwlock_unlock(&g_rwLock);
    return ret;
#else
    struct InterfaceInfo infoTemp;
    ret = GetInterfaceInfoByVal(pipe.interfaceHandle, infoTemp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s infoTemp failed", __func__);
        return HDF_FAILURE;
    }
    return g_DdkLibusbAdapter->SendPipeRequest({infoTemp.busNum, infoTemp.devNum}, pipe.endpoint, size,
        transferedLength, pipe.timeout);
#endif // LIBUSB_ENABLE
}

int32_t SubmitRequestWithAshmem(const UsbRequestPipe &pipe, const UsbAshmem &ashmem, uint32_t &transferredLength,
    uint64_t handle)
{
    pthread_rwlock_rdlock(&g_rwLock);
    const UsbInterfaceHandle *handleConvert = reinterpret_cast<const UsbInterfaceHandle *>(handle);
    struct UsbRequest *request = UsbAllocRequestByAshmem(handleConvert, 0, ashmem.size, ashmem.ashmemFd);
    if (request == nullptr) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        fdsan_close_with_tag(ashmem.ashmemFd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        pthread_rwlock_unlock(&g_rwLock);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    FillPipeRequestParamsWithAshmem(pipe, ashmem, params);
    int32_t ret = UsbFillRequestByMmap(request, handleConvert, &params);
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
    fdsan_close_with_tag(ashmem.ashmemFd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    pthread_rwlock_unlock(&g_rwLock);
    return ret;
}

int32_t UsbDdkService::SendPipeRequestWithAshmem(
    const UsbRequestPipe &pipe, const UsbAshmem &ashmem, uint32_t &transferredLength)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        fdsan_close_with_tag(ashmem.ashmemFd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        return HDF_ERR_NOPERM;
    }

    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(pipe.interfaceHandle, handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        fdsan_close_with_tag(ashmem.ashmemFd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        return ret;
    }
#ifndef LIBUSB_ENABLE
    return SubmitRequestWithAshmem(pipe, ashmem, transferredLength, handle);
#else
    struct InterfaceInfo infoTemp;
    ret = GetInterfaceInfoByVal(pipe.interfaceHandle, infoTemp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s infoTemp failed", __func__);
        return HDF_FAILURE;
    }
    return g_DdkLibusbAdapter->SendPipeRequestWithAshmem({infoTemp.busNum, infoTemp.devNum}, pipe.endpoint,
        {ashmem.ashmemFd, ashmem.size}, transferredLength, pipe.timeout);
#endif // LIBUSB_ENABLE
}

int32_t UsbDdkService::GetDeviceMemMapFd(uint64_t deviceId, int &fd)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }
#ifndef LIBUSB_ENABLE
    int32_t ret = UsbGetDeviceMemMapFd(nullptr, GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId));
    if (ret < 0) {
        HDF_LOGE("%{public}s UsbGetDeviceMemMapFd failed %{public}d", __func__, ret);
        return ret;
    }
    fd = ret;
    HDF_LOGI("%{public}s:%{public}d fd:%{public}d", __func__, __LINE__, fd);
    return HDF_SUCCESS;
#else
    return g_DdkLibusbAdapter->GetDeviceMemMapFd({GET_BUS_NUM(deviceId), GET_DEV_NUM(deviceId)}, fd);
#endif // LIBUSB_ENABLE
}

int32_t UsbDdkService::GetDevices(std::vector<uint64_t> &deviceIds)
{
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

#ifndef LIBUSB_ENABLE
    return HDF_ERR_NOT_SUPPORT;
#else
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    std::vector<uint16_t> vendorIds;
    DriverAbilityInfo driverInfo;
    int32_t ret = UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, driverInfo);
    if (!ret) {
        HDF_LOGW("%{public}s: not find driver info", __func__);
        return HDF_SUCCESS;
    }
    vendorIds = driverInfo.vids;

    std::vector<struct OHOS::HDI::Usb::V1_2::DeviceInfo> devices;
    g_DdkLibusbAdapter->GetDevices(devices);
    if (devices.empty()) {
        HDF_LOGW("%{public}s: devices is empty", __func__);
        return HDF_SUCCESS;
    }

    for (auto device : devices) {
        for (auto vid : vendorIds) {
            if (device.vendorId == vid) {
                deviceIds.push_back(device.deviceId);
                break;
            }
        }
    }

    return HDF_SUCCESS;
#endif // LIBUSB_ENABLE
}

int32_t UsbDdkService::UpdateDriverInfo(const DriverAbilityInfo &driverInfo)
{
    if (UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo)) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t UsbDdkService::RemoveDriverInfo(const std::string &driverUid)
{
    if (UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid)) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}
} // namespace V1_1
} // namespace Ddk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
