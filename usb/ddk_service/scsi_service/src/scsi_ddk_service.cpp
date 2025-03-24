/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "scsi_ddk_service.h"

#include <hdf_base.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <securec.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <unistd.h>

#include "ddk_sysfs_dev_node.h"
#include "hdf_log.h"
#include "usbd_wrapper.h"
#include "usb_ddk_permission.h"

#ifdef __LITEOS__
#include "scsi_liteos_adapter.h"
#else
#include "scsi_linux_adapter.h"
#endif

#define HDF_LOG_TAG scsi_ddk_service
using namespace OHOS::HDI::Usb::Ddk;

namespace OHOS {
namespace HDI {
namespace Usb {
namespace ScsiDdk {
namespace V1_0 {

constexpr uint8_t THIRTY_TWO_BIT = 32;
constexpr uint8_t SCSIPERIPHERAL_MAX_SENSE_DATA_LEN = 252;
constexpr uint8_t SCSIPERIPHERAL_VENDOR_ID_LEN = 8;
constexpr uint8_t SCSIPERIPHERAL_PRODUCT_ID_LEN = 16;
constexpr uint8_t SCSIPERIPHERAL_PRODUCT_REV_LEN = 4;
constexpr uint8_t PATH_LEN = 50;
constexpr uint8_t ONE_BYTE = 1;
constexpr uint8_t TWO_BYTE = 2;
constexpr uint8_t THREE_BYTE = 3;
constexpr uint8_t FOUR_BYTE = 4;
constexpr uint8_t FIVE_BYTE = 5;
constexpr uint8_t SIX_BYTE = 6;
constexpr uint8_t SEVEN_BYTE = 7;
constexpr uint8_t EIGHT_BYTE = 8;
constexpr uint8_t NINE_BYTE = 9;
constexpr uint8_t SIXTEEN_BYTE = 16;
constexpr uint8_t THIRTY_TWO_BYTE = 32;
constexpr uint8_t EIGHT_BIT = 8;
constexpr uint8_t SIXTEEN_BIT = 16;
constexpr uint8_t TWENTY_FOUR_BIT = 24;
constexpr uint8_t BYTE_MASK = 0xFF;
constexpr uint32_t TIMEOUT = 5000;
constexpr uint8_t OPERATION_CODE_READCAPACITY10 = 0x25;
constexpr uint8_t OPERATION_CODE_TESTUNITREADY = 0x00;
constexpr uint8_t OPERATION_CODE_INQUIRY = 0x12;
constexpr uint8_t OPERATION_CODE_REQUEST_SENSE = 0x03;
constexpr uint8_t OPERATION_CODE_READ10 = 0x28;
constexpr uint8_t OPERATION_CODE_WRITE10 = 0x2A;
constexpr uint8_t OPERATION_CODE_VERIFY10 = 0x2F;
constexpr uint8_t CDB_LENGTH_SIX = 6;
constexpr uint8_t CDB_LENGTH_TEN = 10;
constexpr uint32_t MAX_TRANSFER_BYTES = UINT32_MAX;
constexpr uint32_t MAX_MEM_MAP_SIZE = UINT32_MAX;
constexpr const char* SCSIPERIPHERAL_DEVICE_MMAP_PATH = "/data/service/el1/public/usb/scsi";
static const std::string PERMISSION_NAME = "ohos.permission.ACCESS_DDK_SCSI_PERIPHERAL";
std::mutex g_memMapMutex;

class MemMapFinalizer {
public:
    MemMapFinalizer(uint8_t *buffer, uint32_t size)
        : buffer_(buffer), size_(size)
    {
    }

    ~MemMapFinalizer()
    {
        munmap(buffer_, size_);
    }

private:
    MemMapFinalizer(const MemMapFinalizer&);
    void operator=(const MemMapFinalizer&);

private:
    uint8_t *buffer_ = nullptr;
    uint32_t size_ = 0;
};

template<typename Func, typename ResultType = decltype(std::declval<Func>()())>
ResultType TrackTime(Func&& func, const char* desc = "")
{
    auto start = std::chrono::high_resolution_clock::now();
    ResultType result = func();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration<double, std::milli>(end - start);
    HDF_LOGD("Function [%{public}s] took [%{public}.2f]ms with result [%{public}d]", desc, duration_ms.count(), result);
    return result;
}

inline uint32_t GetBusNum(uint64_t devHandle)
{
    return static_cast<uint32_t>(devHandle >> THIRTY_TWO_BIT);
}

inline uint32_t GetDevNum(uint64_t devHandle)
{
    return static_cast<uint32_t>(devHandle & 0xFFFFFFFF);
}

static bool VerifyPermission(const std::string &permissionName)
{
    return DdkPermissionManager::VerifyPermission(permissionName);
}

static inline void SetUint16(unsigned char *cdb, int start, uint16_t val)
{
    cdb[start] = (val >> EIGHT_BIT) & BYTE_MASK;
    cdb[start + ONE_BYTE] = val & BYTE_MASK;
}

static inline void SetUint32(unsigned char *cdb, int start, uint32_t val)
{
    cdb[start] = (val >> TWENTY_FOUR_BIT) & BYTE_MASK;
    cdb[start + ONE_BYTE] = (val >> SIXTEEN_BIT) & BYTE_MASK;
    cdb[start + TWO_BYTE] = (val >> EIGHT_BIT) & BYTE_MASK;
    cdb[start + THREE_BYTE] = val & BYTE_MASK;
}

static inline uint32_t GetUint32(unsigned char *buf, int start)
{
    return (
        (static_cast<uint32_t>(buf[start]) << TWENTY_FOUR_BIT) |
        (static_cast<uint32_t>(buf[start + ONE_BYTE]) << SIXTEEN_BIT) |
        (static_cast<uint32_t>(buf[start + TWO_BYTE]) << EIGHT_BIT) |
        (static_cast<uint32_t>(buf[start + THREE_BYTE]))
    );
}

static void BuildCdbForReadAndWrite(const ScsiPeripheralIORequest& request, unsigned char cdb[CDB_LENGTH_TEN],
    uint8_t operationCode)
{
    cdb[0] = operationCode;
    cdb[ONE_BYTE] = request.byte1;
    SetUint32(cdb, TWO_BYTE, request.lbAddress);
    cdb[SIX_BYTE] = request.byte6;
    SetUint16(cdb, SEVEN_BYTE, request.transferLength);
    cdb[NINE_BYTE] = request.control;
}

static int32_t AllocateAndInitializeBuffer(const ScsiPeripheralDevice& dev, uint32_t memMapSize, uint8_t*& buffer,
    uint16_t allocationLength)
{
    if (memMapSize < allocationLength || memMapSize > MAX_MEM_MAP_SIZE) {
        HDF_LOGE("%{public}s: memMapSize is invalid. memMapSize=%{public}d, allocationLength=%{public}d", __func__,
            memMapSize, allocationLength);
        return SCSIPERIPHERAL_DDK_INVALID_PARAMETER;
    }
    buffer = static_cast<uint8_t *>(mmap(nullptr, memMapSize, PROT_READ | PROT_WRITE, MAP_SHARED, dev.memMapFd, 0));
    if (buffer == MAP_FAILED) {
        HDF_LOGE("%{public}s: mmap failed, errno=%{public}d, memMapFd=%{public}d, memMapSize=%{public}d", __func__,
            errno, dev.memMapFd, memMapSize);
        return SCSIPERIPHERAL_DDK_MEMORY_ERROR;
    }

    int32_t ret = memset_s(buffer, memMapSize, 0, memMapSize);
    if (ret != 0) {
        HDF_LOGE("%{public}s memset_s(io_hdr) failed, ret=%{public}d", __func__, ret);
        munmap(buffer, memMapSize);
        return SCSIPERIPHERAL_DDK_MEMORY_ERROR;
    }
    return HDF_SUCCESS;
}

static void UpdateResponseFromOsAdapter(ScsiPeripheralResponse& response, const Response& resp)
{
    response.senseData.assign(resp.senseData.begin(), resp.senseData.end());
    response.status = resp.status;
    response.maskedStatus = resp.maskedStatus;
    response.msgStatus = resp.msgStatus;
    response.sbLenWr = resp.sbLenWr;
    response.hostStatus = resp.hostStatus;
    response.driverStatus = resp.driverStatus;
    response.resId = resp.resId;
    response.duration = resp.duration;
    response.transferredLength = resp.transferredLength;
}

extern "C" IScsiPeripheralDdk *ScsiPeripheralDdkImplGetInstance(void)
{
    std::shared_ptr<ScsiOsAdapter> osAdapter;
    #ifdef __LITEOS__
        osAdapter = std::make_shared<LiteosScsiOsAdapter>();
    #else
        osAdapter = std::make_shared<LinuxScsiOsAdapter>();
    #endif
    return new (std::nothrow) ScsiDdkService(osAdapter);
}

int32_t ScsiDdkService::Init()
{
    HDF_LOGD("ScsiDdkService::Init start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGI("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::Release()
{
    HDF_LOGD("ScsiDdkService::Release start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    DdkPermissionManager::Reset();

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::Open(uint64_t deviceId, uint8_t interfaceIndex, ScsiPeripheralDevice& dev, int &memMapFd)
{
    HDF_LOGD("ScsiDdkService::Open start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGI("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    uint16_t busNum = GetBusNum(deviceId);
    uint16_t devNum = GetDevNum(deviceId);
    SysfsDevNode devNode(busNum, devNum, interfaceIndex, "sg");
    std::string path;
    int32_t ret = devNode.FindPath(path);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("Get devNodePath ret: %{public}d\n", ret);
        return SCSIPERIPHERAL_DDK_DEVICE_NOT_FOUND;
    }

    int32_t fd = TrackTime([&]() {
        return open(path.c_str(), O_RDWR);
    }, __func__);
    if (fd < 0) {
        HDF_LOGE("%{public}s open failed, path=%{public}s, errno=%{public}d", __func__, path.c_str(), errno);
        return SCSIPERIPHERAL_DDK_IO_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));

    dev.devFd = fd;
    HDF_LOGD("Open success, dev.devFd=%{public}d, path.c_str()=%{public}s", dev.devFd, path.c_str());

    ret = GetDeviceMemMapFd(busNum, devNum, interfaceIndex, memMapFd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("GetDeviceMemMapFd failed, ret=%{public}d", ret);
        return ret;
    }
    dev.memMapFd = memMapFd;

    ScsiPeripheralReadCapacityRequest request;
    ScsiPeripheralCapacityInfo capacityInfo;
    ScsiPeripheralResponse response;
    request.lbAddress = 0;
    request.byte8 = 0;
    request.control = 0;
    request.timeout = TIMEOUT;

    ret = ReadCapacity10(dev, request, capacityInfo, response);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("ReadCapacity10 failed, ret=%{public}d", ret);
        return ret;
    }

    dev.lbLength = capacityInfo.lbLength;
    HDF_LOGD("ReadCapacity success, dev.lbLength=%{public}d", dev.lbLength);

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::Close(const ScsiPeripheralDevice& dev)
{
    HDF_LOGD("ScsiDdkService::Close start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    int32_t ret = TrackTime([&]() {
        return fdsan_close_with_tag(dev.devFd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    }, __func__);
    if (ret == -1) {
        HDF_LOGE("%{public}s close failed", __func__);
        return SCSIPERIPHERAL_DDK_IO_ERROR;
    }

    ret = TrackTime([&]() {
        return fdsan_close_with_tag(dev.memMapFd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    }, __func__);
    if (ret < 0) {
        HDF_LOGE("%{public}s: close failed, memMapFd=%{public}d, errno=%{public}d", __func__, dev.memMapFd, errno);
        return SCSIPERIPHERAL_DDK_IO_ERROR;
    }

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::ReadCapacity10(const ScsiPeripheralDevice& dev,
    const ScsiPeripheralReadCapacityRequest& request, ScsiPeripheralCapacityInfo& capacityInfo,
    ScsiPeripheralResponse& response)
{
    HDF_LOGD("ScsiDdkService::ReadCapacity10 start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    Request req;
    uint8_t cdb[CDB_LENGTH_TEN];
    cdb[0] = OPERATION_CODE_READCAPACITY10;
    SetUint32(cdb, TWO_BYTE, request.lbAddress);
    cdb[EIGHT_BYTE] = request.byte8;
    cdb[NINE_BYTE] = request.control;
    req.commandDescriptorBlock.assign(cdb, cdb + sizeof(cdb));
    req.dataTransferDirection = SG_DXFER_FROM_DEV;
    req.timeout = request.timeout;
    req.devFd = dev.devFd;

    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return SCSIPERIPHERAL_DDK_INVALID_OPERATION;
    }

    std::vector<uint8_t> data(sizeof(capacityInfo));
    Response resp;
    int32_t ret = TrackTime([&]() {
        return osAdapter_->SendRequest(req, data.data(), data.size(), resp);
    }, __func__);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SendRequest failed, ret=%{public}d", __func__, ret);
        return ret;
    }

    UpdateResponseFromOsAdapter(response, resp);

    capacityInfo.lbAddress = GetUint32(data.data(), 0);
    capacityInfo.lbLength = GetUint32(data.data(), FOUR_BYTE);

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::TestUnitReady(const ScsiPeripheralDevice& dev,
    const ScsiPeripheralTestUnitReadyRequest& request, ScsiPeripheralResponse& response)
{
    HDF_LOGD("ScsiDdkService::TestUnitReady start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    Request req;
    unsigned char cdb[CDB_LENGTH_SIX];
    cdb[0] = OPERATION_CODE_TESTUNITREADY;
    SetUint32(cdb, 1, 0);
    cdb[FIVE_BYTE] = request.control;
    req.commandDescriptorBlock.assign(cdb, cdb + sizeof(cdb));
    req.dataTransferDirection = SG_DXFER_NONE;
    req.timeout = request.timeout;
    req.devFd = dev.devFd;

    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return SCSIPERIPHERAL_DDK_INVALID_OPERATION;
    }

    Response resp;
    int32_t ret = TrackTime([&]() {
        return osAdapter_->SendRequest(req, nullptr, 0, resp);
    }, __func__);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SendRequest failed, ret=%{public}d", __func__, ret);
        return ret;
    }

    UpdateResponseFromOsAdapter(response, resp);

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::Inquiry(const ScsiPeripheralDevice& dev, const ScsiPeripheralInquiryRequest& request,
    ScsiPeripheralInquiryInfo& inquiryInfo, ScsiPeripheralResponse& response)
{
    HDF_LOGD("ScsiDdkService::Inquiry start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    Request req;
    uint8_t cdb[CDB_LENGTH_SIX];
    cdb[0] = OPERATION_CODE_INQUIRY;
    cdb[ONE_BYTE] = request.byte1;
    cdb[TWO_BYTE] = request.pageCode;
    SetUint16(cdb, THREE_BYTE, request.allocationLength);
    cdb[FIVE_BYTE] = request.control;
    req.commandDescriptorBlock.assign(cdb, cdb + sizeof(cdb));
    req.dataTransferDirection = SG_DXFER_FROM_DEV;
    req.timeout = request.timeout;
    req.devFd = dev.devFd;

    std::lock_guard<std::mutex> lock(g_memMapMutex);
    uint8_t* buffer = nullptr;
    uint32_t memMapSize = request.memMapSize;
    if (memMapSize < THIRTY_TWO_BYTE + SCSIPERIPHERAL_PRODUCT_REV_LEN) {
        HDF_LOGE("%{public}s: memMapSize should be greater than %{public}d", __func__,
            THIRTY_TWO_BYTE + SCSIPERIPHERAL_PRODUCT_REV_LEN);
        return SCSIPERIPHERAL_DDK_INVALID_PARAMETER;
    }

    int32_t ret = AllocateAndInitializeBuffer(dev, memMapSize, buffer, request.allocationLength);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    MemMapFinalizer memMapFinalizer(buffer, memMapSize);

    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return SCSIPERIPHERAL_DDK_INVALID_OPERATION;
    }

    Response resp;
    ret = TrackTime([&]() {
        return osAdapter_->SendRequest(req, buffer, request.allocationLength, resp);
    }, __func__);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SendRequest failed, ret=%{public}d", __func__, ret);
        return ret;
    }

    UpdateResponseFromOsAdapter(response, resp);

    inquiryInfo.deviceType = buffer[0] & 0x1f;
    inquiryInfo.idVendor.assign(buffer + EIGHT_BYTE, buffer + EIGHT_BYTE + SCSIPERIPHERAL_VENDOR_ID_LEN);
    inquiryInfo.idProduct.assign(buffer + SIXTEEN_BYTE, buffer + SIXTEEN_BYTE + SCSIPERIPHERAL_PRODUCT_ID_LEN);
    inquiryInfo.revProduct.assign(buffer + THIRTY_TWO_BYTE, buffer + THIRTY_TWO_BYTE + SCSIPERIPHERAL_PRODUCT_REV_LEN);

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::RequestSense(const ScsiPeripheralDevice& dev,
    const ScsiPeripheralRequestSenseRequest& request, ScsiPeripheralResponse& response)
{
    HDF_LOGD("ScsiDdkService::RequestSense start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    Request req;
    unsigned char cdb[CDB_LENGTH_SIX];
    cdb[0] = OPERATION_CODE_REQUEST_SENSE;
    cdb[ONE_BYTE] = request.byte1;
    cdb[FOUR_BYTE] = request.allocationLength;
    cdb[FIVE_BYTE] = request.control;
    req.commandDescriptorBlock.assign(cdb, cdb + sizeof(cdb));
    req.dataTransferDirection = SG_DXFER_FROM_DEV;
    req.timeout = request.timeout;
    req.devFd = dev.devFd;

    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return SCSIPERIPHERAL_DDK_INVALID_OPERATION;
    }

    uint32_t bufferSize = request.allocationLength < SCSIPERIPHERAL_MAX_SENSE_DATA_LEN ? request.allocationLength :
        SCSIPERIPHERAL_MAX_SENSE_DATA_LEN;
    Response resp;
    resp.senseData.resize(bufferSize);
    int32_t ret = TrackTime([&]() {
        return osAdapter_->SendRequest(req, resp.senseData.data(), bufferSize, resp);
    }, __func__);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SendRequest failed, ret=%{public}d", __func__, ret);
        return ret;
    }

    response.senseData.resize(SCSIPERIPHERAL_MAX_SENSE_DATA_LEN);
    UpdateResponseFromOsAdapter(response, resp);

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::Read10(const ScsiPeripheralDevice& dev,
    const ScsiPeripheralIORequest& request, ScsiPeripheralResponse& response)
{
    HDF_LOGD("ScsiDdkService::Read10 start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    if (request.transferLength * dev.lbLength * (uint64_t)1 > MAX_TRANSFER_BYTES) {
        HDF_LOGE("%{public}s: The value of transferLength is too large", __func__);
        return SCSIPERIPHERAL_DDK_INVALID_PARAMETER;
    }

    Request req;
    unsigned char cdb[CDB_LENGTH_TEN];
    BuildCdbForReadAndWrite(request, cdb, OPERATION_CODE_READ10);
    req.commandDescriptorBlock.assign(cdb, cdb + sizeof(cdb));
    req.dataTransferDirection = SG_DXFER_FROM_DEV;
    req.timeout = request.timeout;
    req.devFd = dev.devFd;

    std::lock_guard<std::mutex> lock(g_memMapMutex);
    uint8_t* buffer = nullptr;
    uint32_t memMapSize = request.memMapSize;
    uint32_t bufferSize = request.transferLength * dev.lbLength;
    int32_t ret = AllocateAndInitializeBuffer(dev, memMapSize, buffer, bufferSize);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    MemMapFinalizer memMapFinalizer(buffer, memMapSize);

    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return SCSIPERIPHERAL_DDK_INVALID_OPERATION;
    }

    Response resp;
    ret = TrackTime([&]() {
        return osAdapter_->SendRequest(req, buffer, bufferSize, resp);
    }, __func__);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SendRequest failed, ret=%{public}d", __func__, ret);
        return ret;
    }
    UpdateResponseFromOsAdapter(response, resp);

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::Write10(const ScsiPeripheralDevice& dev,
    const ScsiPeripheralIORequest& request, ScsiPeripheralResponse& response)
{
    HDF_LOGD("ScsiDdkService::Write10 start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    if (request.transferLength * dev.lbLength * (uint64_t)1 > MAX_TRANSFER_BYTES) {
        HDF_LOGE("%{public}s: The value of transferLength is too large", __func__);
        return SCSIPERIPHERAL_DDK_INVALID_PARAMETER;
    }

    Request req;
    unsigned char cdb[CDB_LENGTH_TEN];
    BuildCdbForReadAndWrite(request, cdb, OPERATION_CODE_WRITE10);

    req.commandDescriptorBlock.assign(cdb, cdb + sizeof(cdb));
    req.dataTransferDirection = SG_DXFER_TO_DEV;
    req.timeout = request.timeout;
    req.devFd = dev.devFd;

    std::lock_guard<std::mutex> lock(g_memMapMutex);
    uint32_t memMapSize = request.memMapSize;
    uint32_t bufferSize = request.transferLength * dev.lbLength;
    if (memMapSize < bufferSize || memMapSize > MAX_MEM_MAP_SIZE) {
        HDF_LOGE("%{public}s: memMapSize is invalid. memMapSize=%{public}d, bufferSize=%{public}d", __func__,
            memMapSize, bufferSize);
        return SCSIPERIPHERAL_DDK_INVALID_PARAMETER;
    }

    auto buffer = static_cast<uint8_t *>(mmap(nullptr, memMapSize, PROT_READ | PROT_WRITE, MAP_SHARED,
        dev.memMapFd, 0));
    if (buffer == MAP_FAILED) {
        HDF_LOGE("%{public}s: mmap failed, errno=%{public}d, memMapFd=%{public}d, memMapSize=%{public}d", __func__,
            errno, dev.memMapFd, memMapSize);
        return SCSIPERIPHERAL_DDK_MEMORY_ERROR;
    }
    MemMapFinalizer memMapFinalizer(buffer, memMapSize);

    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return SCSIPERIPHERAL_DDK_INVALID_OPERATION;
    }

    Response resp;
    int32_t ret = TrackTime([&]() {
        return osAdapter_->SendRequest(req, buffer, bufferSize, resp);
    }, __func__);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SendRequest failed, ret=%{public}d", __func__, ret);
        return ret;
    }

    UpdateResponseFromOsAdapter(response, resp);

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::Verify10(const ScsiPeripheralDevice& dev,
    const ScsiPeripheralVerifyRequest& request, ScsiPeripheralResponse& response)
{
    HDF_LOGD("ScsiDdkService::Verify10 start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    Request req;
    unsigned char cdb[CDB_LENGTH_TEN];
    cdb[0] = OPERATION_CODE_VERIFY10;
    cdb[ONE_BYTE] = request.byte1;
    SetUint32(cdb, TWO_BYTE, request.lbAddress);
    cdb[SIX_BYTE] = request.byte6;
    SetUint16(cdb, SEVEN_BYTE, request.verificationLength);
    cdb[NINE_BYTE] = request.control;
    req.commandDescriptorBlock.assign(cdb, cdb + sizeof(cdb));
    req.dataTransferDirection = SG_DXFER_NONE;
    req.timeout = request.timeout;
    req.devFd = dev.devFd;

    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return SCSIPERIPHERAL_DDK_INVALID_OPERATION;
    }

    Response resp;
    int32_t ret = TrackTime([&]() {
        return osAdapter_->SendRequest(req, nullptr, 0, resp);
    }, __func__);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SendRequest failed, ret=%{public}d", __func__, ret);
        return ret;
    }

    UpdateResponseFromOsAdapter(response, resp);

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::SendRequestByCDB(const ScsiPeripheralDevice& dev,
    const ScsiPeripheralRequest& request, ScsiPeripheralResponse& response)
{
    HDF_LOGD("ScsiDdkService::SendRequestByCDB start");
    if (!VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return SCSIPERIPHERAL_DDK_NO_PERM;
    }

    Request req;
    req.commandDescriptorBlock = request.commandDescriptorBlock;
    req.dataTransferDirection = request.dataTransferDirection;
    req.timeout = request.timeout;
    req.devFd = dev.devFd;

    std::lock_guard<std::mutex> lock(g_memMapMutex);
    uint32_t memMapSize = request.memMapSize;
    if (memMapSize > MAX_MEM_MAP_SIZE) {
        HDF_LOGE("%{public}s: memMapSize is too large. memMapSize=%{public}d, MAX_MEM_MAP_SIZE=%{public}d", __func__,
            memMapSize, MAX_MEM_MAP_SIZE);
        return SCSIPERIPHERAL_DDK_INVALID_PARAMETER;
    }
    auto buffer = static_cast<uint8_t *>(mmap(nullptr, memMapSize, PROT_READ | PROT_WRITE, MAP_SHARED,
        dev.memMapFd, 0));
    if (buffer == MAP_FAILED) {
        HDF_LOGE("%{public}s: mmap failed, errno=%{public}d, memMapFd=%{public}d, memMapSize=%{public}d", __func__,
            errno, dev.memMapFd, memMapSize);
        return SCSIPERIPHERAL_DDK_MEMORY_ERROR;
    }
    MemMapFinalizer memMapFinalizer(buffer, memMapSize);

    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return SCSIPERIPHERAL_DDK_INVALID_OPERATION;
    }

    Response resp;
    int32_t ret = TrackTime([&]() {
        return osAdapter_->SendRequest(req, buffer, memMapSize, resp);
    }, __func__);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SendRequest failed, ret=%{public}d", __func__, ret);
        return ret;
    }
    UpdateResponseFromOsAdapter(response, resp);

    return HDF_SUCCESS;
}

int32_t ScsiDdkService::GetDeviceMemMapFd(uint16_t busNum, uint16_t devAddr, uint8_t interfaceIndex, int &memMapFd)
{
    char path[PATH_LEN];
    (void)memset_s(path, PATH_LEN, 0, PATH_LEN);
    HDF_LOGD("scsi GetDeviceMemMapFd busNum:%{public}u, devAddr:%{public}u", busNum, devAddr);
    int32_t ret = sprintf_s(path, sizeof(path), "%s_%03u_%03u_%u", SCSIPERIPHERAL_DEVICE_MMAP_PATH, busNum, devAddr,
        interfaceIndex);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: sprintf_s error, ret=%{public}d", __func__, ret);
        return SCSIPERIPHERAL_DDK_INVALID_OPERATION;
    }

    HDF_LOGD("%{public}s: path is %{public}s", __func__, path);
    int32_t fd = TrackTime([&]() {
        return open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    }, __func__);
    if (fd < 0) {
        HDF_LOGE("%{public}s: open error, path=%{public}s, errno=%{public}d", __func__, path, errno);
        return SCSIPERIPHERAL_DDK_IO_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));

    memMapFd = fd;
    HDF_LOGD("%{public}s: memMapFd:%{public}d", __func__, memMapFd);

    return HDF_SUCCESS;
}
} // V1_0
} // ScsiDdk
} // Usb
} // HDI
} // OHOS
