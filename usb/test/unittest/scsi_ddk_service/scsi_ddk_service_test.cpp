/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <unistd.h>
#include <sys/mman.h>

#include "hdf_log.h"
#include "scsi_ddk_err_code.h"
#include "scsi_ddk_service.h"
#include "scsi_os_adapter.h"
#include "usb_ddk_permission.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::HDI::Usb::ScsiDdk::V1_0;

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Ddk {
bool DdkPermissionManager::VerifyPermission(const std::string &permissionName)
{
    return true;
}
void DdkPermissionManager::Reset() {}
int32_t DdkPermissionManager::GetHapApiVersion(int32_t &apiVersion)
{
    return HDF_SUCCESS;
}
} // Ddk
} // Usb
} // HDI
} // OHOS

namespace {
class MockScsiOsAdapter : public ScsiOsAdapter {
public:
    int32_t SendRequest(const Request& request, uint8_t *buffer, uint32_t bufferSize,
        Response& response) override
    {
        response.status = 0;
        response.maskedStatus = 0;
        response.hostStatus = 0;
        response.driverStatus = 0;
        response.duration = 1;
        response.transferredLength = static_cast<int>(bufferSize);
        response.resId = 0;
        return HDF_SUCCESS;
    }
};

constexpr uint32_t DEVICE_MEM_MAP_SIZE = 1024 * 1024; // 1MB
constexpr uint32_t TIMEOUT_MS = 5000;
constexpr uint32_t SCSI_TRANSFER_LENGTH_MAX = 0xFFFF;
constexpr uint32_t OVERFLOW_TEST_LB_LENGTH = 65538;
constexpr uint32_t BOUNDARY_TEST_LB_LENGTH = 65537;
constexpr uint32_t SECTOR_SIZE_512 = 512;
constexpr uint32_t SECTOR_SIZE_4K = 4096;
constexpr uint32_t MEM_MAP_SIZE_4K = 4096;
constexpr uint32_t MEM_MAP_SIZE_8K = 8192;
// 128 * 512 = 65536 = 0x10000, low 16 bits = 0
constexpr uint32_t TRUNCATION_TRANSFER_LENGTH_512 = 128;
// 264 * 512 = 135168 = 0x21000, low 16 bits = 0x1000
constexpr uint32_t TRUNCATION_TRANSFER_LENGTH_264 = 264;
// 20 * 512 = 10240 > memMapSize(4096)
constexpr uint32_t EXCEEDS_MEM_MAP_TRANSFER_LENGTH = 20;
// 16 * 4096 = 65536 = 0x10000, low 16 bits = 0
constexpr uint32_t TRUNCATION_4K_TRANSFER_LENGTH = 16;

class ScsiDdkServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static ScsiDdkService *service_;
    static ScsiPeripheralDevice device_;
};

ScsiDdkService *ScsiDdkServiceTest::service_ = nullptr;
ScsiPeripheralDevice ScsiDdkServiceTest::device_ = {};

void ScsiDdkServiceTest::SetUpTestCase()
{
    static MockScsiOsAdapter mockAdapter;
    std::shared_ptr<ScsiOsAdapter> adapter(&mockAdapter, [](ScsiOsAdapter *) {});
    service_ = new ScsiDdkService(adapter);

    // Create a temp file for mmap
    const char *mmapPath = "/data/local/tmp/scsi_test_mmap";
    int memMapFd = open(mmapPath, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(memMapFd, 0) << "Failed to create mmap file";
    ftruncate(memMapFd, DEVICE_MEM_MAP_SIZE);

    // Set up device with a large lbLength to trigger overflow
    device_.devFd = -1;
    device_.memMapFd = memMapFd;
    // SCSI_TRANSFER_LENGTH_MAX * OVERFLOW_TEST_LB_LENGTH > UINT32_MAX
    device_.lbLength = OVERFLOW_TEST_LB_LENGTH;

    HDF_LOGI("SetUpTestCase: memMapFd=%{public}d, lbLength=%{public}u",
             device_.memMapFd, device_.lbLength);
}

void ScsiDdkServiceTest::TearDownTestCase()
{
    delete service_;
    service_ = nullptr;
    if (device_.memMapFd >= 0) {
        close(device_.memMapFd);
    }
}

void ScsiDdkServiceTest::SetUp() {}
void ScsiDdkServiceTest::TearDown() {}

/**
 * @tc.name: Read10Normal001
 * @tc.desc: Test functions to Read10
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Read10Normal001, TestSize.Level1)
{
    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = 1;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = DEVICE_MEM_MAP_SIZE;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Read10(device_, request, response);
    HDF_LOGI("Read10Normal001: ret=%{public}d", ret);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: Read10OverflowCheck001
 * @tc.desc: Test functions to Read10
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Read10OverflowCheck001, TestSize.Level1)
{
    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = SCSI_TRANSFER_LENGTH_MAX;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = DEVICE_MEM_MAP_SIZE;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Read10(device_, request, response);

    uint64_t expectedSize = static_cast<uint64_t>(request.transferLength) * device_.lbLength;
    HDF_LOGI("Read10OverflowCheck001: transferLength=%{public}u, lbLength=%{public}u, "
             "expectedSize=%{public}lu, ret=%{public}d",
             request.transferLength, device_.lbLength,
             static_cast<unsigned long>(expectedSize), ret);

    if (expectedSize > UINT32_MAX) {
        EXPECT_EQ(ret, SCSIPERIPHERAL_DDK_INVALID_PARAMETER)
            << "Read10 should reject overflow params, got ret=" << ret;
    }
}

/**
 * @tc.name: Read10Boundary001
 * @tc.desc: Test functions to Read10
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Read10Boundary001, TestSize.Level1)
{
    ScsiPeripheralDevice boundaryDev = device_;
    // SCSI_TRANSFER_LENGTH_MAX * BOUNDARY_TEST_LB_LENGTH = UINT32_MAX
    boundaryDev.lbLength = BOUNDARY_TEST_LB_LENGTH;

    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = SCSI_TRANSFER_LENGTH_MAX;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = DEVICE_MEM_MAP_SIZE;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Read10(boundaryDev, request, response);

    uint64_t expectedSize = static_cast<uint64_t>(request.transferLength) * boundaryDev.lbLength;
    HDF_LOGI("Read10Boundary001: expectedSize=%{public}lu, ret=%{public}d",
             static_cast<unsigned long>(expectedSize), ret);

    EXPECT_TRUE(ret == HDF_SUCCESS || ret == SCSIPERIPHERAL_DDK_INVALID_PARAMETER)
        << "Unexpected ret=" << ret;
}

/**
 * @tc.name: Read10ZeroLbLength001
 * @tc.desc: Test functions to Read10
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Read10ZeroLbLength001, TestSize.Level1)
{
    ScsiPeripheralDevice zeroDev = device_;
    zeroDev.lbLength = 0;

    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = 1;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = DEVICE_MEM_MAP_SIZE;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Read10(zeroDev, request, response);
    HDF_LOGI("Read10ZeroLbLength001: lbLength=0, ret=%{public}d", ret);

    EXPECT_EQ(ret, SCSIPERIPHERAL_DDK_INVALID_PARAMETER);
}

/**
 * @tc.name: Read10SmallMemMap001
 * @tc.desc: Test functions to Read10
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Read10SmallMemMap001, TestSize.Level1)
{
    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = 1;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = 1;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Read10(device_, request, response);
    HDF_LOGI("Read10SmallMemMap001: memMapSize=1, lbLength=%{public}u, ret=%{public}d",
             device_.lbLength, ret);

    EXPECT_EQ(ret, SCSIPERIPHERAL_DDK_INVALID_PARAMETER);
}

/**
 * @tc.name: Write10OverflowCheck001
 * @tc.desc: Test functions to Read10
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Write10OverflowCheck001, TestSize.Level1)
{
    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = SCSI_TRANSFER_LENGTH_MAX;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = DEVICE_MEM_MAP_SIZE;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Write10(device_, request, response);

    uint64_t expectedSize = static_cast<uint64_t>(request.transferLength) * device_.lbLength;
    HDF_LOGI("Write10OverflowCheck001: expectedSize=%{public}lu, ret=%{public}d",
             static_cast<unsigned long>(expectedSize), ret);

    if (expectedSize > UINT32_MAX) {
        EXPECT_EQ(ret, SCSIPERIPHERAL_DDK_INVALID_PARAMETER)
            << "Write10 should reject overflow params, got ret=" << ret;
    }
}

/**
 * @tc.name: Read10TruncationBypass001
 * @tc.desc: Verify Read10 rejects when bufferSize exceeds memMapSize due to uint16_t truncation.
 *           transferLength=128, lbLength=512 => bufferSize=65536(0x10000).
 *           Old: (uint16_t)65536=0, check "memMapSize < 0" passes, OOB write occurs.
 *           Fixed: uint32_t check "4096 < 65536" correctly rejects.
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Read10TruncationBypass001, TestSize.Level1)
{
    ScsiPeripheralDevice realDev = device_;
    realDev.lbLength = SECTOR_SIZE_512;

    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = TRUNCATION_TRANSFER_LENGTH_512;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = MEM_MAP_SIZE_4K;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Read10(realDev, request, response);
    HDF_LOGI("Read10TruncationBypass001: transferLength=%{public}u, lbLength=%{public}u, memMapSize=%{public}u, ret=%{public}d",
             request.transferLength, realDev.lbLength, request.memMapSize, ret);

    EXPECT_EQ(ret, SCSIPERIPHERAL_DDK_INVALID_PARAMETER)
        << "Read10 should reject when bufferSize(65536) > memMapSize(4096), "
        << "even though (uint16_t)65536==0 would bypass old check";
}

/**
 * @tc.name: Read10TruncationBypass002
 * @tc.desc: Verify Read10 rejects when low 16 bits of bufferSize are non-zero but still
 *           bypass the uint16_t check. transferLength=264, lbLength=512 => bufferSize=135168(0x21000).
 *           (uint16_t)135168=0x1000=4096. Old: "8192 < 4096" is false => passes, OOB ~127KB.
 *           Fixed: "8192 < 135168" => rejected.
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Read10TruncationBypass002, TestSize.Level1)
{
    ScsiPeripheralDevice realDev = device_;
    realDev.lbLength = SECTOR_SIZE_512;

    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = TRUNCATION_TRANSFER_LENGTH_264;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = MEM_MAP_SIZE_8K;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Read10(realDev, request, response);
    HDF_LOGI("Read10TruncationBypass002: transferLength=%{public}u, lbLength=%{public}u, memMapSize=%{public}u, ret=%{public}d",
             request.transferLength, realDev.lbLength, request.memMapSize, ret);

    EXPECT_EQ(ret, SCSIPERIPHERAL_DDK_INVALID_PARAMETER)
        << "Read10 should reject when bufferSize(135168) > memMapSize(8192)";
}

/**
 * @tc.name: Read10ZeroTransferLength001
 * @tc.desc: Verify Read10 rejects transferLength=0, which results in bufferSize=0.
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Read10ZeroTransferLength001, TestSize.Level1)
{
    ScsiPeripheralDevice realDev = device_;
    realDev.lbLength = SECTOR_SIZE_512;

    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = 0;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = DEVICE_MEM_MAP_SIZE;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Read10(realDev, request, response);
    HDF_LOGI("Read10ZeroTransferLength001: transferLength=0, ret=%{public}d", ret);

    EXPECT_EQ(ret, SCSIPERIPHERAL_DDK_INVALID_PARAMETER)
        << "Read10 should reject transferLength=0";
}

/**
 * @tc.name: Read10BufferSizeExceedsMemMap001
 * @tc.desc: Verify Read10 rejects when bufferSize > memMapSize without truncation trick.
 *           transferLength=20, lbLength=512 => bufferSize=10240 > memMapSize=4096.
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Read10BufferSizeExceedsMemMap001, TestSize.Level1)
{
    ScsiPeripheralDevice realDev = device_;
    realDev.lbLength = SECTOR_SIZE_512;

    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = EXCEEDS_MEM_MAP_TRANSFER_LENGTH;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = MEM_MAP_SIZE_4K;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Read10(realDev, request, response);
    HDF_LOGI("Read10BufferSizeExceedsMemMap001: transferLength=%{public}u, memMapSize=%{public}u, ret=%{public}d",
             request.transferLength, request.memMapSize, ret);

    EXPECT_EQ(ret, SCSIPERIPHERAL_DDK_INVALID_PARAMETER)
        << "Read10 should reject when bufferSize(10240) > memMapSize(4096)";
}

/**
 * @tc.name: Read10TruncationBypass4kSector001
 * @tc.desc: Verify Read10 rejects truncation bypass with 4K-sector device (lbLength=4096).
 *           transferLength=16 => bufferSize=65536(0x10000), low 16 bits=0.
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Read10TruncationBypass4kSector001, TestSize.Level1)
{
    ScsiPeripheralDevice dev4k = device_;
    dev4k.lbLength = SECTOR_SIZE_4K;

    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = TRUNCATION_4K_TRANSFER_LENGTH;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = MEM_MAP_SIZE_4K;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Read10(dev4k, request, response);
    HDF_LOGI("Read10TruncationBypass4kSector001: transferLength=%{public}u, lbLength=%{public}u, memMapSize=%{public}u, ret=%{public}d",
             request.transferLength, dev4k.lbLength, request.memMapSize, ret);

    EXPECT_EQ(ret, SCSIPERIPHERAL_DDK_INVALID_PARAMETER)
        << "Read10 should reject when bufferSize(65536) > memMapSize(4096) for 4K-sector device";
}

/**
 * @tc.name: Write10BufferSizeExceedsMemMap001
 * @tc.desc: Verify Write10 also rejects when bufferSize > memMapSize with realistic lbLength.
 *           Write10 uses AllocateBuffer (uint32_t, no truncation), verify consistency.
 * @tc.type: FUNC
 */
HWTEST_F(ScsiDdkServiceTest, Write10BufferSizeExceedsMemMap001, TestSize.Level1)
{
    ScsiPeripheralDevice realDev = device_;
    realDev.lbLength = SECTOR_SIZE_512;

    ScsiPeripheralIORequest request = {};
    request.lbAddress = 0;
    request.transferLength = TRUNCATION_TRANSFER_LENGTH_512;
    request.byte1 = 0;
    request.byte6 = 0;
    request.control = 0;
    request.memMapSize = MEM_MAP_SIZE_4K;
    request.timeout = TIMEOUT_MS;

    ScsiPeripheralResponse response;
    int32_t ret = service_->Write10(realDev, request, response);
    HDF_LOGI("Write10BufferSizeExceedsMemMap001: transferLength=%{public}u, memMapSize=%{public}u, ret=%{public}d",
             request.transferLength, request.memMapSize, ret);

    EXPECT_EQ(ret, SCSIPERIPHERAL_DDK_INVALID_PARAMETER)
        << "Write10 should reject when bufferSize(65536) > memMapSize(4096)";
}
} // namespace
