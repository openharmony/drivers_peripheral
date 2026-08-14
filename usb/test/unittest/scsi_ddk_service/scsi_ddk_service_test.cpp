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
} // namespace
