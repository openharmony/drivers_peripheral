/*
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <string>
#include <unistd.h>
#include "hdf_uhdf_test.h"
#include "hdf_io_service_if.h"

using namespace testing::ext;

#define HDF_TEST_NAME "/dev/hdf_test"
namespace {
enum HdfLiteUsbRawTestCmd {
    USB_RAW_SDK_IF_START_IO,
    USB_RAW_SDK_IF_INIT_001_TEST,
    USB_RAW_SDK_IF_EXIT_001_TEST,
    USB_RAW_SDK_IF_INIT_002_TEST,
    USB_RAW_SDK_IF_EXIT_002_TEST,
    USB_RAW_SDK_IF_INIT_003_TEST,
    USB_RAW_SDK_IF_INIT_004_TEST,
    USB_RAW_SDK_IF_INIT_005_TEST,
    USB_RAW_SDK_IF_OPEN_DEVICE_001_TEST,
    USB_RAW_SDK_IF_OPEN_DEVICE_002_TEST,
    USB_RAW_SDK_IF_OPEN_DEVICE_003_TEST,
    USB_RAW_SDK_IF_OPEN_DEVICE_004_TEST,
    USB_RAW_SDK_IF_OPEN_DEVICE_005_TEST,
    USB_RAW_SDK_IF_OPEN_DEVICE_006_TEST,
    USB_RAW_SDK_IF_RESET_DEVICE_001_TEST,
    USB_RAW_SDK_IF_RESET_DEVICE_002_TEST,
    USB_RAW_SDK_IF_CLOSE_DEVICE_001_TEST,
    USB_RAW_SDK_IF_CLOSE_DEVICE_002_TEST,
    USB_RAW_SDK_IF_OPEN_DEVICE_007_TEST,
    USB_RAW_SDK_IF_GET_CONFIGURATION_001_TEST,
    USB_RAW_SDK_IF_GET_CONFIGURATION_002_TEST,
    USB_RAW_SDK_IF_GET_CONFIGURATION_003_TEST,
    USB_RAW_SDK_IF_GET_CONFIGURATION_004_TEST,
    USB_RAW_SDK_IF_GET_DEVICE_001_TEST,
    USB_RAW_SDK_IF_GET_DEVICE_002_TEST,
    USB_RAW_SDK_IF_GET_CONFIG_DESC_001_TEST,
    USB_RAW_SDK_IF_GET_CONFIG_DESC_002_TEST,
    USB_RAW_SDK_IF_GET_CONFIG_DESC_003_TEST,
    USB_RAW_SDK_IF_GET_CONFIG_DESC_004_TEST,
    USB_RAW_SDK_IF_SET_CONFIGURATION_001_TEST,
    USB_RAW_SDK_IF_SET_CONFIGURATION_002_TEST,
    USB_RAW_SDK_IF_SET_CONFIGURATION_003_TEST,
    USB_RAW_SDK_IF_SET_CONFIGURATION_004_TEST,
    USB_RAW_SDK_IF_SET_CONFIGURATION_005_TEST,
    USB_RAW_SDK_IF_SET_CONFIGURATION_006_TEST,
    USB_RAW_SDK_IF_SET_CONFIGURATION_007_TEST,
    USB_RAW_SDK_IF_SET_CONFIGURATION_008_TEST,
    USB_RAW_SDK_IF_GET_DEVICE_DESC_001_TEST,
    USB_RAW_SDK_IF_GET_DEVICE_DESC_002_TEST,
    USB_RAW_SDK_IF_GET_DEVICE_DESC_003_TEST,
    USB_RAW_SDK_IF_GET_DEVICE_DESC_004_TEST,
    USB_RAW_SDK_IF_GET_CONFIG_DESC_005_TEST,
    USB_RAW_SDK_IF_GET_DEVICE_DESC_005_TEST,
    USB_RAW_SDK_IF_CLAMIN_INTERFACE_001_TEST,
    USB_RAW_SDK_IF_CLAMIN_INTERFACE_002_TEST,
    USB_RAW_SDK_IF_CLAMIN_INTERFACE_003_TEST,
    USB_RAW_SDK_IF_CLAMIN_INTERFACE_004_TEST,
    USB_RAW_SDK_IF_CLAMIN_INTERFACE_005_TEST,
    USB_RAW_SDK_IF_RELEASE_INTERFACE_001_TEST,
    USB_RAW_SDK_IF_RELEASE_INTERFACE_002_TEST,
    USB_RAW_SDK_IF_RELEASE_INTERFACE_003_TEST,
    USB_RAW_SDK_IF_RELEASE_INTERFACE_004_TEST,
    USB_RAW_SDK_IF_CLAMIN_INTERFACE_006_TEST,
    USB_RAW_SDK_IF_ALLOC_REQUEST_001_TEST,
    USB_RAW_SDK_IF_ALLOC_REQUEST_002_TEST,
    USB_RAW_SDK_IF_ALLOC_REQUEST_003_TEST,
    USB_RAW_SDK_IF_ALLOC_REQUEST_004_TEST,
    USB_RAW_SDK_IF_ALLOC_REQUEST_005_TEST,
    USB_RAW_SDK_IF_ALLOC_REQUEST_006_TEST,
    USB_RAW_SDK_IF_ALLOC_REQUEST_007_TEST,
    USB_RAW_SDK_IF_ALLOC_REQUEST_008_TEST,
    USB_RAW_SDK_IF_ALLOC_REQUEST_010_TEST,
    USB_RAW_SDK_IF_ALLOC_REQUEST_011_TEST,
    USB_RAW_SDK_IF_FREE_REQUEST_006_TEST,
    USB_RAW_SDK_IF_FILL_ISO_REQUEST_001_TEST,
    USB_RAW_SDK_IF_FILL_ISO_REQUEST_002_TEST,
    USB_RAW_SDK_IF_FILL_ISO_REQUEST_003_TEST,
    USB_RAW_SDK_IF_FILL_ISO_REQUEST_004_TEST,
    USB_RAW_SDK_IF_FILL_ISO_REQUEST_005_TEST,
    USB_RAW_SDK_IF_FILL_ISO_REQUEST_006_TEST,
    USB_RAW_SDK_IF_FREE_REQUEST_001_TEST,
    USB_RAW_SDK_IF_FREE_REQUEST_002_TEST,
    USB_RAW_SDK_IF_FREE_REQUEST_003_TEST,
    USB_RAW_SDK_IF_FREE_REQUEST_004_TEST,
    USB_RAW_SDK_IF_FREE_REQUEST_005_TEST,
    USB_RAW_SDK_IF_ALLOC_REQUEST_009_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_001_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_002_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_003_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_004_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_005_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_006_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_007_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_008_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_009_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_010_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_011_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_012_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_013_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_014_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_015_TEST,
    USB_RAW_SDK_IF_GET_DESCRIPTION_016_TEST,
    USB_RAW_SDK_IF_FILL_BULK_REQUEST_001_TEST,
    USB_RAW_SDK_IF_FILL_BULK_REQUEST_002_TEST,
    USB_RAW_SDK_IF_FILL_INT_REQUEST_001_TEST,
    USB_RAW_SDK_IF_FILL_INT_REQUEST_002_TEST,
    USB_RAW_SDK_IF_FILL_INT_REQUEST_003_TEST,
    USB_RAW_SDK_IF_FILL_INT_REQUEST_004_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_001_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_002_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_003_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_004_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_005_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_006_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_007_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_008_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_SETUP_001_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_SETUP_002_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_SETUP_003_TEST,
    USB_RAW_SDK_IF_FILL_CONTROL_SETUP_004_TEST,
    USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_001_TEST,
    USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_002_TEST,
    USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_003_TEST,
    USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_004_TEST,
    USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_005_TEST,
    USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_006_TEST,
    USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_007_TEST,
    USB_RAW_SDK_IF_SEND_BULK_REQUEST_001_TEST,
    USB_RAW_SDK_IF_SEND_BULK_REQUEST_002_TEST,
    USB_RAW_SDK_IF_SEND_BULK_REQUEST_003_TEST,
    USB_RAW_SDK_IF_SEND_BULK_REQUEST_004_TEST,
    USB_RAW_SDK_IF_SEND_BULK_REQUEST_005_TEST,
    USB_RAW_SDK_IF_SEND_INT_REQUEST_001_TEST,
    USB_RAW_SDK_IF_SEND_INT_REQUEST_002_TEST,
    USB_RAW_SDK_IF_SEND_INT_REQUEST_003_TEST,
    USB_RAW_SDK_IF_SEND_INT_REQUEST_004_TEST,
    USB_RAW_SDK_IF_FILL_BULK_REQUEST_003_TEST,
    USB_RAW_SDK_IF_FILL_BULK_REQUEST_004_TEST,
    USB_RAW_SDK_IF_FILL_INT_REQUEST_005_TEST,
    USB_RAW_SDK_IF_SUBMIT_REQUEST_001_TEST,
    USB_RAW_SDK_IF_SUBMIT_REQUEST_002_TEST,
    USB_RAW_SDK_IF_SUBMIT_REQUEST_003_TEST,
    USB_RAW_SDK_IF_SUBMIT_REQUEST_004_TEST,
    USB_RAW_SDK_IF_CANCEL_REQUEST_001_TEST,
    USB_RAW_SDK_IF_CANCEL_REQUEST_002_TEST,
    USB_RAW_SDK_IF_CANCEL_REQUEST_003_TEST,
    USB_RAW_SDK_IF_CANCEL_REQUEST_004_TEST,
    USB_RAW_SDK_IF_STOP_IO,
};

class hdfUsbRawTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void hdfUsbRawTest::SetUpTestCase()
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_START_IO, -1};
    HdfTestOpenService();
    HdfTestSendMsgToService(&msg);
}

void hdfUsbRawTest::TearDownTestCase()
{
    HdfTestCloseService();
}

/**
 * @tc.number    : CheckRawSdkIfInit001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfInit001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_INIT_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfExit001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfExit001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_EXIT_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfInit002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfInit002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_INIT_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfExit002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfExit002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_EXIT_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfInit003
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfInit003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_INIT_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfInit004
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfInit004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_INIT_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfInit005
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfInit005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_INIT_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfOpenDevice001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfOpenDevice001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_OPEN_DEVICE_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfOpenDevice002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfOpenDevice002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_OPEN_DEVICE_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfOpenDevice003
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfOpenDevice003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_OPEN_DEVICE_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfOpenDevice004
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfOpenDevice004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_OPEN_DEVICE_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfOpenDevice005
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfOpenDevice005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_OPEN_DEVICE_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfOpenDevice006
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfOpenDevice006, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_OPEN_DEVICE_006_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfResetDevice001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfResetDevice001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_RESET_DEVICE_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfResetDevice002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfResetDevice002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_RESET_DEVICE_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfCloseDevice001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfCloseDevice001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CLOSE_DEVICE_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfCloseDevice002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfCloseDevice002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CLOSE_DEVICE_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfOpenDevice007
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfOpenDevice007, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_OPEN_DEVICE_007_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetConfiguration001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetConfiguration001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_CONFIGURATION_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetConfiguration002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetConfiguration002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_CONFIGURATION_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetConfiguration003
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetConfiguration003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_CONFIGURATION_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetConfiguration004
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetConfiguration004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_CONFIGURATION_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDevice001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDevice001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DEVICE_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDevice002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDevice002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DEVICE_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetConfigDescriptor001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetConfigDescriptor001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_CONFIG_DESC_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetConfigDescriptor002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetConfigDescriptor002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_CONFIG_DESC_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetConfigDescriptor003
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetConfigDescriptor003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_CONFIG_DESC_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetConfigDescriptor004
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetConfigDescriptor004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_CONFIG_DESC_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSetConfiguration001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSetConfiguration001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SET_CONFIGURATION_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSetConfiguration002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSetConfiguration002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SET_CONFIGURATION_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSetConfiguration003
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSetConfiguration003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SET_CONFIGURATION_003_TEST, -1};
    EXPECT_EQ(HDF_FAILURE, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSetConfiguration004
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSetConfiguration004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SET_CONFIGURATION_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSetConfiguration005
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSetConfiguration005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SET_CONFIGURATION_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSetConfiguration006
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSetConfiguration006, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SET_CONFIGURATION_006_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSetConfiguration007
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSetConfiguration007, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SET_CONFIGURATION_007_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSetConfiguration008
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSetConfiguration008, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SET_CONFIGURATION_008_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDeviceDescriptor001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDeviceDescriptor001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DEVICE_DESC_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDeviceDescriptor002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDeviceDescriptor002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DEVICE_DESC_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDeviceDescriptor003
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDeviceDescriptor003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DEVICE_DESC_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDeviceDescriptor004
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDeviceDescriptor004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DEVICE_DESC_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetConfigDescriptor005
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetConfigDescriptor005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_CONFIG_DESC_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDeviceDescriptor005
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDeviceDescriptor005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DEVICE_DESC_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfClaimInterface001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfClaimInterface001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CLAMIN_INTERFACE_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfClaimInterface002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfClaimInterface002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CLAMIN_INTERFACE_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfClaimInterface003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfClaimInterface003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CLAMIN_INTERFACE_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfClaimInterface004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfClaimInterface004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CLAMIN_INTERFACE_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfClaimInterface005
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfClaimInterface005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CLAMIN_INTERFACE_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfReleaseInterface001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfReleaseInterface001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_RELEASE_INTERFACE_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfReleaseInterface002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfReleaseInterface002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_RELEASE_INTERFACE_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfReleaseInterface003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfReleaseInterface003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_RELEASE_INTERFACE_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfReleaseInterface004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfReleaseInterface004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_RELEASE_INTERFACE_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfClaimInterface006
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfClaimInterface006, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CLAMIN_INTERFACE_006_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfAllocRequest001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfAllocRequest001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_ALLOC_REQUEST_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfAllocRequest002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfAllocRequest002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_ALLOC_REQUEST_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfAllocRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfAllocRequest003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_ALLOC_REQUEST_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfAllocRequest004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfAllocRequest004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_ALLOC_REQUEST_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfAllocRequest005
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfAllocRequest005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_ALLOC_REQUEST_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}
/**
 * @tc.number    : CheckRawSdkIfAllocRequest006
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfAllocRequest006, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_ALLOC_REQUEST_006_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}
/**
 * @tc.number    : CheckRawSdkIfAllocRequest007
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfAllocRequest007, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_ALLOC_REQUEST_007_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfAllocRequest008
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfAllocRequest008, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_ALLOC_REQUEST_008_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}
/**
 * @tc.number    : CheckRawSdkIfAllocRequest010
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfAllocRequest010, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_ALLOC_REQUEST_010_TEST, -1};
    EXPECT_EQ(HDF_FAILURE, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfAllocRequest011
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfAllocRequest011, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_ALLOC_REQUEST_011_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillIsoRequest001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillIsoRequest001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_ISO_REQUEST_001_TEST, -1};
    EXPECT_EQ(HDF_FAILURE, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillIsoRequest002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillIsoRequest002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_ISO_REQUEST_002_TEST, -1};
    EXPECT_EQ(HDF_FAILURE, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillIsoRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillIsoRequest003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_ISO_REQUEST_003_TEST, -1};
    EXPECT_EQ(HDF_FAILURE, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillIsoRequest004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillIsoRequest004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_ISO_REQUEST_004_TEST, -1};
    EXPECT_EQ(HDF_FAILURE, HdfTestSendMsgToService(&msg));
}
/**
 * @tc.number    : CheckRawSdkIfFillIsoRequest005
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillIsoRequest005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_ISO_REQUEST_005_TEST, -1};
    EXPECT_EQ(HDF_FAILURE, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillIsoRequest006
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillIsoRequest006, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_ISO_REQUEST_006_TEST, -1};
    EXPECT_EQ(HDF_FAILURE, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFreeRequest006
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFreeRequest006, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FREE_REQUEST_006_TEST, -1};
    EXPECT_EQ(HDF_FAILURE, HdfTestSendMsgToService(&msg));
}
/**
 * @tc.number    : CheckRawSdkIfFreeRequest001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFreeRequest001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FREE_REQUEST_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFreeRequest002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFreeRequest002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FREE_REQUEST_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFreeRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFreeRequest003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FREE_REQUEST_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFreeRequest004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFreeRequest004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FREE_REQUEST_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFreeRequest005
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFreeRequest005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FREE_REQUEST_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfAllocRequest009
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfAllocRequest009, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_ALLOC_REQUEST_009_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor003
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor004
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor005
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor007
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor007, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_007_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor008
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor008, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_008_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor009
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor009, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_009_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor010
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor010, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_010_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor011
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor011, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_011_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor012
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor012, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_012_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor013
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor013, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_013_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor014
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor014, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_014_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor015
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor015, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_015_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfGetDescriptor016
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfGetDescriptor016, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_GET_DESCRIPTION_016_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillBulkRequest001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillBulkRequest001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_BULK_REQUEST_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillBulkRequest002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillBulkRequest002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_BULK_REQUEST_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillInterruptRequest001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillInterruptRequest001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_INT_REQUEST_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillInterruptRequest002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillInterruptRequest002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_INT_REQUEST_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillInterruptRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillInterruptRequest003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_INT_REQUEST_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillInterruptRequest004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillInterruptRequest004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_INT_REQUEST_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlRequest001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlRequest001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlRequest002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlRequest002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlRequest003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlRequest004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlRequest004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlRequest005
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlRequest005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlRequest006
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlRequest006, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_006_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlRequest007
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlRequest007, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_007_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlRequest008
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlRequest008, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_REQUEST_008_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlSetup001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlSetup001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_SETUP_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlSetup002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlSetup002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_SETUP_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlSetup003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlSetup003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_SETUP_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillControlSetup004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillControlSetup004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_CONTROL_SETUP_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendControlRequest001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendControlRequest001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendControlRequest002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendControlRequest002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendControlRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendControlRequest003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendControlRequest005
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendControlRequest005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendControlRequest006
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendControlRequest006, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_006_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendControlRequest007
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendControlRequest007, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_CONTROL_REQUEST_007_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendBulkRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendBulkRequest003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_BULK_REQUEST_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendBulkRequest004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendBulkRequest004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_BULK_REQUEST_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendBulkRequest005
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendBulkRequest005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_BULK_REQUEST_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendInterruptRequest002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendInterruptRequest002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_INT_REQUEST_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendInterruptRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendInterruptRequest003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_INT_REQUEST_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSendInterruptRequest004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSendInterruptRequest004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SEND_INT_REQUEST_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillBulkRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillBulkRequest003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_BULK_REQUEST_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillBulkRequest004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillBulkRequest004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_BULK_REQUEST_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFillInterruptRequest005
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFillInterruptRequest005, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FILL_INT_REQUEST_005_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSubmitRequest001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSubmitRequest001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SUBMIT_REQUEST_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSubmitRequest002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSubmitRequest002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SUBMIT_REQUEST_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSubmitRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSubmitRequest003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SUBMIT_REQUEST_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfSubmitRequest004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfSubmitRequest004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_SUBMIT_REQUEST_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfCancelRequest001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfCancelRequest001, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CANCEL_REQUEST_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfCancelRequest002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfCancelRequest002, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CANCEL_REQUEST_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfCancelRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfCancelRequest003, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CANCEL_REQUEST_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfCancelRequest004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfCancelRequest004, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CANCEL_REQUEST_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : UsbStopIo
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, UsbStopIo, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_STOP_IO, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFreeRequest004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFreeRequest004_close, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FREE_REQUEST_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFreeRequest003
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFreeRequest003_close, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FREE_REQUEST_003_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFreeRequest001
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFreeRequest001_close, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FREE_REQUEST_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfFreeRequest002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfFreeRequest002_close, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_FREE_REQUEST_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfReleaseInterface004
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfReleaseInterface004_close, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_RELEASE_INTERFACE_004_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfReleaseInterface002
 * @tc.name      :
 * @tc.type      : PERFs
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfReleaseInterface002_close, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_RELEASE_INTERFACE_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfCloseDevice002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfCloseDevice002_close, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_CLOSE_DEVICE_002_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

/**
 * @tc.number    : CheckRawSdkIfExit001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(hdfUsbRawTest, CheckRawSdkIfExit001_close, TestSize.Level1)
{
    struct HdfTestMsg msg = {TEST_USB_HOST_RAW_TYPE, USB_RAW_SDK_IF_EXIT_001_TEST, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}
}
