/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "hi3516_audio_driver_test.h"
#include <gtest/gtest.h>
#include "hdf_uhdf_test.h"

using namespace testing::ext;

namespace {
class Hi3516PlatformOpsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void Hi3516PlatformOpsTest::SetUpTestCase()
{
    HdfTestOpenService();
}

void Hi3516PlatformOpsTest::TearDownTestCase()
{
    HdfTestCloseService();
}

void Hi3516PlatformOpsTest::SetUp()
{
}

void Hi3516PlatformOpsTest::TearDown()
{
}

// platform driver test
HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_AudioPlatformDeivceInit, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAUDIOPLATFORMDEVICEINIT, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformHwParams, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMHWPARAMS, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformRenderPrepare, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMRENDERPREPARE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformCapturePrepare, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMCAPTUREPREPARE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformWrite, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMWRITE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformRead, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMREAD, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformRenderStart, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMRENDERSTART, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformCaptureStart, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMCAPTURESTART, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformRenderStop, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMREANERSTOP, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformCaptureStop, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMCAPTUERSTOP, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformCapturePause, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMCAPUTERPAUSE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformRenderPause, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMRENDERPAUSE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformRenderResume, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMRENDERRESUME, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516PlatformOpsTest, Hi3516PlatformOpsTest_PlatformCaptureResume, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTPLATFORMCAPTURERESUME, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}
}