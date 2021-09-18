/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "hi3516_audio_driver_test.h"
#include <gtest/gtest.h>
#include "hdf_uhdf_test.h"

using namespace testing::ext;

namespace {
class Hi3516AiaoImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void Hi3516AiaoImplTest::SetUpTestCase()
{
    HdfTestOpenService();
}

void Hi3516AiaoImplTest::TearDownTestCase()
{
    HdfTestCloseService();
}

void Hi3516AiaoImplTest::SetUp()
{
}

void Hi3516AiaoImplTest::TearDown()
{
}
// aiao driver test
HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AiaoHalSysInit, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIAOHALSYSINIT, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AiaoClockReset, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIAOCLOCKRESET, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AiaoHalReadReg, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIAOHALREADREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBuffRptr, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFRPTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBuffWptr, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFWPTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBufferAddr, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFERADDR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBufferAddr, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFERADDR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBufferSize, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFERSIZE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetTransSize, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETTRANSSIZE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetRxStart, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETRXSTART, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBuffWptr, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFWPTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBuffRptr, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFRPTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBufferSize, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFERSIZE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetTransSize, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETTRANSSIZE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetTxStart, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETTXSTART, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalDevEnable, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALDEVENABLE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipBuffRptrReg, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPBUFFRPTRREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipBuffWptrReg, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPBUFFWPTRREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopBuffRptrReg, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPBUFFRPTRREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopBuffWptrReg, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPBUFFWPTRREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopSetSysCtlReg, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPSETSYSCTLREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopSetAttr, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPSETATTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipSetSysCtlReg, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPSETSYSCTLREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipSetAttr, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPSETATTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AiaoDeviceInit, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIAODEVICEINIT, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_I2sCrgCfgInit, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTI2SCRGCFGINIT, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}
}
