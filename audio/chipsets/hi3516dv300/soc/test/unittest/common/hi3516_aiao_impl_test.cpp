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
HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AiaoHalSysInit, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIAOHALSYSINIT, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AiaoClockReset, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIAOCLOCKRESET, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AiaoHalReadReg, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIAOHALREADREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBuffRptr, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFRPTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBuffRptrInvalidChnId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFRPTRINVALIDCHANID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBuffWptr, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFWPTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBuffWptrInvalidChnId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFWPTRINVALIDCHNID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBufferAddr, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFERADDR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBufferAddrInvalidChnId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFERADDRINVALIDCHNID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBufferAddr, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFERADDR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBufferAddrInvalidChnId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFERADDRINVALIDCHNID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBufferSize, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFERSIZE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBufferSizeInvalidChnId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFERSIZEINVALIDCHNID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetTransSize, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETTRANSSIZE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetTransSizeInvalidChnId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETTRANSSIZEINVALIDCHNID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetRxStart, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETRXSTART, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetRxStartInvalidChnId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETRXSTARTINVALIDCHNID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBuffWptr, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFWPTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBuffWptrInvalidChdId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFWPTRINVALIDCHNID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBuffRptr, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFRPTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipHalSetBuffRptrInvalidChnId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPHALSETBUFFRPTRINVALIDCHNID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBufferSize, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFERSIZE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetBufferSizeInvalidChnId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETBUFFERSIZEINVALIDCHNID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetTransSize, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETTRANSSIZE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetTransSizeInvalidChnId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETTRANSSIZEINVALIDCHNID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetTxStart, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETTXSTART, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalSetTxStartInvalidChnId, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALSETTXSTARTINVALIDCHNID, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_ShowAllAiaoRegister, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTSHOWALLAIAOREGISTER, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopHalDevEnable, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPHALDEVENABLE, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipBuffRptrReg, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPBUFFRPTRREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipBuffWptrReg, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPBUFFWPTRREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopBuffRptrReg, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPBUFFRPTRREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopBuffRptrRegInvalidChannelCnt, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPSETATTRINVALIDCHANNELCNT, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopBuffRptrRegInvalidBitWidth, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPSETATTRINVALIDBITWIDTH, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopBuffWptrReg, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPBUFFWPTRREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopSetSysCtlReg, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPSETSYSCTLREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopSetSysCtlRegInvalidRate, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPSETSYSCTLREGINVALIDRATE, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AopSetAttr, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAOPSETATTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipSetSysCtlReg, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPSETSYSCTLREG, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipSetSysCtlRegInvalidRate, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPSETSYSCTLREGINVALIDRATE, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipSetAttr, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPSETATTR, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipBuffRptrRegInvalidChannelCnt, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPSETATTRINVALIDCHANNELCNT, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AipBuffRptrRegInvalidBitWidth, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIPSETATTRINVALIDBITWIDTH, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_AiaoDeviceInit, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTAIAODEVICEINIT, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516AiaoImplTest, Hi3516AiaoImplTest_I2sCrgCfgInit, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTI2SCRGCFGINIT, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}
}
