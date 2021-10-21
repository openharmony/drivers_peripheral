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
class Hi3516DaiAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void Hi3516DaiAdapterTest::SetUpTestCase()
{
    HdfTestOpenService();
}

void Hi3516DaiAdapterTest::TearDownTestCase()
{
    HdfTestCloseService();
}

void Hi3516DaiAdapterTest::SetUp()
{
}

void Hi3516DaiAdapterTest::TearDown()
{
}

// dai driver test

HWTEST_F(Hi3516DaiAdapterTest, Hi3516DaiAdapterTest_DaiHwParams, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTDAIHWPARAMS, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}

// condition samplerate is invalid
HWTEST_F(Hi3516DaiAdapterTest, Hi3516DaiAdapterTest_InvalidRateParam, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTDAIINVALIDRATEPARAM, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

// condition reander bitwitdh invalid
HWTEST_F(Hi3516DaiAdapterTest, Hi3516DaiAdapterTest_InvalidRenderBitwidthParam, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTDAIINVALIDRENDERBITWIDTHPARAM, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

// condition capture bitwitdh invalid
HWTEST_F(Hi3516DaiAdapterTest, Hi3516DaiAdapterTest_InvalidCaptuerBitwidthParam, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTDAIINVALIDCAPTUERBITWIDTHPARAM, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

// condition stream type invalid
HWTEST_F(Hi3516DaiAdapterTest, Hi3516DaiAdapterTest_InvalidStreamTypeParam, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTDAIINVALIDSTREAMTYPEPARAM, -1};
    EXPECT_EQ(-1, HdfTestSendMsgToService(&msg));
}

HWTEST_F(Hi3516DaiAdapterTest, Hi3516DaiAdapterTest_Trigger, TestSize.Level1)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTDAITRIGGER, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}
}
