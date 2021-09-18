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

HWTEST_F(Hi3516DaiAdapterTest, Hi3516DaiAdapterTest_DaiHwParams, TestSize.Level0)
{
    struct HdfTestMsg msg = {G_TEST_HI3516_AUDIO_DRIVER_TYPE, TESTDAIHWPARAMS, -1};
    EXPECT_EQ(0, HdfTestSendMsgToService(&msg));
}
}
