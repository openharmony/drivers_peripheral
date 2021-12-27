/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "usbd_function_test.h"
#include <iostream>
#include "hdf_log.h"
#include "if_system_ability_manager.h"
#include "system_ability_definition.h"
#include "usbd_client.h"

const int SLEEP_TIME = 3;

const int TEST_PORT_ID = 1;
const int TEST_POWER_ROLE = 2;
const int TEST_DATAR_ROLE = 2;

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;

void UsbdFunctionTest::SetUpTestCase(void)
{
    auto ret = UsbdClient::SetPortRole(TEST_PORT_ID, TEST_POWER_ROLE, TEST_DATAR_ROLE);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdFunctionTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    if (ret != 0) {
        exit(0);
    }
    HDF_LOGI("Start UsbdFunctionTest");
}

void UsbdFunctionTest::TearDownTestCase(void)
{
    HDF_LOGI("End UsbdFunctionTest");
}

void UsbdFunctionTest::SetUp(void) {}

void UsbdFunctionTest::TearDown(void) {}

/**
 * @tc.name: UsbdGetCurrentFunctions001
 * @tc.desc: Test functions to GetCurrentFunctions
 * @tc.desc: int32_t GetCurrentFunctions(int32_t &funcs);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdGetCurrentFunctions001, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdFunction001 : GetCurrentFunctions");
    int32_t funcs = 0;
    auto ret = UsbdClient::GetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdGetCurrentFunctions001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    HDF_LOGI("Case End : UsbdFunction001 : GetCurrentFunctions");
}

/**
 * @tc.name: UsbdGetCurrentFunctions002
 * @tc.desc: Test functions to GetCurrentFunctions
 * @tc.desc: int32_t GetCurrentFunctions(int32_t &funcs);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdGetCurrentFunctions002, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdFunction002 : GetCurrentFunctions");
    auto ret = UsbdClient::SetCurrentFunctions(1);
    HDF_LOGI("UsbdFunctionTest::UsbdFunction011 %{public}d SetCurrentFunctions=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    int32_t funcs = 255;
    ret = UsbdClient::GetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdFunction001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    HDF_LOGI("Case End : UsbdFunction002 : GetCurrentFunctions");
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdSetCurrentFunctions001
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions001, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdFunction001 : SetCurrentFunctions");
    int32_t funcs = 1;
    auto ret = UsbdClient::SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions001 %{public}d SetCurrentFunctions=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    HDF_LOGI("Case End : UsbdFunction001 : SetCurrentFunctions");
}

/**
 * @tc.name: UsbdSetCurrentFunctions002
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: 反向测试：参数异常，funcs错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions002, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdFunction002 : SetCurrentFunctions");
    int32_t funcs = -1;
    auto ret = UsbdClient::SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdFunction012 %{public}d ret=%{public}d", __LINE__, ret);
    HDF_LOGI("UsbdFunctionTest::UsbdFunction012 %{public}d funcs=%{public}d", __LINE__, funcs);
    ASSERT_TRUE(ret != 0);
    HDF_LOGI("Case End : UsbdFunction002 : SetCurrentFunctions");
}
/**
 * @tc.name: UsbdSetCurrentFunctions003
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions003, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdFunction003 : SetCurrentFunctions");
    int32_t funcs = 2;
    auto ret = UsbdClient::SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions003 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    HDF_LOGI("Case End : UsbdFunction003 : SetCurrentFunctions");
}

/**
 * @tc.name: UsbdSetCurrentFunctions004
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions004, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdFunction004 : SetCurrentFunctions");
    int32_t funcs = 3;
    auto ret = UsbdClient::SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions004 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    HDF_LOGI("Case End : UsbdFunction004 : SetCurrentFunctions");
}

/**
 * @tc.name: UsbdSetCurrentFunctions005
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions005, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdFunction005 : SetCurrentFunctions");
    int32_t funcs = 4;
    auto ret = UsbdClient::SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions005 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    HDF_LOGI("Case End : UsbdFunction005 : SetCurrentFunctions");
}

/**
 * @tc.name: UsbdSetCurrentFunctions006
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions006, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdFunction006 : SetCurrentFunctions");
    int32_t funcs = 5;
    auto ret = UsbdClient::SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    HDF_LOGI("Case End : UsbdFunction006 : SetCurrentFunctions");
}

/**
 * @tc.name: UsbdSetCurrentFunctions007
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions007, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdFunction007 : SetCurrentFunctions");
    int32_t funcs = 6;
    auto ret = UsbdClient::SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions007 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    HDF_LOGI("Case End : UsbdFunction007 : SetCurrentFunctions");
}

/**
 * @tc.name: UsbdSetCurrentFunctions008
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: 反向测试：参数异常，funcs错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions008, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdFunction008 : SetCurrentFunctions");
    int32_t funcs = 8;
    auto ret = UsbdClient::SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
    HDF_LOGI("Case End : UsbdFunction008 : SetCurrentFunctions");
}

/**
 * @tc.name: UsbdSetPortRole001
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole001, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdSetPortRole001 : SetPortRole");
    auto ret = UsbdClient::SetPortRole(1, 1, 1);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    HDF_LOGI("Case End : UsbdSetPortRole001 : SetPortRole");
}

/**
 * @tc.name: UsbdSetPortRole002
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: 反向测试：参数异常，portId错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole002, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdSetPortRole002 : SetPortRole");
    auto ret = UsbdClient::SetPortRole(2, 1, 1);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole002 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
    HDF_LOGI("Case End : UsbdSetPortRole002 : SetPortRole");
}

/**
 * @tc.name: UsbdSetPortRole003
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: 反向测试：参数异常，powerRole错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole003, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdSetPortRole003 : SetPortRole");
    auto ret = UsbdClient::SetPortRole(1, 4, 2);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole003 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
    HDF_LOGI("Case End : UsbdSetPortRole003 : SetPortRole");
}

/**
 * @tc.name: UsbdSetPortRole004
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: 反向测试：参数异常，dataRole错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole004, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdSetPortRole004 : SetPortRole");
    auto ret = UsbdClient::SetPortRole(1, 1, 5);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole004 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
    HDF_LOGI("Case End : UsbdSetPortRole004 : SetPortRole");
}

/**
 * @tc.name: UsbdSetPortRole005
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: 反向测试：参数异常，portId、powerRole错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole005, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdSetPortRole005 : SetPortRole");
    auto ret = UsbdClient::SetPortRole(1, 5, 5);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole005 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
    HDF_LOGI("Case End : UsbdSetPortRole005 : SetPortRole");
}

/**
 * @tc.name: UsbdSetPortRole006
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: 反向测试：参数异常，portId、dataRole错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole006, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdSetPortRole006 : SetPortRole");
    auto ret = UsbdClient::SetPortRole(5, 1, 5);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
    HDF_LOGI("Case End : UsbdSetPortRole006 : SetPortRole");
}

/**
 * @tc.name: UsbdSetPortRole007
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: 反向测试：powerRole、dataRole错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole007, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdSetPortRole007 : SetPortRole");
    auto ret = UsbdClient::SetPortRole(1, 5, 5);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole007 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
    HDF_LOGI("Case End : UsbdSetPortRole007 : SetPortRole");
}

/**
 * @tc.name: UsbdSetPortRole008
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: 反向测试：portId、powerRole、dataRole错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole008, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdSetPortRole008 : SetPortRole");
    auto ret = UsbdClient::SetPortRole(2, 5, 5);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
    HDF_LOGI("Case End : UsbdSetPortRole008 : SetPortRole");
}

/**
 * @tc.name: SetPortRole009
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, SetPortRole09, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdSetPortRole009 : SetPortRole");
    auto ret = UsbdClient::SetPortRole(1, 2, 2);
    HDF_LOGI("UsbdFunctionTest::SetPortRole09 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    HDF_LOGI("Case End : UsbdSetPortRole009 : SetPortRole");
}

/**
 * @tc.name: QueryPort001
 * @tc.desc: Test functions to QueryPort
 * @tc.desc: int32_t QueryPort(int32_t &portId, int32_t &powerRole, int32_t &dataRole, int32_t &mode);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, QueryPort001, TestSize.Level1)
{
    HDF_LOGI("Case Start : QueryPort001 : SetPortRole");
    int32_t portId = 0;
    int32_t powerRole = 0;
    int32_t dataRole = 0;
    int32_t mode = 0;
    auto ret = UsbdClient::QueryPort(portId, powerRole, dataRole, mode);
    HDF_LOGI("UsbdFunctionTest::SetPortRole09 %{public}d ret=%{public}d", __LINE__, ret);
    HDF_LOGI(
        "UsbdFunctionTest::SetPortRole09 %{public}d portId=%{public}d powerRole=%{public}d dataRole=%{public}d "
        "mode=%{public}d",
        __LINE__, portId, powerRole, dataRole, mode);
    ASSERT_TRUE(ret == 0);
    HDF_LOGI("Case End : QueryPort001 : SetPortRole");
}
