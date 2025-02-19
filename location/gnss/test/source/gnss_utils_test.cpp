/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "gnss_utils_test.h"
#include "gnss_interface_impl.h"
#include "string_ex.h"

using namespace testing::ext;
namespace OHOS {
namespace HDI {
namespace Location {
namespace Gnss {
namespace V1_0 {

void GnssUtilsTest::SetUp()
{
    auto gnssInstance_ = GnssInterfaceImplGetInstance();
}

void GnssUtilsTest::TearDown()
{
    gnssInstance_ = nullptr;
}

HWTEST_F(GnssUtilsTest, SetGnssReferenceInfoTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "GnssUtilsTest, SetGnssReferenceInfoTest001, TestSize.Level1";
    EXPECT_NE(nullptr, gnssInstance_);
    if (gnssInstance_ != nullptr) {
        int32_t ret = gnssInstance_->SetGnssReferenceInfo();
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

HWTEST_F(GnssUtilsTest, SetPredictGnssDataTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "GnssUtilsTest, SetPredictGnssDataTest001, TestSize.Level1";
    EXPECT_NE(nullptr, gnssInstance_);
    if (gnssInstance_ != nullptr) {
        int32_t ret = gnssInstance_->SetPredictGnssData();
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

HWTEST_F(GnssUtilsTest, GetCachedGnssLocationsSizeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "GnssUtilsTest, GetCachedGnssLocationsSizeTest001, TestSize.Level1";
    EXPECT_NE(nullptr, gnssInstance_);
    if (gnssInstance_ != nullptr) {
        int32_t ret = gnssInstance_->GetCachedGnssLocationsSize();
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

HWTEST_F(GnssUtilsTest, EnableGnssTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "GnssUtilsTest, EnableGnssTest001, TestSize.Level1";
    EXPECT_NE(nullptr, gnssInstance_);
    int32_t ret = gnssInstance_->StartGnss(GnssStartType::GNSS_START_TYPE_NORMAL);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
} // V1_0
} // Gnss
} // Location
} // HDI
} // OHOS
