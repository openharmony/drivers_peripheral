/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef IAM_USER_AUTH_INTERFACE_SERVICE_TEST_H
#define IAM_USER_AUTH_INTERFACE_SERVICE_TEST_H

#include <gtest/gtest.h>

namespace OHOS {
namespace HDI {
namespace UserAuth {
namespace V1_0 {
class UserAuthInterfaceServiceTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};
} // namespace V1_0
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS
#endif // IAM_USER_AUTH_INTERFACE_SERVICE_TEST_H