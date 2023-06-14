/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef IAM_MOCK_ADAPTOR_MEMORY_H
#define IAM_MOCK_ADAPTOR_MEMORY_H

#include "c_mocker.h"

#include "adaptor_memory.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockMemMgr final : public CMocker<MockMemMgr> {
public:
    static void *MallocTest(const size_t size);
    static void FreeTest(void *ptr);

    DECLARE_METHOD(void *, Malloc, (const size_t size));
    DECLARE_METHOD(void, Free, (void *ptr));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_MOCK_ADAPTOR_MEMORY_H