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

#include "mock_adaptor_memory.h"

#include <cstdlib>

#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void *MockMemMgr::MallocTest(const size_t size)
{
    if (size == 0) {
        return NULL;
    }

    void *data = malloc(size);
    if (data != NULL) {
        (void)memset_s(data, size, 0, size);
    }

    return data;
}

void MockMemMgr::FreeTest(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

extern "C" {
using namespace OHOS::UserIam::UserAuth;
IMPLEMENT_FUNCTION_WITH_INVOKER(MockMemMgr, void *, Malloc, (const size_t size), MockMemMgr::MallocTest);
IMPLEMENT_FUNCTION_WITH_INVOKER(MockMemMgr, void, Free, (void *ptr), MockMemMgr::FreeTest);
}