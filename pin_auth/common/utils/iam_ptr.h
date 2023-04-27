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

#ifndef IAM_PTR_H
#define IAM_PTR_H

#include <memory>

#include "refbase.h"

namespace OHOS {
namespace UserIam {
namespace Common {
template <typename T>
static inline std::shared_ptr<T> SptrToStdSharedPtr(sptr<T> &other)
{
    return std::shared_ptr<T>(other.GetRefPtr(), [other](T *) mutable { other = nullptr; });
}

template <typename T, typename... Args>
static inline std::shared_ptr<T> MakeShared(Args &&... args)
{
    try {
        return std::make_shared<T>(std::forward<Args>(args)...);
    } catch (...) {
        return nullptr;
    }
}

template <typename T, typename... Args>
static inline std::unique_ptr<T> MakeUnique(Args &&... args)
{
    try {
        return std::make_unique<T>(std::forward<Args>(args)...);
    } catch (...) {
        return nullptr;
    }
}
} // namespace Common
} // namespace UserIam
} // namespace OHOS

#endif // IAM_PTR_H
