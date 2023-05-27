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

#ifndef IAM_UNITTEST_C_MOCKER_H
#define IAM_UNITTEST_C_MOCKER_H

#include <dlfcn.h>
#include <mutex>

#include <gmock/gmock.h>

namespace OHOS {
namespace UserIam {
namespace UserAuth {

template <typename T>
class CMocker {
public:
    CMocker()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        EXPECT_EQ(instance_, nullptr);
        instance_ = static_cast<T *>(this);
    }

    virtual ~CMocker()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        EXPECT_EQ(instance_, this);
        instance_ = nullptr;
    }
    static inline T *GetInstance()
    {
        return instance_;
    }

    static inline std::mutex &GetMutex()
    {
        return mutex_;
    }

private:
    static T *instance_;
    static std::mutex mutex_;
};

template <typename T>
T *CMocker<T>::instance_ = nullptr;

template <typename T>
std::mutex CMocker<T>::mutex_ {};

#define SIGNATURE(ret, args) (GMOCK_INTERNAL_SIGNATURE(ret, args))

#define PARAMETER(index, signature, dummy) \
    GMOCK_PP_COMMA_IF(index) GMOCK_INTERNAL_ARG_O(index, GMOCK_PP_REMOVE_PARENS(signature))

#define DECLARE_METHOD(ret, method, args)                                                                  \
public:                                                                                                    \
    MOCK_METHOD(ret, method, args);                                                                        \
    using typeof##method = ret (*)(GMOCK_PP_REPEAT(PARAMETER, SIGNATURE(ret, args), GMOCK_PP_NARG0 args)); \
    using get##method = std::function<typeof##method()>;                                                   \
    const static typeof##method default##method;

#define IMPLEMENT_FUNCTION_INTERNAL(cls, method, count, signature, invoker)                               \
    const cls::typeof##method cls::default##method = reinterpret_cast<cls::typeof##method>(invoker);      \
    testing::internal::Function<GMOCK_PP_REMOVE_PARENS(signature)>::Result method(                        \
        GMOCK_PP_REPEAT(GMOCK_INTERNAL_PARAMETER, signature, count))                                      \
    {                                                                                                     \
        const std::lock_guard<std::mutex> lock(cls::GetMutex());                                          \
        static auto lookup = reinterpret_cast<cls::typeof##method>(dlsym(RTLD_NEXT, #method));            \
                                                                                                          \
        auto *mock = cls::GetInstance();                                                                  \
        auto *stub = cls::default##method != nullptr ? cls::default##method : lookup;                     \
                                                                                                          \
        if (mock != nullptr && stub != nullptr) {                                                         \
            ON_CALL(*mock, method).WillByDefault(stub);                                                   \
        }                                                                                                 \
                                                                                                          \
        if (mock != nullptr) {                                                                            \
            return mock->method(GMOCK_PP_REPEAT(GMOCK_INTERNAL_FORWARD_ARG, signature, count));           \
        }                                                                                                 \
                                                                                                          \
        if (stub != nullptr) {                                                                            \
            return stub(GMOCK_PP_REPEAT(GMOCK_INTERNAL_FORWARD_ARG, signature, count));                   \
        }                                                                                                 \
                                                                                                          \
        testing::internal::Log(testing::internal::kWarning, #method " invoked without an implement.", 0); \
        return testing::internal::Function<GMOCK_PP_REMOVE_PARENS(signature)>::Result();                  \
    }

#define IMPLEMENT_FUNCTION_WITH_INVOKER(cls, ret, method, args, invoker) \
    IMPLEMENT_FUNCTION_INTERNAL(cls, method, GMOCK_PP_NARG0 args, SIGNATURE(ret, args), invoker)

#define IMPLEMENT_FUNCTION(cls, ret, method, args) \
    IMPLEMENT_FUNCTION_WITH_INVOKER(cls, ret, method, args, static_cast<void *>(nullptr))

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_UNITTEST_C_MOCKER_H