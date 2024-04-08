/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HOS_TIMEOUTEXECUTOR_H
#define HOS_TIMEOUTEXECUTOR_H
#include <chrono>
#include <memory>
#include <thread>             // std::thread
#include <mutex>              // std::mutex, std::unique_lock
#include <condition_variable> // std::condition_variable
#include <type_traits>
#include <atomic>
#include <functional>

namespace OHOS::TIMEOUTEXECUTOR {

template<class... Params>
struct check_all_parameters;

template <>
struct check_all_parameters<> {
    static const bool value = true;
};

template <class T, class... Others>
struct check_all_parameters<T, Others...> :
    private check_all_parameters<Others...> {
    using Mybase = check_all_parameters<Others...>;
    static const bool value = \
        std::is_scalar<T>::value && !std::is_pointer<T>::value && Mybase::value;
};

template <class... Params>
using TypesCheck = check_all_parameters<Params...>;

template <class FunctionType>
class BaseExecutor {
    template<class... Params>
    using TC = TypesCheck<Params...>;
public:
    template<class _Fx, class Params = std::enable_if_t<true>>
    struct FunctionImpl;

    // function requires parameters pass by value, no reference, no pointer
    template<class Ret, class... Args>
    struct FunctionImpl<Ret(Args...), std::enable_if_t<TC<Ret, Args...>::value>> {
        using ResultType = Ret;
        using CALLABLE = Ret(Args...);

        CALLABLE *ptr;
        FunctionImpl(CALLABLE& callable) : ptr(&callable) {}

        ResultType invoke(Args... args)
        {
            return ((CALLABLE *)ptr)(args...);
        }
    };

    // only for class inherit from std::enable_shared_from_this<T>
    template<class Ret, class Ct, class... Args>
    struct FunctionImpl<Ret(Ct::*)(Args...), std::enable_if_t<TC<Ret, Args...>::value>> {
        using ResultType = Ret;
        using CALLABLE = Ret(Ct::*)(Args...);
        using SHAREPOINTER = std::shared_ptr<Ct>;
        using Derived = std::enable_if_t<std::is_base_of<std::enable_shared_from_this<Ct>, Ct>::value>;

        CALLABLE ptr;
        FunctionImpl(CALLABLE& callable) : ptr(callable) {}

        ResultType invoke(SHAREPOINTER cls, Args... args)
        {
            return (cls.get()->*ptr)(args...);
        }
    };

    typedef FunctionImpl<FunctionType> Function;
    typedef std::shared_ptr<Function> FunctionPointer;

protected:
    FunctionPointer _fx;

public:
    BaseExecutor(FunctionType& fx) : _fx(new Function(fx)) {}
};

template <class FunctionType>
class TimeOutExecutor : public BaseExecutor<FunctionType> {
    uint32_t _timeout = 2000; //milliseconds
    using Mybase = BaseExecutor<FunctionType>;
    using Result = typename BaseExecutor<FunctionType>::Function::ResultType;

public:
    enum ExecuteResult {
        SUCCESS,
        TIMEOUT
    };

    TimeOutExecutor(FunctionType&& ft) : Mybase(ft) {}

    template<class... Args>
    ExecuteResult Execute(Result &result, Args... args)
    {
        // add ref count
        auto funcImpl = this->_fx;

        std::shared_ptr<std::condition_variable> cv =
            std::make_shared<std::condition_variable>();

        std::shared_ptr<bool> is_detach =
            std::make_shared<bool>(false);

        std::shared_ptr <std::mutex> mtxPointer = std::make_shared<std::mutex>();
        std::unique_lock<std::mutex> lck(*mtxPointer);

        std::thread workThread([=, &result]() {
            {
                std::unique_lock<std::mutex> lck(*mtxPointer);
            }

#ifndef NOLOG
            std::chrono::system_clock::time_point begin = std::chrono::system_clock::now();
#endif
            Result r = funcImpl->invoke(args...);
#ifndef NOLOG
            std::chrono::system_clock::time_point end = std::chrono::system_clock::now();
            std::cout << "Actually execute time: " << \
                std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count() << " ms" << std::endl;
#endif
            {
                std::unique_lock<std::mutex> lck(*mtxPointer);

                if (false == (*is_detach)) {
                    result = r;
                    cv->notify_one(); //notify join thread completion
                }
            }
        });

        if (cv->wait_for(lck, std::chrono::milliseconds(_timeout)) ==
            std::cv_status::timeout) {
            *is_detach = true;
            workThread.detach();    //detach work thread and return timeout
            return TimeOutExecutor::TIMEOUT;
        }

        workThread.join();
        return TimeOutExecutor::SUCCESS;
    }

    void SetTimeOut(uint32_t ms)
    {
        _timeout = ms;
    }

    uint32_t GetTimeOut() const
    {
        return _timeout;
    }
};
}

#endif //HOS_TIMEOUTEXECUTOR_H