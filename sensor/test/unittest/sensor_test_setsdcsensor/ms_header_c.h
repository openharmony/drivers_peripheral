/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MS_HEADER_C_H
#define MS_HEADER_C_H

#include <cstdint.h>
#include <cstddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MS_LITE_API
#ifdef _WIN32
#define MS_LITE_API __declspec(dllexport)
#else
#define MS_LITE_API __attribute__((visibility("default")))
#endif
#endif

typedef void *Context;
typedef void *Model;
typedef void *Tensor;

typedef struct CallbackInfo {
    char *callbackName;
    char *callbackType;
} CallbackInfo;

typedef struct TensorInfo {
    size_t num;
    Tensor *list;
} TensorInfo;

typedef bool (*CallbackFun)(const TensorInfo inputTensor, const TensorInfo outputTensor,
    const CallbackInfo callbackInfo);

// 创建模型上下文
MS_LITE_API Context MSContextCreate(void);

// 创建模型
MS_LITE_API Model MSModelCreate(void);

// 编译模型
MS_LITE_API int MSModelBuild(Model model, const void *data, size_t size, int type, const Context context);

// 销毁模型
MS_LITE_API void MSModelDestroy(Model *model);

// 销毁模型上下文
MS_LITE_API void MSContextDestroy(Context *context);

// 获取模型输入Tensor
MS_LITE_API TensorInfo MSModelGetInputs(const Model model);

// 获取tensor内多个数据
MS_LITE_API void *MSTensorGetMutableData(const Tensor tensor);

// 获取Tensor元素个数
MS_LITE_API int64_t MSTensorGetElementNum(const Tensor tensor);

// 获取模型输出tensor
MS_LITE_API TensorInfo MSModelGetOutputs(const Model model);

// 模型推理
MS_LITE_API int MSModelPredict(Model model, const TensorInfo inputTensor, TensorInfo *outputTensor,
    const CallbackFun callbackBefore, const CallbackFun callbackAfter);

// 获取tensor内数据
MS_LITE_API const void *MSTensorGetData(const Tensor tensor);

#ifdef __cplusplus
}
#endif
#endif  // MS_HEADER_C_H