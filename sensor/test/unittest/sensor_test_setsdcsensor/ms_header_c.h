/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#ifndef MS_HEADER_C_H
#define MS_HEADER_C_H

#include <stdint.h>
#include <stddef.h>

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

// 创建tensor
MS_LITE_API Tensor MSTensorCreate(const char *name, int type, const int64_t *shape, size_t shapeNum, const void*data,
    size_t dataLen);

#ifdef __cplusplus
}
#endif
#endif  // MS_HEADER_C_H