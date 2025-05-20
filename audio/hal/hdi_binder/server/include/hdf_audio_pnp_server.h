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

#ifndef HDF_AUDIO_PNP_SERVER_H
#define HDF_AUDIO_PNP_SERVER_H

#include "v5_0/audio_types.h"
#include "hdf_types.h"

#define FFRT_TASK_ATTR_STORAGE_SIZE 128
#define FFRT_AUTO_MANAGED_FUNCTION_STORAGE_SIZE (64 + sizeof(FfrtFunctionHeader))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t storage[(FFRT_TASK_ATTR_STORAGE_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
} FfrtTaskAttr;

typedef void(*FfrtFunctionT)(void*);

typedef enum {
    FFRT_FUNCTION_KIND_GENERAL,
    FFRT_FUNCTION_KIND_QUEUE,
#ifdef FFRT_IO_TASK_SCHEDULER
    FFRT_FUNCTION_KIND_IO,
#endif
} FfrtFunctionKind;

typedef enum {
    FFRT_QOS_INHERIT = -1,
    FFRT_QOS_BACKGROUND,
    FFRT_QOS_UTILITY,
    FFRT_QOS_DEFAULT,
    FFRT_QOS_USER_INITIATED,
} FfrtQosDefault;

typedef enum {
    FFRT_DEPENDENCE_DATA,
    FFRT_DEPENDENCE_TASK,
} FfrtDependenceType;

typedef struct {
    FfrtDependenceType type;
    const void *ptr;
} FfrtDependence;

typedef struct {
    uint32_t len;
    const FfrtDependence *items;
} FfrtDeps;

typedef struct {
    FfrtFunctionT exec;
    FfrtFunctionT destroy;
    uint64_t reserve[2];
} FfrtFunctionHeader;

typedef struct {
    FfrtFunctionHeader header;
    FfrtFunctionT func;
    FfrtFunctionT afterFunc;
    void *arg;
} FfrtFunction;

typedef void*(*FfrtAllocBase)(FfrtFunctionKind);
typedef int(*FfrtTaskAttrInit)(FfrtTaskAttr*);
typedef void(*FfrtTaskAttrSetQos)(FfrtTaskAttr*, int);
typedef void(*FfrtTaskAttrSetName)(FfrtTaskAttr*, const char*);
typedef void(*FfrtSubmitBase)(
    FfrtFunctionHeader*, const FfrtDeps*, const FfrtDeps*, const FfrtTaskAttr*);
FfrtTaskAttrInit FfrtAttrInitFunc(void);
FfrtTaskAttrSetQos FfrtAttrSetQosFunc(void);
FfrtTaskAttrSetName FfrtAttrSetNameFunc(void);
FfrtSubmitBase FfrtSubmitBaseFunc(void);

/* statusInfo is update new info */
int32_t AudioPnpUpdateInfo(const char *statusInfo);
int32_t AudioPnpUpdateInfoOnly(struct AudioEvent audioEvent);
int32_t AudioUhdfUnloadDriver(const char *driverName);
int32_t AudioUhdfLoadDriver(const char *driverName);
FfrtFunctionHeader* FfrtCreateFunctionWrapper(const FfrtFunctionT func,
    const FfrtFunctionT afterFunc, void* arg);
#ifdef __cplusplus
}
#endif
#endif
