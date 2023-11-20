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

#include "v1_1/audio_types.h"
#include "hdf_types.h"

#define FFRT_TASK_ATTR_STORAGE_SIZE 128
#define FFRT_AUTO_MANAGED_FUNCTION_STORAGE_SIZE 64 + sizeof(ffrt_function_header_t)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t storage[(FFRT_TASK_ATTR_STORAGE_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
} ffrt_task_attr_t;

typedef void(*ffrt_function_t)(void*);

typedef enum {
    ffrt_function_kind_general,
    ffrt_function_kind_queue,
#ifdef FFRT_IO_TASK_SCHEDULER
    ffrt_function_kind_io,
#endif
} ffrt_function_kind_t;

typedef enum {
    ffrt_qos_inherit = -1,
    ffrt_qos_background,
    ffrt_qos_utility,
    ffrt_qos_default,
    ffrt_qos_user_initiated,
} ffrt_qos_default_t;

typedef enum {
    ffrt_dependence_data,
    ffrt_dependence_task,
} ffrt_dependence_type_t;

typedef struct {
    ffrt_dependence_type_t type;
    const void *ptr;
} ffrt_dependence_t;

typedef struct {
    uint32_t len;
    const ffrt_dependence_t *items;
} ffrt_deps_t;

typedef struct {
    ffrt_function_t exec;
    ffrt_function_t destroy;
    uint64_t reserve[2];
} ffrt_function_header_t;

typedef struct {
    ffrt_function_header_t header;
    ffrt_function_t func;
    ffrt_function_t afterFunc;
    void *arg;
} FFRTFunction;

typedef void*(*ffrt_alloc_base)(ffrt_function_kind_t);
typedef int(*ffrt_task_attr_init)(ffrt_task_attr_t*);
typedef void(*ffrt_task_attr_set_qos)(ffrt_task_attr_t*, int);
typedef void(*ffrt_task_attr_set_name)(ffrt_task_attr_t*, const char*);
typedef void(*ffrt_submit_base)(
    ffrt_function_header_t*, const ffrt_deps_t*, const ffrt_deps_t*, const ffrt_task_attr_t*);
ffrt_task_attr_init FFRTAttrInit();
ffrt_task_attr_set_qos FFRTAttrSetQos();
ffrt_task_attr_set_name FFRTAttrSetName();
ffrt_submit_base FFRTSubmitBase();

/* statusInfo is update new info */
int32_t AudioPnpUpdateInfo(const char *statusInfo);
int32_t AudioPnpUpdateInfoOnly(struct AudioEvent audioEvent);
int32_t AudioUhdfUnloadDriver(const char *driverName);
int32_t AudioUhdfLoadDriver(const char *driverName);
ffrt_function_header_t* FFRTCreateFunctionWrapper(const ffrt_function_t func,
    const ffrt_function_t afterFunc, void* arg);
#ifdef __cplusplus
}
#endif
#endif
