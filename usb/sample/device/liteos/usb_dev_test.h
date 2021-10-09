/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <hdf_io_service_if.h>
#include <hdf_log.h>
#include <osal_file.h>
#include <osal_mem.h>
#include <osal_mutex.h>
#include <osal_thread.h>
#include <osal_time.h>
#include <securec.h>

int acm_speed_read(int argc, char *argv[]);
int acm_speed_write(int argc, char *argv[]);
int acm_test(int argc, char *argv[]);
int prop_test(int argc, char *argv[]);
