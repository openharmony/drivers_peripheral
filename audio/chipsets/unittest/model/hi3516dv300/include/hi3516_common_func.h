/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef HI3516_COMMON_FUNC_H
#define HI3516_COMMON_FUNC_H

#include "hdf_types.h"
#include "audio_host.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */
typedef enum {
    INNER = 0,
    OUTER = 1,
}AudioType;

int32_t InitHwParam(struct AudioPcmHwParams *codecHwParam);
int32_t GetAudioCard(struct AudioCard **card, AudioType *type);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
