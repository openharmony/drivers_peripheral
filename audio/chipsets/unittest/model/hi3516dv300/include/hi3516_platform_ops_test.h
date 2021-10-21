/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef HI3516_PLATFORM_OPS_TEST_H
#define HI3516_PLATFORM_OPS_TEST_H

#include "hdf_types.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

int32_t TestAudioPlatformDeviceInit(void);
int32_t TestPlatformHwParams(void);
int32_t TestPlatformInvalidChannelsParam(void);
int32_t TestPlatformInvalidStreamTypeParam(void);
int32_t TestPlatformInvalidRenderPeriodCountParam(void);
int32_t TestPlatformInvalidRenderPeriodSizeParam(void);
int32_t TestPlatformInvalidCaptuerPeriodCountParam(void);
int32_t TestPlatformInvalidCaptuerPeriodSizeParam(void);
int32_t TestPlatformInvalidCaptuerSilenceThresholdParam(void);
int32_t TestPlatformRenderPrepare(void);
int32_t TestPlatformCapturePrepare(void);
int32_t TestPlatformWrite(void);
int32_t TestPlatformRead(void);
int32_t TestPlatformRenderStart(void);
int32_t TestPlatformCaptureStart(void);
int32_t TestPlatformRenderStop(void);
int32_t TestPlatformCaptureStop(void);
int32_t TestPlatformRenderPause(void);
int32_t TestPlatformRenderResume(void);
int32_t TestPlatformCapturePause(void);
int32_t TestPlatformCaptureResume(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

