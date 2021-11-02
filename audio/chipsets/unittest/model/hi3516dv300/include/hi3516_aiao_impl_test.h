/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef HI3516_AIAO_IMPL_TEST_H
#define HI3516_AIAO_IMPL_TEST_H

#include "hdf_types.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

int32_t TestAiaoHalSysInit(void);
int32_t TestAiaoClockReset(void);
int32_t TestAiaoHalReadReg(void);
int32_t TestAopHalSetBuffRptr(void);
int32_t TestAopHalSetBuffRptrInvalidChdId(void);
int32_t TestAopHalSetBuffWptr(void);
int32_t TestAopHalSetBuffWptrInvalidChnId(void);
int32_t TestAopHalSetBufferAddr(void);
int32_t TestAopHalSetBufferAddrInvalidChnId(void);
int32_t TestAipHalSetBufferAddr(void);
int32_t TestAipHalSetBufferAddrInvalidChnId(void);
int32_t TestAipHalSetBufferSize(void);
int32_t TestAipHalSetBufferSizeInvalidChnId(void);
int32_t TestAipHalSetTransSize(void);
int32_t TestAipHalSetTransSizeInvalidChnId(void);
int32_t TestAipHalSetRxStart(void);
int32_t TestAipHalSetRxStartInvalidChnId(void);
int32_t TestAipHalSetBuffWptr(void);
int32_t TestAipHalSetBuffWptrInvalidChnId(void);
int32_t TestAipHalSetBuffRptr(void);
int32_t TestAipHalSetBuffRptrInvalidChnId(void);
int32_t TestAopHalSetBufferSize(void);
int32_t TestAopHalSetBufferSizeInvalidChnId(void);
int32_t TestAopHalSetTransSize(void);
int32_t TestAopHalSetTransSizeInvalidChnId(void);
int32_t TestAopHalSetTxStart(void);
int32_t TestAopHalSetTxStartInvalidChnId(void);
int32_t TestAopHalDevEnable(void);
int32_t TestAipBuffRptrReg(void);
int32_t TestAipBuffWptrReg(void);
int32_t TestAopBuffRptrReg(void);
int32_t TestAopBuffWptrReg(void);
int32_t TestAopBuffWptrReg(void);
int32_t TestAopSetSysCtlReg(void);
int32_t TestAopSetSysCtlRegInvalidRate(void);
int32_t TestAopSetAttr(void);
int32_t TestAopSetAttrInvalidChannelCnt(void);
int32_t TestAopSetAttrInvalidBitWidth(void);
int32_t TestAipSetSysCtlReg(void);
int32_t TestAipSetSysCtlRegInvalidRate(void);
int32_t TestAipSetAttr(void);
int32_t TestAipSetAttrInvalidChannelCnt(void);
int32_t TestAipSetAttrInvalidBitWidth(void);
int32_t TestAiaoDeviceInit(void);
int32_t TestI2sCrgCfgInit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
