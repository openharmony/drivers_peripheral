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
#ifndef PROXY_MSGPROC_H
#define PROXY_MSGPROC_H

#include <hdf_sbuf.h>
#include "codec_type.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t CodecProxyParseGottenCapability(struct HdfSBuf *reply, CodecCapability *cap);
int32_t CodecProxyPackParam(struct HdfSBuf *data, const Param *param);
int32_t CodecProxyParseParam(struct HdfSBuf *reply, Param *param);
int32_t CodecProxyPackCodecBuffer(struct HdfSBuf *data, const CodecBuffer *codecBuffer);
int32_t CodecProxyParseCodecBuffer(struct HdfSBuf *reply, CodecBuffer *codecBuffer);
int32_t CodecProxyParseFenceFd(struct HdfSBuf *reply, int32_t *fenceFd);
int32_t CodecProxyPackFenceFd(struct HdfSBuf *data, int32_t fenceFd);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // PROXY_MSGPROC_H