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

#include <securec.h>
#include "display_type.h"
#include "hdf_io_service_if.h"
#include "hdf_log.h"
#include "hdf_sbuf.h"
#include "disp_hal.h"

#define OFFSET_TWO_BYTE    16
#define MASK_TWO_BYTE      0xffff

static int32_t DispCmdSend(const uint32_t cmd, struct HdfSBuf *reqData, struct HdfSBuf *respData)
{
    struct HdfIoService *dispService = NULL;

    dispService = HdfIoServiceBind(DISP_SERVICE_NAME);
    if (dispService == NULL || dispService->dispatcher == NULL || dispService->dispatcher->Dispatch == NULL) {
        HDF_LOGE("%s:bad remote service found", __func__);
        goto EXIT;
    }
    int32_t ret = dispService->dispatcher->Dispatch(&dispService->object, cmd, reqData, respData);
    if (ret) {
        HDF_LOGE("%s: cmd=%d, ret=%d", __func__, cmd, ret);
        goto EXIT;
    }
    HDF_LOGI("%s: cmd=%d, ret=%d", __func__, cmd, ret);
    HdfIoServiceRecycle(dispService);
    return DISPLAY_SUCCESS;

EXIT:
    HdfIoServiceRecycle(dispService);
    return DISPLAY_FAILURE;
}

int32_t DispGetInfo(uint32_t devId, struct DispInfo *info)
{
    int32_t ret;
    struct DispInfo *tmpInfo = NULL;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (info == NULL) {
        HDF_LOGE("%s: invalid param", __func__);
        return DISPLAY_FAILURE;
    }

    data = HdfSBufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: obtain data sbuf fail", __func__);
        return DISPLAY_FAILURE;
    }
    reply = HdfSBufObtainDefaultSize();
    if (reply == NULL) {
        HDF_LOGE("%s: obtain reply sbuf fail", __func__);
        goto EXIT;
    }
    if (!HdfSbufWriteUint32(data, devId)) {
        HDF_LOGE("HdfSbufWriteUint32 failure");
        goto EXIT;
    }
    ret = DispCmdSend(DISP_CMD_GET_PANELINFO, data, reply);
    if (ret) {
        HDF_LOGE("cmd:DISP_CMD_GET_PANEL_INFO failure");
        goto EXIT;
    }
    uint32_t dataSize = 0;
    if (!HdfSbufReadBuffer(reply, (const void **)(&tmpInfo), &dataSize) || dataSize != sizeof(struct DispInfo)) {
        HDF_LOGE("HdfSbufReadBuffer failure");
        goto EXIT;
    }
    (void)memcpy_s(info, sizeof(struct DispInfo), tmpInfo, dataSize);
    HDF_LOGI("tmpInfo->width = %d, tmpInfo->height = %d", tmpInfo->width, tmpInfo->height);
    HDF_LOGI("tmpInfo->hbp = %d, tmpInfo->hfp = %d", tmpInfo->hbp, tmpInfo->hfp);
    HDF_LOGI("tmpInfo->frameRate = %d", tmpInfo->frameRate);
    HDF_LOGI("tmpInfo->intfSync = %d", tmpInfo->intfSync);
    HdfSBufRecycle(data);
    HdfSBufRecycle(reply);
    return DISPLAY_SUCCESS;

EXIT:
    HdfSBufRecycle(data);
    HdfSBufRecycle(reply);
    return DISPLAY_FAILURE;
}

int32_t DispOn(uint32_t devId)
{
    int32_t ret;
    uint32_t mode = DISP_ON;

    struct HdfSBuf *data = HdfSBufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: obtain data sbuf fail", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t para = (devId << OFFSET_TWO_BYTE) | (mode & 0xffff);
    if (!HdfSbufWriteUint32(data, para)) {
        HDF_LOGE("HdfSbufWriteUint32 failure\n");
        goto EXIT;
    }
    ret = DispCmdSend(DISP_CMD_SET_POWERMODE, data, NULL);
    if (ret) {
        HDF_LOGE("cmd:DISP_CMD_SET_POWERMODE failure\n");
        goto EXIT;
    }
    HdfSBufRecycle(data);
    return DISPLAY_SUCCESS;

EXIT:
    HdfSBufRecycle(data);
    return DISPLAY_FAILURE;
}

int32_t SetBacklight(uint32_t devId, uint32_t level)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSBufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: obtain data sbuf fail", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t para = (devId << OFFSET_TWO_BYTE) | (level & 0xffff);
    if (!HdfSbufWriteUint32(data, para)) {
        HDF_LOGE("HdfSbufWriteUint32 failure\n");
        goto EXIT;
    }
    ret = DispCmdSend(DISP_CMD_SET_BACKLIGHT, data, NULL);
    if (ret) {
        HDF_LOGE("cmd:DISP_CMD_SET_BACKLIGHT failure\n");
        goto EXIT;
    }
    HdfSBufRecycle(data);
    return DISPLAY_SUCCESS;

EXIT:
    HdfSBufRecycle(data);
    return DISPLAY_FAILURE;
}

int32_t DispOff(uint32_t devId)
{
    int32_t ret;
    uint32_t mode = DISP_OFF;

    struct HdfSBuf *data = HdfSBufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: obtain data sbuf fail", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t para = (devId << OFFSET_TWO_BYTE) | (mode & 0xffff);
    if (!HdfSbufWriteUint32(data, para)) {
        HDF_LOGE("HdfSbufWriteUint32 failure\n");
        goto EXIT;
    }
    ret = DispCmdSend(DISP_CMD_SET_POWERMODE, data, NULL);
    if (ret) {
        HDF_LOGE("cmd:DISP_CMD_SET_POWERMODE failure\n");
        goto EXIT;
    }
    HdfSBufRecycle(data);
    return DISPLAY_SUCCESS;

EXIT:
    HdfSBufRecycle(data);
    return DISPLAY_FAILURE;
}

int32_t DispInit(uint32_t devId)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSBufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: obtain data sbuf fail", __func__);
        return DISPLAY_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, devId)) {
        HDF_LOGE("HdfSbufWriteUint32 failure\n");
        goto EXIT;
    }
    ret = DispCmdSend(DISP_CMD_INIT, data, NULL);
    if (ret) {
        HDF_LOGE("cmd:DISP_CMD_INIT failure\n");
        goto EXIT;
    }
    HdfSBufRecycle(data);
    return DISPLAY_SUCCESS;

EXIT:
    HdfSBufRecycle(data);
    return DISPLAY_FAILURE;
}
