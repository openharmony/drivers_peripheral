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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include "pnp_message_report.h"
#include "audio_internal.h"
#include "hdf_log.h"


#define PNP_REPORT_MSG_FIELD_NUM 5

static int32_t AudioPnpDevPlugMsgDeSerialize(uint8_t *msgStr, struct PnpReportDevPlugMsg *devPlugMsg)
{
    int i;
    char *stringTepm = NULL;
    uint8_t buf[PNP_REPORT_MSG_FIELD_NUM -1] = {0};

    if (msgStr == NULL) {
        HDF_LOGE("[%{public}s]: Parameter error!\n", __func__);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    char strTemp[PNP_REPORT_MSG_LEN_MAX] = {0};
    memcpy_s(strTemp, PNP_REPORT_MSG_LEN_MAX - 1, (char *)msgStr, strlen((char *)msgStr));

    stringTepm = strtok((char*)strTemp, ";");
    if (stringTepm != NULL) {
        devPlugMsg->eventType = (uint8_t)atoi(stringTepm);
        if (devPlugMsg->eventType != DEVICE_PULG) {
            HDF_LOGE("[%{public}s]: PnpReportType error!\n", __func__);

            return AUDIO_HAL_ERR_INVALID_PARAM;
        }
    }
    for (i = 1; i < PNP_REPORT_MSG_FIELD_NUM; i++) {
        stringTepm = strtok(NULL, ";");
        if (stringTepm != NULL) {
            buf[i - 1] = (uint8_t)atoi(stringTepm);
        } else {
            HDF_LOGE("[%{public}s]: Parse error!\n", __func__);
            return AUDIO_HAL_ERR_NOT_SUPPORT;
        }
    }
    devPlugMsg->state = buf[0];
    devPlugMsg->deviceType = buf[1];
    devPlugMsg->deviceCap = buf[2];
    devPlugMsg->id = buf[3];

    return AUDIO_HAL_SUCCESS;
}

static int32_t AudioPnpDevEventMsgDeSerialize(uint8_t *msgStr, struct PnpReportEventMsg *eventMsg)
{
    int i;
    char *stringTepm = NULL;
    uint8_t buf[PNP_REPORT_MSG_FIELD_NUM -1] = {0};

    if (msgStr == NULL || eventMsg == NULL) {
        HDF_LOGE("[%{public}s]: Parameter error!\n", __func__);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    char strTemp[PNP_REPORT_MSG_LEN_MAX] = {0};
    memcpy_s(strTemp, PNP_REPORT_MSG_LEN_MAX - 1, (char *)msgStr, strlen((char *)msgStr));

    stringTepm = strtok((char *)strTemp, ";");
    if (stringTepm != NULL) {
        eventMsg->eventType = (uint8_t)atoi(stringTepm);
        if (eventMsg->eventType != EVENT_REPORT) {
            HDF_LOGE("[%{public}s]: PnpReportType error!\n", __func__);
            return AUDIO_HAL_ERR_INVALID_PARAM;
        }
    }
    for (i = 1; i < PNP_REPORT_MSG_FIELD_NUM; i++) {
        stringTepm = strtok(NULL, ";");
        if (stringTepm != NULL) {
            buf[i - 1] = (uint8_t)atoi(stringTepm);
        } else {
            HDF_LOGE("[%{public}s]: Parse error!\n", __func__);
            return AUDIO_HAL_ERR_NOT_SUPPORT;
        }
    }

    eventMsg->eventId = buf[0];
    eventMsg->eventValue = buf[1];
    eventMsg->deviceType = buf[2];
    eventMsg->reserve = buf[3];
    
    return AUDIO_HAL_SUCCESS;
}

int32_t PnpReportMsgDeSerialize(uint8_t *msgStr, enum PnpReportType msgType, 
    struct PnpReportMsg *pnpReportMsg)
{
    int32_t ret;
    int len;
    if (pnpReportMsg == NULL || msgStr == NULL) {
        HDF_LOGE("[%s]: Parameter error!\n", __func__);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    len = strlen((const char *)msgStr);
    if (len == 0 || len > PNP_REPORT_MSG_LEN_MAX) {
        HDF_LOGE("[%s]: Parameter error!\n", __func__);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    switch (msgType) {
        case DEVICE_PULG:
            pnpReportMsg->reportType = DEVICE_PULG;
            ret = AudioPnpDevPlugMsgDeSerialize(msgStr, &pnpReportMsg->devPlugMsg);
            if (ret != 0) {
                HDF_LOGE("[%s]: PnpDevPlugMsgPrase error!\n", __func__);
                return AUDIO_HAL_ERR_INTERNAL;
            }
            break;
        case EVENT_REPORT:
            pnpReportMsg->reportType = EVENT_REPORT;
            ret = AudioPnpDevEventMsgDeSerialize(msgStr, &pnpReportMsg->eventMsg);
            if (ret != 0) {
                HDF_LOGE("[%s]: PnpDevEventMsgPrase error!\n", __func__);
                return AUDIO_HAL_ERR_INTERNAL;
            }
            break;
        default:
            HDF_LOGE("[%s]: Unknown message type!\n", __func__);
            return AUDIO_HAL_ERR_NOT_SUPPORT;
    }
    return AUDIO_HAL_SUCCESS;
}

uint8_t *PnpReportMsgSerialize(struct PnpReportMsg *pnpReportMsg)
{
    uint8_t *msgBuf = NULL;

    if (pnpReportMsg == NULL) {
        HDF_LOGE("[%s]: Parameter error!\n", __func__);
        return NULL;
    }
    
    msgBuf = (uint8_t *)calloc(1, PNP_REPORT_MSG_LEN_MAX);
    if (msgBuf == NULL) {
        HDF_LOGE("[%s]: Malloc memory failed!\n", __func__);
        return NULL;
    }
    memset_s(msgBuf, PNP_REPORT_MSG_LEN_MAX, 0, PNP_REPORT_MSG_LEN_MAX);
    
    switch (pnpReportMsg->reportType) {
        case DEVICE_PULG:
            (void)snprintf_s((char *)msgBuf, PNP_REPORT_MSG_LEN_MAX, PNP_REPORT_MSG_LEN_MAX - 1, "%d;%d;%d;%d;%d",
                    pnpReportMsg->devPlugMsg.eventType, pnpReportMsg->devPlugMsg.state,
                    pnpReportMsg->devPlugMsg.deviceType, pnpReportMsg->devPlugMsg.deviceCap,
                    pnpReportMsg->devPlugMsg.id);
            break;
        case EVENT_REPORT:
            (void)snprintf_s((char *)msgBuf, PNP_REPORT_MSG_LEN_MAX, PNP_REPORT_MSG_LEN_MAX - 1, "%d;%d;%d;%d;%d",
                    pnpReportMsg->eventMsg.eventType, pnpReportMsg->eventMsg.eventId,
                    pnpReportMsg->eventMsg.eventValue, pnpReportMsg->eventMsg.deviceType,
                    pnpReportMsg->eventMsg.reserve);
            break;
        default:
            HDF_LOGE("[%s]: Unknown message type!\n", __func__);
            AudioMemFree((void **)&msgBuf);
            return NULL;
    }

    return msgBuf;
}

