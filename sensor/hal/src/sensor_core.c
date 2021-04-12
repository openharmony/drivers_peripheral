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

#include <fcntl.h>
#include "securec.h"
#include "osal_mem.h"
#include "osal_mutex.h"
#include "sensor_channel.h"
#include "sensor_common_type.h"
#include "sensor_core.h"
#include "sensor_if.h"
#include "sensor_manager.h"

#define HDF_LOG_TAG    sensor_core_c
#define HDF_SENSOR_INFO_MAX_SIZE (4 * 1024) // 4kB

void ReleaseAllSensorInfo(void)
{
    struct SensorDevManager *manager = GetSensorDevManager();
    struct SensorIdListNode *pos = NULL;
    struct SensorIdListNode *tmp = NULL;

    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &manager->sensorIdListHead, struct SensorIdListNode, node) {
        DListRemove(&(pos->node));
        OsalMemFree(pos);
    }
    if (manager->sensorInfoEntry != NULL) {
        OsalMemFree(manager->sensorInfoEntry);
        manager->sensorInfoEntry = NULL;
    }
    manager->sensorSum = 0;
}

static int32_t SetSensorIdClassification(void)
{
    struct SensorDevManager *manager = GetSensorDevManager();
    struct SensorManagerNode *pos = NULL;
    int32_t begin = 0;
    int32_t end;
    struct SensorIdListNode *sensorIdNode = NULL;
    CHECK_NULL_PTR_RETURN_VALUE(manager->sensorInfoEntry, SENSOR_NULL_PTR);

    DLIST_FOR_EACH_ENTRY(pos, &manager->managerHead, struct SensorManagerNode, node) {
        end = begin + pos->sensorCount;
        if (end > manager->sensorSum) {
            break;
        }

        for (int i = begin; i < end; i++) {
            sensorIdNode = (struct SensorIdListNode*)OsalMemCalloc(sizeof(*sensorIdNode));
            CHECK_NULL_PTR_RETURN_VALUE(sensorIdNode, SENSOR_NULL_PTR);
            sensorIdNode->ioService = pos->ioService;
            sensorIdNode->sensorId = manager->sensorInfoEntry[i].sensorId;
            SetSensorIdBySensorType(manager->sensorInfoEntry[i].sensorTypeId, manager->sensorInfoEntry[i].sensorId);
            if (sensorIdNode->sensorId == SENSOR_TYPE_ACCELEROMETER) {
                manager->sensorInfoEntry[i].maxRange = manager->sensorInfoEntry[i].maxRange * HDI_SENSOR_GRAVITY;
                manager->sensorInfoEntry[i].accuracy = HDI_SENSOR_GRAVITY / HDI_SENSOR_ACCEL_LSB / HDI_SENSOR_UNITS;
                manager->sensorInfoEntry[i].power = manager->sensorInfoEntry[i].power / HDI_SENSOR_UNITS;
            }
            DListInsertTail(&sensorIdNode->node, &manager->sensorIdListHead);
        }
        begin = end;
    }

    return HDF_SUCCESS;
}

static int32_t GetSensorInfoFromReply(struct HdfSBuf *reply)
{
    struct SensorDevManager *manager = GetSensorDevManager();
    struct SensorInformation *pos = NULL;
    struct SensorBasicInformation *buf = NULL;
    int32_t count = manager->sensorSum;
    uint32_t len;

    if (manager->sensorInfoEntry != NULL) {
        OsalMemFree(manager->sensorInfoEntry);
        manager->sensorInfoEntry = NULL;
    }

    manager->sensorInfoEntry = (struct SensorInformation *)OsalMemCalloc(sizeof(*manager->sensorInfoEntry) * count);
    if (manager->sensorInfoEntry == NULL) {
        HDF_LOGE("sensor info malloc failed");
        return HDF_FAILURE;
    }

    pos = manager->sensorInfoEntry;
    int32_t preLen = sizeof(*manager->sensorInfoEntry) -
        (sizeof(pos->maxRange) + sizeof(pos->accuracy) + sizeof(pos->power));

    for (int32_t i = 0; i < count; i++) {
        if (!HdfSbufReadBuffer(reply, (const void **)&buf, &len) || buf == NULL) {
            HDF_LOGE("sensor read reply info failed");
            break;
        }

        if (memcpy_s(pos, sizeof(*pos), (void *)buf, preLen) != EOK) {
            HDF_LOGE("sensor copy reply info failed");
            goto ERROR;
        }
        pos->maxRange = (float)(buf->maxRange);
        pos->accuracy = (float)(buf->accuracy);
        pos->power = (float)(buf->power);
        pos++;
    }

    if (SetSensorIdClassification() != SENSOR_SUCCESS) {
        HDF_LOGE("sensor id Classification failed");
        goto ERROR;
    }
    return SENSOR_SUCCESS;

ERROR:
    ReleaseAllSensorInfo();
    return HDF_FAILURE;
}

static int32_t GetSensorNumByManagerType(struct HdfSBuf *reply)
{
    struct SensorDevManager *manager = GetSensorDevManager();
    int32_t count = HdfSbufGetDataSize(reply) / sizeof(struct SensorBasicInformation);

    return ((count > manager->sensorSum) ? (count - manager->sensorSum) : 0);
}

static int32_t GetSensorInfo(struct SensorInformation **sensor, int32_t *count)
{
    struct SensorDevManager *manager = GetSensorDevManager();
    CHECK_NULL_PTR_RETURN_VALUE(sensor, SENSOR_NULL_PTR);
    CHECK_NULL_PTR_RETURN_VALUE(count, SENSOR_NULL_PTR);

    struct SensorManagerNode *pos = NULL;
    struct HdfSBuf *reply = HdfSBufObtain(HDF_SENSOR_INFO_MAX_SIZE);
    CHECK_NULL_PTR_RETURN_VALUE(reply, SENSOR_NULL_PTR);
    manager->sensorSum = 0;

    (void)OsalMutexLock(&manager->mutex);
    DLIST_FOR_EACH_ENTRY(pos, &manager->managerHead, struct SensorManagerNode, node) {
        pos->sensorCount = 0;
        if (pos->ioService == NULL || pos->ioService->dispatcher == NULL ||
            pos->ioService->dispatcher->Dispatch == NULL) {
            HDF_LOGE("sensor pos para failed");
            continue;
        }

        int32_t ret = pos->ioService->dispatcher->Dispatch(&pos->ioService->object,
            SENSOR_IO_GET_INFO_LIST, NULL, reply);
        if (ret != SENSOR_SUCCESS) {
            HDF_LOGE("sensor dispatch sensor info failed[%d]", ret);
            break;
        }
        pos->sensorCount = GetSensorNumByManagerType(reply);
        manager->sensorSum += pos->sensorCount;
    }

    if (manager->sensorSum == 0) {
        HDF_LOGE("sensor get info count failed");
        HdfSBufRecycle(reply);
        (void)OsalMutexUnlock(&manager->mutex);
        return HDF_FAILURE;
    }

    if (GetSensorInfoFromReply(reply) != SENSOR_SUCCESS) {
        HDF_LOGE("sensor get info from reply failed");
        (void)OsalMutexUnlock(&manager->mutex);
        HdfSBufRecycle(reply);
        return HDF_FAILURE;
    }

    (void)OsalMutexUnlock(&manager->mutex);
    HdfSBufRecycle(reply);

    *count = manager->sensorSum;
    *sensor = manager->sensorInfoEntry;
    return SENSOR_SUCCESS;
}

static int32_t DispatchSensorMsg(struct HdfIoService *ioService, int32_t cmd,
    struct HdfSBuf *msg, struct HdfSBuf *reply)
{
    CHECK_NULL_PTR_RETURN_VALUE(ioService, SENSOR_NULL_PTR);
    CHECK_NULL_PTR_RETURN_VALUE(ioService->dispatcher, SENSOR_NULL_PTR);
    CHECK_NULL_PTR_RETURN_VALUE(ioService->dispatcher->Dispatch, SENSOR_NULL_PTR);

    int32_t ret = ioService->dispatcher->Dispatch(&ioService->object, cmd, msg, reply);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("sensor Dispatch failed");
        return HDF_FAILURE;
    }

    return ret;
}

static int32_t SendSensorMsg(int32_t sensorId, struct HdfSBuf *msg, struct HdfSBuf *reply)
{
    int32_t ret = SENSOR_FAILURE;
    bool flag = false;
    struct SensorDevManager *manager = GetSensorDevManager();
    struct SensorIdListNode *sensorIdPos = NULL;

    DLIST_FOR_EACH_ENTRY(sensorIdPos, &manager->sensorIdListHead, struct SensorIdListNode, node) {
        if (sensorIdPos->sensorId == sensorId) {
            ret = DispatchSensorMsg(sensorIdPos->ioService, sensorId, msg, reply);
            flag = true;
            break;
        }
    }

    if (!flag) {
        HDF_LOGE("sensor id[%d] not find sensor method", sensorId);
        ret = SENSOR_NOT_SUPPORT;
    }

    return ret;
}

static int32_t EnableSensor(int32_t sensorId)
{
    struct HdfSBuf *msg = HdfSBufObtainDefaultSize();
    if (msg == NULL) {
        HDF_LOGE("failed to obtain sBuf size");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(msg, SENSOR_IO_ENABLE)) {
        HDF_LOGE("sensor write failed");
        HdfSBufRecycle(msg);
        return HDF_FAILURE;
    }

    int32_t ret = SendSensorMsg(sensorId, msg, NULL);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("sensor enable failed, ret[%d]", ret);
    }
    HdfSBufRecycle(msg);

    return ret;
}

static int32_t DisableSensor(int32_t sensorId)
{
    struct HdfSBuf *msg = HdfSBufObtainDefaultSize();
    if (msg == NULL) {
        HDF_LOGE("failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(msg, SENSOR_IO_DISABLE)) {
        HDF_LOGE("sensor write failed");
        HdfSBufRecycle(msg);
        return HDF_FAILURE;
    }

    int32_t ret = SendSensorMsg(sensorId, msg, NULL);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("sensor disable failed, ret[%d]", ret);
    }
    HdfSBufRecycle(msg);

    return ret;
}

static int32_t SetSensorBatch(int32_t sensorId, int64_t samplingInterval, int64_t interval)
{
    struct HdfSBuf *msg = HdfSBufObtainDefaultSize();
    if (msg == NULL) {
        HDF_LOGE("msg failed to obtain sBuf");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(msg, SENSOR_IO_SET_BATCH) || !HdfSbufWriteInt64(msg, samplingInterval) ||
        !HdfSbufWriteInt64(msg, interval)) {
        HDF_LOGE("sensor write failed");
        HdfSBufRecycle(msg);
        return HDF_FAILURE;
    }

    int32_t ret = SendSensorMsg(sensorId, msg, NULL);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("sensor set batch failed, ret[%d]", ret);
    }
    HdfSBufRecycle(msg);

    return ret;
}

static int32_t SetSensorMode(int32_t sensorId, int32_t mode)
{
    struct HdfSBuf *msg = HdfSBufObtainDefaultSize();
    if (msg == NULL) {
        HDF_LOGE("msg failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(msg, SENSOR_IO_SET_MODE) || !HdfSbufWriteInt32(msg, mode)) {
        HDF_LOGE("sensor write failed");
        HdfSBufRecycle(msg);
        return HDF_FAILURE;
    }

    int32_t ret = SendSensorMsg(sensorId, msg, NULL);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("sensor set mode failed, ret[%d]", ret);
    }
    HdfSBufRecycle(msg);

    return ret;
}

static int32_t SetSensorOption(int32_t sensorId, uint32_t option)
{
    struct HdfSBuf *msg = HdfSBufObtainDefaultSize();
    if (msg == NULL) {
        HDF_LOGE("msg failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(msg, SENSOR_IO_SET_OPTION) || !HdfSbufWriteUint32(msg, option)) {
        HDF_LOGE("sensor write failed");
        HdfSBufRecycle(msg);
        return HDF_FAILURE;
    }

    int32_t ret = SendSensorMsg(sensorId, msg, NULL);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("sensor set option failed, ret[%d]", ret);
    }
    HdfSBufRecycle(msg);

    return ret;
}

void GetSensorDeviceMethods(struct SensorInterface *device)
{
    CHECK_NULL_PTR_RETURN(device);
    device->GetAllSensors = GetSensorInfo;
    device->Enable = EnableSensor;
    device->Disable = DisableSensor;
    device->SetBatch = SetSensorBatch;
    device->SetMode = SetSensorMode;
    device->SetOption = SetSensorOption;
    device->Register = Register;
    device->Unregister = Unregister;
}
