/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "sensor_dump.h"
#include <inttypes.h>
#include "devhost_dump_reg.h"
#include "sensor_uhdf_log.h"
#include "sensor_channel.h"
#include "sensor_controller.h"
#include "sensor_manager.h"

#define HDF_LOG_TAG    uhdf_sensor_service
#define STRING_LEN    2048

static const char *g_helpComment =
    " Sensor manager dump options:\n"
    "     -h: [sensor command help]\n"
    "     -l: [show sensor list]\n"
    "     -d: [The data information is displayed 10 times]\n";

struct SensorDevelopmentList {
    int32_t sensorTypeId;
    char sensorName[SENSOR_NAME_MAX_LEN];
    int32_t dataDimension;
};

struct SensorDevelopmentList g_sensorList[] = {
    { SENSOR_TYPE_NONE, "sensor_test", DATA_X },
    { SENSOR_TYPE_ACCELEROMETER, "accelerometer", DATA_XYZ },
    { SENSOR_TYPE_PEDOMETER, "pedometer", DATA_X },
    { SENSOR_TYPE_PROXIMITY, "proximity", DATA_X },
    { SENSOR_TYPE_HALL, "hallrometer", DATA_X },
    { SENSOR_TYPE_BAROMETER, "barometer", DATA_XY },
    { SENSOR_TYPE_AMBIENT_LIGHT, "als", DATA_X },
    { SENSOR_TYPE_MAGNETIC_FIELD, "magnetometer", DATA_XYZ },
    { SENSOR_TYPE_GYROSCOPE, "gyroscope", DATA_XYZ },
    { SENSOR_TYPE_GRAVITY, "gravity", DATA_XYZ }
};

int32_t SensorShowList(struct HdfSBuf *reply)
{
    int32_t index = -1;
    int32_t ret = 0;
    int32_t *sensorStatus = NULL;
    struct SensorDevManager *sensorList = NULL;
    char sensorInfoDate[STRING_LEN] = { 0 };

    sensorList = GetSensorDevManager();
    if ((sensorList == NULL) || (sensorList->sensorInfoEntry == NULL) || (sensorList->sensorSum == 0)) {
        HDF_LOGE("%{public}s: sensorList is failed\n", __func__);
        return DUMP_NULL_PTR;
    }

    sensorStatus = GetSensorStatus();
    if (sensorStatus == NULL) {
        HDF_LOGE("%{public}s: sensorStatus is failed\n", __func__);
        return DUMP_NULL_PTR;
    }

    for (index = 0; index < sensorList->sensorSum; index++) {
        ret = memset_s(sensorInfoDate, STRING_LEN, 0, STRING_LEN);
        if (ret != DUMP_SUCCESS) {
            HDF_LOGE("%{public}s: memset sensorInfoList is failed\n", __func__);
            return DUMP_FAILURE;
        }

        ret = sprintf_s(sensorInfoDate, STRING_LEN,
            "=================================================\n\r \
            sensorName: %s \n\r \
            sensorId: %d \n\r \
            sensorStatus: %d \n\r \
            maxRange: %f \n\r \
            accuracy: %f \n\r \
            power:    %f \n\r \
            minDelay: %" PRId64 "\n\r \
            maxDelay: %" PRId64 "\n\r \
            fifoMaxEventCount: %u \n\r",
            sensorList->sensorInfoEntry[index].sensorName,
            sensorList->sensorInfoEntry[index].sensorId,
            sensorStatus[sensorList->sensorInfoEntry[index].sensorId],
            sensorList->sensorInfoEntry[index].maxRange,
            sensorList->sensorInfoEntry[index].accuracy,
            sensorList->sensorInfoEntry[index].power,
            sensorList->sensorInfoEntry[index].minDelay,
            sensorList->sensorInfoEntry[index].maxDelay,
            sensorList->sensorInfoEntry[index].fifoMaxEventCount);
        if (ret < DUMP_SUCCESS) {
            HDF_LOGE("%{public}s: sprintf sensorList is failed\n", __func__);
            return DUMP_FAILURE;
        }

        (void)HdfSbufWriteString(reply, sensorInfoDate);
    }

    return DUMP_SUCCESS;
}

static void ShowData(const float *data, int64_t timesTamp, const struct SensorDevelopmentList sensorNode,
    struct HdfSBuf *reply)
{
    int32_t ret = 0;
    char sensorInfoDate[STRING_LEN] = { 0 };

    if (sensorNode.dataDimension == DATA_X) {
        ret = sprintf_s(sensorInfoDate, STRING_LEN,
            "sensor name :[%s], sensor id :[%d], ts=[%0.9f], data= [%f]\n\r",
            sensorNode.sensorName, sensorNode.sensorTypeId, timesTamp / 1e9, *(data));
        if (ret < DUMP_SUCCESS) {
            HDF_LOGE("%{public}s: sprintf sensorInfoDate is failed\n", __func__);
            return;
        }
    } else {
        ret = sprintf_s(sensorInfoDate, STRING_LEN,
            "sensor name :[%s], sensor id :[%d], ts=[%0.9f], data= [%f], [%f], [%f]\n\r",
            sensorNode.sensorName, sensorNode.sensorTypeId, timesTamp / 1e9, *(data), *(data + DATA_X),
            *(data + DATA_XY));
        if (ret < DUMP_SUCCESS) {
            HDF_LOGE("%{public}s: sprintf ShowData is failed\n", __func__);
            return;
        }
    }
    (void)HdfSbufWriteString(reply, sensorInfoDate);
}

int32_t SensorShowData(struct HdfSBuf *reply)
{
    int32_t len;
    int32_t ret = 0;
    struct SensorDatePack *eventDumpList;
    char sensorInfoDate[STRING_LEN] = { 0 };

    eventDumpList = GetEventData();

    ret = sprintf_s(sensorInfoDate, STRING_LEN, "======The last 10 data records======\n\r");
    if (ret < DUMP_SUCCESS) {
        HDF_LOGE("%{public}s: sprintf SensorShowData is failed\n", __func__);
        return DUMP_NULL_PTR;
    }
    (void)HdfSbufWriteString(reply, sensorInfoDate);

    if (eventDumpList->count < MAX_DUMP_DATA_SIZE) {
        for (len = 0; len < eventDumpList->count; len++) {
            float *data = (float *)(eventDumpList->listDumpArr[len].data);
            ShowData(data, eventDumpList->listDumpArr[len].timestamp,
                g_sensorList[eventDumpList->listDumpArr[len].sensorId], reply);
        }
    } else {
        int32_t pos = eventDumpList->pos;
        for (len = 0; len < eventDumpList->count; len++) {
            pos = pos + 1 > MAX_DUMP_DATA_SIZE ? 1 : pos + 1;
            float *data = (float *)(eventDumpList->listDumpArr[pos - 1].data);
            ShowData(data, eventDumpList->listDumpArr[pos - 1].timestamp,
                g_sensorList[eventDumpList->listDumpArr[pos - 1].sensorId], reply);
        }
    }

    return DUMP_SUCCESS;
}

static int32_t DevHostSensorDump(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint32_t argv = 0;

    if (data == NULL || reply == NULL) {
        HDF_LOGE("%{public}s data or reply is invalid", __func__);
        return HDF_FAILURE;
    }

    if (!HdfSbufReadUint32(data, &argv)) {
        HDF_LOGE("%{public}s: read &argv failed!", __func__);
        return DUMP_FAILURE;
    }

    if (argv == 0) {
        (void)HdfSbufWriteString(reply, g_helpComment);
        return HDF_SUCCESS;
    }

    for (uint32_t i = 0; i < argv; i++) {
        const char *value = HdfSbufReadString(data);
        if (value == NULL) {
            HDF_LOGE("%{public}s value is invalid", __func__);
            return HDF_FAILURE;
        }
        if (strcmp(value, "-h") == 0) {
            (void)HdfSbufWriteString(reply, g_helpComment);
            return HDF_SUCCESS;
        } else if (strcmp(value, "-l") == 0) {
            SensorShowList(reply);
            return HDF_SUCCESS;
        } else if (strcmp(value, "-d") == 0) {
            SensorShowData(reply);
            return HDF_SUCCESS;
        }
    }

    return HDF_SUCCESS;
}

void SensorDevRegisterDump(void)
{
    DevHostRegisterDumpHost(DevHostSensorDump);
}
