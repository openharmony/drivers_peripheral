/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "magnetic_mmc5617.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"
#include "sensor_magnetic_driver.h"

#define HDF_LOG_TAG    hdf_sensor_magnetic

#define MAX_RETRY_ATTEMPTS 5
#define BUFFER_NUM 2
#define GAUSS_THRESHOLD    10
#define SLEEP_DURATION_1MS    1
#define SLEEP_DURATION_8MS    8
#define SLEEP_DURATION_15MS    15

#define SHIFT_8BIT 8
#define MMC5617_REG_BYTE_OFFSET_0    0
#define MMC5617_REG_BYTE_OFFSET_1    1
#define MMC5617_REG_BYTE_OFFSET_2    2
#define MMC5617_REG_BYTE_OFFSET_3    3
#define MMC5617_REG_BYTE_OFFSET_4    4
#define MMC5617_REG_BYTE_OFFSET_5    5
#define X_INDEX    0
#define Y_INDEX    1
#define Z_INDEX    2
#define SENSOR_STATE_NORMAL    1
#define SENSOR_STATE_STANDBY    2
#define REG_COUNT    3
#define MID_POINT    128
#define SCALE_FACTOR    32
#define DIVISOR    5


static struct Mmc5617DrvData *g_mmc5617DrvData = NULL;

/* Indicate working mode of sensor */
static uint8_t g_sensorState = 1;
static uint16_t mmc56xx_sensitivity = 1024;
const int SLEEP_DURATION_MS = 8;

struct Mmc5617DrvData *Mmc5617GetDrvData(void)
{
    return g_mmc5617DrvData;
}

static int32_t ReadMmc5617RawData(struct SensorCfgData *data, struct MagneticData *rawData, uint64_t *timestamp)
{
    uint8_t regValue[6];
    int32_t raw_data[3];
    OsalTimespec time;
    int32_t ret;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    (void)memset_s(regValue, sizeof(regValue), 0, sizeof(regValue));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */

    /* Read 6 bytes of magnetic data from reg 0x00-0x05 */
    ret = ReadSensor(&data->busCfg, MMC5617_MAGNETIC_X_MSB_ADDR, regValue, sizeof(regValue));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 read data failed", __func__);
        return HDF_FAILURE;
    }

    /* Combine MSB and LSB, then subtract offset (32768 for 16-bit mode) */
    raw_data[X_INDEX] = (int32_t)(((regValue[MMC5617_REG_BYTE_OFFSET_0] << SHIFT_8BIT) |
                                	regValue[MMC5617_REG_BYTE_OFFSET_1]) - MMC5617_16BIT_OFFSET);
    raw_data[Y_INDEX] = (int32_t)(((regValue[MMC5617_REG_BYTE_OFFSET_2] << SHIFT_8BIT) |
    	                            regValue[MMC5617_REG_BYTE_OFFSET_3]) - MMC5617_16BIT_OFFSET);
    raw_data[Z_INDEX] = (int32_t)(((regValue[MMC5617_REG_BYTE_OFFSET_4] << SHIFT_8BIT) |
	                                regValue[MMC5617_REG_BYTE_OFFSET_5]) - MMC5617_16BIT_OFFSET);
    HDF_LOGI("%s: raw_data (%d, %d, %d)", __func__, raw_data[X_INDEX], raw_data[Y_INDEX], raw_data[Z_INDEX]);

    /* Remap data based on sensor direction configuration */
    ret = SensorRawDataToRemapData(data->direction, (int32_t *)raw_data, MAGNETIC_AXIS_NUM);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 remap data failed", __func__);
        return HDF_FAILURE;
    }

    rawData->x = raw_data[X_INDEX];
    rawData->y = raw_data[Y_INDEX];
    rawData->z = raw_data[Z_INDEX];

    return HDF_SUCCESS;
}

int32_t ReadMmc5617Data(struct SensorCfgData *data)
{
    struct MagneticData rawData = { 0, 0, 0 };
    struct SensorReportEvent event;
    int32_t tmp[MAGNETIC_AXIS_NUM];

    (void)memset_s(&event, sizeof(event), 0, sizeof(event));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    int32_t ret = ReadMmc5617RawData(data, &rawData, &event.timestamp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 read raw data failed", __func__);
        return HDF_FAILURE;
    }

    event.sensorId = SENSOR_TAG_MAGNETIC_FIELD;
    event.option = 0;
    event.mode = SENSOR_WORK_MODE_REALTIME;

    tmp[MAGNETIC_X_AXIS] = rawData.x;
    tmp[MAGNETIC_Y_AXIS] = rawData.y;
    tmp[MAGNETIC_Z_AXIS] = rawData.z;
    HDF_LOGI("%s: tmp x=%d y=%d z=%d", __func__, tmp[MAGNETIC_X_AXIS], tmp[MAGNETIC_Y_AXIS], tmp[MAGNETIC_Z_AXIS]);

    /* Auto switch between continuous mode and single mode based on magnetic field strength */
    ret = Mmc56xxAutoSwitch(data, tmp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 auto switch failed", __func__);
    }

    event.dataLen = sizeof(int32_t) * MAGNETIC_AXIS_NUM;
    event.data = (uint8_t *)tmp;
    ret = ReportSensorEvent(&event);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 report data failed", __func__);
    }

    return ret;
}

static int32_t Mmc56xxAutoSelftestConfiguration(struct SensorCfgData *data)
{
    int32_t ret;
    uint8_t regValue[MAGNETIC_AXIS_NUM];
    uint8_t writeBuffer[BUFFER_NUM];
    int i;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    /* Read trim data from reg 0x27-0x29 */
    ret = ReadSensor(&data->busCfg, 0x27, regValue, sizeof(regValue));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 read ST VALUE failed", __func__);
        return HDF_FAILURE;
    }

    /* Calculate and write threshold to reg 0x1E-0x20 */
    for (i = 0; i < REG_COUNT; i++) {
        int16_t stThrData = (int16_t)(regValue[i] - MID_POINT) * SCALE_FACTOR;
        if (stThrData < 0) {
            stThrData = -stThrData;
        }
        int16_t stThrNew = stThrData - stThrData / DIVISOR;
        int16_t stThd = stThrNew / 8;
        uint8_t stThdReg = (stThd > 255) ? 0xFF : (uint8_t)stThd;

        writeBuffer[0] = 0x1E + i;
        writeBuffer[1] = stThdReg;
        ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: MMC5617 write REG %d THRESHOLD failed", __func__, i);
            return HDF_FAILURE;
        }
        uint8_t readBack;
        ret = ReadSensor(&data->busCfg, writeBuffer[0], &readBack, 1);
        if (ret == HDF_SUCCESS) {
            HDF_LOGI("%s: Read back reg 0x%02X value=0x%02X", __func__, writeBuffer[0], readBack);
        } else {
            HDF_LOGE("%s: Failed to read back reg 0x%02X", __func__, writeBuffer[0]);
        }
    }

    return HDF_SUCCESS;
}

static int32_t Mmc56xxSetOperation(struct SensorCfgData *data)
{
    int32_t ret;
    uint8_t writeBuffer[2];

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    /* Write 0x08 to register 0x1B to do SET operation */
    writeBuffer[0] = 0x1B;
    writeBuffer[1] = 0x08;
    ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 SET failed", __func__);
        return HDF_FAILURE;
    }
    OsalMSleep(SLEEP_DURATION_1MS);

    return HDF_SUCCESS;
}

static int32_t Mmc56xxContinuousModeWithAuto_Sr(struct SensorCfgData *data)
{
    int32_t ret;
    uint8_t writeBuffer[2];

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    /* Write reg 0x1C, Set BW<1:0> = 0x01 */
    writeBuffer[0] = 0x1C;
    writeBuffer[1] = 0x01;
    ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 Continuous Mode reg 0x1C failed", __func__);
        return HDF_FAILURE;
    }

    /* Write reg 0x1A, set ODR = 120 (0x78) */
    writeBuffer[0] = 0x1A;
    writeBuffer[1] = 0x78;
    ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 Continuous Mode reg 0x1A failed", __func__);
        return HDF_FAILURE;
    }

    /* Write reg 0x1B, set CMM_FREQ_EN and AUTO_SR_EN (0xA0) */
    writeBuffer[0] = 0x1B;
    writeBuffer[1] = 0xA0;
    ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 Continuous Mode reg 0x1B failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t Mmc56xxAutoSelfTest(struct SensorCfgData *data)
{
    int32_t ret;
    uint8_t writeBuffer[2];
    uint8_t regValue;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    /* Write 0x40 to register 0x1B, set Auto_st_en bit high */
    writeBuffer[0] = MMC5617_REG_CTRL0;
    writeBuffer[1] = MMC5617_CMD_AUTO_ST;
    ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 auto selftest failed", __func__);
        return HDF_FAILURE;
    }
    OsalMSleep(SLEEP_DURATION_15MS); /* Delay 15ms to finish the selftest process */

    /* Read register 0x18, check Sat_sensor bit */
    ret = ReadSensor(&data->busCfg, MMC5617_REG_STATUS1, &regValue, 1);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 read STATUS1 failed", __func__);
        return HDF_FAILURE;
    }

    if ((regValue & MMC5617_SAT_SENSOR)) {
        HDF_LOGE("%s: MMC5617 sensor is saturated", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

/*********************************************************************************
* description: Saturation checking - periodically run selftest to detect saturation
*********************************************************************************/
static int32_t Mmc56xxSaturationChecking(struct SensorCfgData *data)
{
    int32_t ret;
    uint8_t writeBuffer[2];
    /* If sampling rate is 50Hz, then do saturation checking every 250 loops, i.e. 5 seconds */
    static int gSamplesNum = 250;
    static int gCountNum = 0;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if ((gCountNum++) >= gSamplesNum) {
        gCountNum = 0;

        ret = Mmc56xxAutoSelfTest(data);
        if (ret != HDF_SUCCESS) {
            /* Sensor is saturated, need to do SET operation */
            HDF_LOGI("%s: Sensor saturated, doing SET operation", __func__);
            ret = Mmc56xxSetOperation(data);
            if (ret != HDF_SUCCESS) {
                HDF_LOGE("%s: MMC5617 SET operation failed", __func__);
                return ret;
            }
        }

        /* Do TM_M after selftest operation */
        writeBuffer[0] = MMC5617_REG_CTRL0;
        writeBuffer[1] = MMC5617_CMD_TMM;
        ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: MMC5617 TM_M after selftest operation failed", __func__);
            return ret;
        }
        OsalMSleep(SLEEP_DURATION_8MS); /* Delay 8ms to finish the TM_M operation */
    }

    return HDF_SUCCESS;
}

static int32_t WriteSensorRegister(struct SensorCfgData *data, uint8_t reg, uint8_t value)
{
    uint8_t writeBuffer[2] = {reg, value};
    return WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
}

static int32_t CheckAndSwitchToSingleMode(struct SensorCfgData *data, int32_t mag_out[3])
{
    uint8_t writeBuffer[2];
    int32_t ret;
    
    /* If X or Y axis output exceed 10 Gauss, then switch to single mode */
    if ((abs(mag_out[X_INDEX]) > GAUSS_THRESHOLD * mmc56xx_sensitivity) ||
        (abs(mag_out[Y_INDEX]) > GAUSS_THRESHOLD * mmc56xx_sensitivity)) {
        g_sensorState = SENSOR_STATE_STANDBY;

        /* Disable continuous mode */
        writeBuffer[0] = MMC56XX_ENABLE_REG;
        writeBuffer[1] = MMC56XX_DISABLE_VALUE;
        ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: MMC5617 disable continuous mode failed", __func__);
            return ret;
        }
        OsalMSleep(SLEEP_DURATION_15MS);

        /* Do SET operation */
        ret = Mmc56xxSetOperation(data);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: MMC5617 SET operation failed", __func__);
            return ret;
        }
        OsalMSleep(SLEEP_DURATION_1MS);

        /* Do TM_M before next data reading */
        writeBuffer[0] = MMC5617_REG_CTRL0;
        writeBuffer[1] = MMC56XX_ENABLE_VALUE;
        ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: MMC5617 CTRL0 TMM failed", __func__);
            return ret;
        }
        OsalMSleep(SLEEP_DURATION_8MS);
    }
    
    return HDF_SUCCESS;
}

static int32_t CheckAndSwitchToContinuousMode(struct SensorCfgData *data, int32_t mag_out[3])
{
    uint8_t writeBuffer[2];
    int32_t ret;
    
    /* If both of X and Y axis output less than 8 Gauss, then switch to continuous mode with Auto_SR */
    if ((abs(mag_out[X_INDEX]) < SHIFT_8BIT * mmc56xx_sensitivity) &&
        (abs(mag_out[Y_INDEX]) < SHIFT_8BIT * mmc56xx_sensitivity)) {
        g_sensorState = SENSOR_STATE_NORMAL;

        /* Enable continuous mode with Auto_SR */
        writeBuffer[0] = MMC5617_REG_CTRL0;
        writeBuffer[1] = MMC56XX_VAL_ATUO_SR;
        ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: MMC5617 CTRL0 AUTO_SR failed", __func__);
            return ret;
        }

        writeBuffer[0] = MMC56XX_ENABLE_REG;
        writeBuffer[1] = MMC56XX_ENABLE_VALUE;
        ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: MMC5617 CTRL2 CMM_EN failed", __func__);
            return ret;
        }
        
        return HDF_SUCCESS;
    }
    
    return HDF_FAILURE;
}

static int32_t HandleStandbyModeOperation(struct SensorCfgData *data)
{
    uint8_t writeBuffer[2];
    int32_t ret;
    
    /* Sensor checking */
    ret = Mmc56xxSaturationChecking(data);
    if (ret == HDF_SUCCESS) {
        /* Do TM_M before next data reading */
        writeBuffer[0] = MMC5617_REG_CTRL0;
        writeBuffer[1] = MMC5617_CMD_TMM;
        ret = WriteSensor(&data->busCfg, writeBuffer, sizeof(writeBuffer));
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: MMC5617 CTRL0 TMM failed", __func__);
            return ret;
        }
        OsalMSleep(SLEEP_DURATION_8MS);
    }
    
    return HDF_SUCCESS;
}

/*********************************************************************************
* description: Auto switch the working mode between Auto_SR and SETonly
*********************************************************************************/
static int32_t Mmc56xxAutoSwitch(struct SensorCfgData *data, int32_t mag[3])
{
    int32_t ret;
    int32_t mag_out[3];

    mag_out[X_INDEX] = mag[X_INDEX];
    mag_out[Y_INDEX] = mag[Y_INDEX];
    mag_out[Z_INDEX] = mag[Z_INDEX];

    if (g_sensorState == SENSOR_STATE_NORMAL) {
        ret = CheckAndSwitchToSingleMode(data, mag_out);
        if (ret != HDF_SUCCESS) {
            return ret;
        }
    } else if (g_sensorState == SENSOR_STATE_STANDBY) {
        ret = CheckAndSwitchToContinuousMode(data, mag_out);
        if (ret == HDF_FAILURE) {
            ret = HandleStandbyModeOperation(data);
            if (ret != HDF_SUCCESS) {
                return ret;
            }
        } else if (ret != HDF_SUCCESS) {
            return ret;
        }
    }

    return HDF_SUCCESS;
}

static int32_t InitMmc5617(struct SensorCfgData *data)
{
    int32_t ret;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    ret = Mmc56xxAutoSelftestConfiguration(data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 SelfTest Configuration failed", __func__);
        return HDF_FAILURE;
    }

    ret = Mmc56xxSetOperation(data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 SET failed", __func__);
        return HDF_FAILURE;
    }

    ret = Mmc56xxContinuousModeWithAuto_Sr(data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 Continuous Mode failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t DispatchMmc5617(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

int32_t Mmc5617BindDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct Mmc5617DrvData *drvData = (struct Mmc5617DrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc Mmc5617 drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchMmc5617;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_mmc5617DrvData = drvData;

    return HDF_SUCCESS;
}

int32_t Mmc5617InitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct MagneticOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Mmc5617DrvData *drvData = (struct Mmc5617DrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = MagneticCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating magneticcfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadMmc5617Data;
    ret = MagneticRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register MMC5617 magnetic failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitMmc5617(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init MMC5617 magnetic failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void Mmc5617ReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Mmc5617DrvData *drvData = (struct Mmc5617DrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        MagneticReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_magneticMmc5617DevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_MAGNETIC_MMC5617",
    .Bind = Mmc5617BindDriver,
    .Init = Mmc5617InitDriver,
    .Release = Mmc5617ReleaseDriver,
};

HDF_INIT(g_magneticMmc5617DevEntry);
