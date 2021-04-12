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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/ioctl.h>
#include <securec.h>

#include "hdf_io_service_if.h"

#include "input_common.h"
#include "input_manager.h"

#define DEVICE_NODE_PATH "/dev/input/event"
#define DEVICE_NODE_USB_PATH "/dev/usb/uhid"
#define TOUCH_INDEX 1

static InputDevManager *g_devManager;
int32_t InstanceReporterHdi(InputReporter **hdi);
int32_t InstanceControllerHdi(InputController **hdi);

InputDevManager *GetDevManager(void)
{
    return g_devManager;
}

static int32_t GetInputDevice(uint32_t devIndex, DeviceInfo **devInfo)
{
    DeviceInfoNode *pos = NULL;
    DeviceInfoNode *next = NULL;
    InputDevManager *manager = NULL;

    if (devIndex >= MAX_INPUT_DEV_NUM || devInfo == NULL) {
        HDF_LOGE("%s: invalid param", __func__);
        return INPUT_INVALID_PARAM;
    }
    GET_MANAGER_CHECK_RETURN(manager);

    pthread_mutex_lock(&manager->mutex);
    DLIST_FOR_EACH_ENTRY_SAFE(pos, next, &manager->devList, DeviceInfoNode, node) {
        if (pos->payload.devIndex != devIndex) {
            continue;
        }
        *devInfo = &pos->payload;
        HDF_LOGI("%s: device%u get info succ", __func__, devIndex);
        pthread_mutex_unlock(&manager->mutex);
        return INPUT_SUCCESS;
    }

    HDF_LOGE("%s: device%u doesn't exist, can't get device info", __func__, devIndex);
    pthread_mutex_unlock(&manager->mutex);
    return INPUT_FAILURE;
}

static int32_t GetInputDeviceList(uint32_t *devNum, DeviceInfo **deviceList, uint32_t size)
{
    DeviceInfoNode *pos = NULL;
    DeviceInfoNode *next = NULL;
    InputDevManager *manager = NULL;
    uint32_t tempSize = 0;
    DeviceInfo **tempList = NULL;

    if (devNum == NULL || deviceList == NULL) {
        HDF_LOGE("%s: invalid param", __func__);
        return INPUT_INVALID_PARAM;
    }
    tempList = deviceList;
    GET_MANAGER_CHECK_RETURN(manager);

    pthread_mutex_lock(&manager->mutex);
    DLIST_FOR_EACH_ENTRY_SAFE(pos, next, &manager->devList, DeviceInfoNode, node) {
        if (tempSize >= size) {
            *devNum = manager->currentDevNum;
            HDF_LOGE("%s: size is not enough, size = %u, devNum = %u", __func__,
                size, *devNum);
            pthread_mutex_unlock(&manager->mutex);
            return INPUT_FAILURE;
        }
        *tempList = &pos->payload;
        tempList++;
        tempSize++;
    }
    *devNum = manager->currentDevNum;
    pthread_mutex_unlock(&manager->mutex);
    return INPUT_SUCCESS;
}

static int32_t CloseInputDevice(uint32_t devIndex)
{
    DeviceInfoNode *pos = NULL;
    DeviceInfoNode *next = NULL;
    InputDevManager *manager = NULL;

    GET_MANAGER_CHECK_RETURN(manager);

    pthread_mutex_lock(&manager->mutex);
    DLIST_FOR_EACH_ENTRY_SAFE(pos, next, &manager->devList, DeviceInfoNode, node) {
        if (pos->payload.devIndex != devIndex) {
            continue;
        }
        HdfIoServiceRecycle((struct HdfIoService *)pos->payload.service);
        DListRemove(&pos->node);
        free(pos);
        manager->currentDevNum--;
        pthread_mutex_unlock(&manager->mutex);
        return INPUT_SUCCESS;
    }

    HDF_LOGE("%s: device%u doesn't exist", __func__, devIndex);
    pthread_mutex_unlock(&manager->mutex);
    return INPUT_FAILURE;
}

static int32_t AddService(const uint32_t index, const struct HdfIoService *service)
{
    InputDevManager *manager = NULL;
    DeviceInfoNode *device = (DeviceInfoNode *)malloc(sizeof(DeviceInfoNode));

    if (device == NULL) {
        HDF_LOGE("%s: malloc fail", __func__);
        return INPUT_NOMEM;
    }
    (void)memset_s(device, sizeof(DeviceInfoNode), 0, sizeof(DeviceInfoNode));

    device->payload.devIndex = index;
    device->payload.service = (void *)service;
    GET_MANAGER_CHECK_RETURN(manager);
    pthread_mutex_lock(&manager->mutex);
    DListInsertTail(&device->node, &manager->devList);
    manager->currentDevNum++;
    pthread_mutex_unlock(&manager->mutex);
    return INPUT_SUCCESS;
}

static int32_t CheckIndex(uint32_t devIndex)
{
    DeviceInfoNode *pos = NULL;
    DeviceInfoNode *next = NULL;
    InputDevManager *manager = NULL;

    if (devIndex >= MAX_INPUT_DEV_NUM) {
        HDF_LOGE("%s: invalid param", __func__);
        return INPUT_INVALID_PARAM;
    }

    GET_MANAGER_CHECK_RETURN(manager);
    pthread_mutex_lock(&manager->mutex);
    DLIST_FOR_EACH_ENTRY_SAFE(pos, next, &manager->devList, DeviceInfoNode, node) {
        if (pos->payload.devIndex == devIndex) {
            HDF_LOGE("%s: the device%u has existed", __func__, devIndex);
            pthread_mutex_unlock(&manager->mutex);
            return INPUT_FAILURE;
        }
    }
    pthread_mutex_unlock(&manager->mutex);
    return INPUT_SUCCESS;
}

static int32_t OpenInputDevice(uint32_t devIndex)
{
    int32_t ret;
    struct HdfIoService *service = NULL;
    char serviceName[SERVICE_NAME_LEN] = {0};

    if (CheckIndex(devIndex) != INPUT_SUCCESS) {
        return INPUT_FAILURE;
    }

    ret = snprintf_s(serviceName, SERVICE_NAME_LEN, strlen("event") + 1, "%s%u", "event", devIndex);
    if (ret == -1) {
        HDF_LOGE("%s: snprintf_s fail", __func__);
        return INPUT_FAILURE;
    }

    service = HdfIoServiceBind(serviceName);
    if (service == NULL) {
        HDF_LOGE("%s: fail to get io service: %s", __func__, serviceName);
        return INPUT_NULL_PTR;
    }

    if (AddService(devIndex, service) < 0) {
        HDF_LOGE("%s: add device%d failed", __func__, devIndex);
        HdfIoServiceRecycle(service);
        return INPUT_FAILURE;
    }

    HDF_LOGI("%s: open dev%d succ, service name = %s", __func__, devIndex, serviceName);
    return INPUT_SUCCESS;
}

static int32_t InstanceManagerHdi(InputManager **manager)
{
    InputManager *managerHdi = (InputManager *)malloc(sizeof(InputManager));
    if (managerHdi == NULL) {
        HDF_LOGE("%s: malloc fail", __func__);
        return INPUT_NOMEM;
    }

    (void)memset_s(managerHdi, sizeof(InputManager), 0, sizeof(InputManager));

    managerHdi->OpenInputDevice = OpenInputDevice;
    managerHdi->CloseInputDevice = CloseInputDevice;
    managerHdi->GetInputDevice = GetInputDevice;
    managerHdi->GetInputDeviceList = GetInputDeviceList;
    *manager = managerHdi;
    return INPUT_SUCCESS;
}

static int32_t InitDevManager(void)
{
    InputDevManager *manager = (InputDevManager *)malloc(sizeof(InputDevManager));
    if (manager == NULL) {
        HDF_LOGE("%s: malloc fail", __func__);
        return INPUT_NOMEM;
    }

    (void)memset_s(manager, sizeof(InputDevManager), 0, sizeof(InputDevManager));
    DListHeadInit(&manager->devList);
    pthread_mutex_init(&manager->mutex, NULL);
    manager->callbackNum = 0;
    g_devManager = manager;
    return INPUT_SUCCESS;
}

static void FreeInputHdi(IInputInterface *hdi)
{
    if (hdi->iInputManager != NULL) {
        free(hdi->iInputManager);
        hdi->iInputManager = NULL;
    }

    if (hdi->iInputController != NULL) {
        free(hdi->iInputController);
        hdi->iInputController = NULL;
    }

    if (hdi->iInputReporter != NULL) {
        free(hdi->iInputReporter);
        hdi->iInputReporter = NULL;
    }
    free(hdi);
}

static IInputInterface *InstanceInputHdi(void)
{
    int32_t ret;
    IInputInterface *hdi = (IInputInterface *)malloc(sizeof(IInputInterface));
    if (hdi == NULL) {
        HDF_LOGE("%s: malloc fail", __func__);
        return NULL;
    }
    (void)memset_s(hdi, sizeof(IInputInterface), 0, sizeof(IInputInterface));

    ret = InstanceManagerHdi(&hdi->iInputManager);
    if (ret != INPUT_SUCCESS) {
        FreeInputHdi(hdi);
        return NULL;
    }

    ret = InstanceControllerHdi(&hdi->iInputController);
    if (ret != INPUT_SUCCESS) {
        FreeInputHdi(hdi);
        return NULL;
    }

    ret = InstanceReporterHdi(&hdi->iInputReporter);
    if (ret != INPUT_SUCCESS) {
        FreeInputHdi(hdi);
        return NULL;
    }
    return hdi;
}

int32_t GetInputInterface(IInputInterface **inputInterface)
{
    int32_t ret;
    IInputInterface *inputHdi = NULL;

    if (inputInterface == NULL) {
        HDF_LOGE("%s: parameter is null", __func__);
        return INPUT_INVALID_PARAM;
    }

    inputHdi = InstanceInputHdi();
    if (inputHdi == NULL) {
        HDF_LOGE("%s: failed to instance hdi", __func__);
        return INPUT_NULL_PTR;
    }

    ret = InitDevManager();
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: failed to initialze manager", __func__);
        FreeInputHdi(inputHdi);
        return INPUT_FAILURE;
    }

    *inputInterface = inputHdi;
    HDF_LOGI("%s: exit succ", __func__);
    return INPUT_SUCCESS;
}
