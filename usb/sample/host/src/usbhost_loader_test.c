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

#include <hdf_sbuf.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "hdf_log.h"
#include "hdf_usb_pnp_manage.h"

#define HDF_LOG_TAG                    USB_HOST_PNP_TEST
#define USB_HOST_PNP_TEST_SERVICE_NAME "hdf_usb_pnp_notify_service"
#define USB_TEST_SAMPLE_MODULE_NAME    "usb_test_sample_driver"
#define USB_TEST_SAMPLE_SERVICE_NAME   "usb_test_sample_service"
#define STR_LEN                        1024
#define USB_TEST_INTERFACE_NUM         2

#ifndef INT32_MAX
#define INT32_MAX 0x7fffffff
#endif

static int32_t UsbPnpTestEventReceived(void *priv, uint32_t id, struct HdfSBuf *data)
{
    (void)priv;
    (void)data;
    int32_t ret = HDF_ERR_INVALID_PARAM;
    HDF_LOGI("%{public}s:%{public}d id is %{public}u", __func__, __LINE__, id);
    return ret;
}

int32_t main(int32_t argc, char *argv[])
{
    (void)argc;
    (void)argv;
    struct HdfSBuf *data;
    struct HdfSBuf *reply;
    struct HdfIoService *testService = NULL;
    static struct HdfDevEventlistener usbPnpTestListener = {
        .callBack = UsbPnpTestEventReceived,
    };

    struct HdfIoService *serv = HdfIoServiceBind(USB_HOST_PNP_TEST_SERVICE_NAME);
    if (serv == NULL) {
        HDF_LOGE("%{public}s: fail to get service %{public}s", __func__, USB_HOST_PNP_TEST_SERVICE_NAME);
        return HDF_FAILURE;
    }

    if (HdfDeviceRegisterEventListener(serv, &usbPnpTestListener) != HDF_SUCCESS) {
        HdfIoServiceRecycle(serv);
        HDF_LOGE("HdfDeviceRegisterEventListener failed");
        return HDF_FAILURE;
    }

    data = HdfSbufObtainDefaultSize();
    reply = HdfSbufObtainDefaultSize();
    if (data == NULL || reply == NULL) {
        HdfIoServiceRecycle(serv);
        HDF_LOGE("%{public}s: GetService err", __func__);
        return HDF_FAILURE;
    }

    HdfSbufWriteString(data, USB_TEST_SAMPLE_MODULE_NAME);
    HdfSbufWriteString(data, USB_TEST_SAMPLE_SERVICE_NAME);

    if (serv->dispatcher->Dispatch(&serv->object, USB_PNP_DRIVER_REGISTER_DEVICE, data, NULL) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Dispatch pnp register device err", __func__);
        goto OUT;
    }

    testService = HdfIoServiceBind(USB_TEST_SAMPLE_SERVICE_NAME);
    if (testService == NULL) {
        HDF_LOGE("%{public}s: HdfIoServiceBind err", __func__);
        goto OUT;
    }

    if (serv->dispatcher->Dispatch(&serv->object, USB_PNP_DRIVER_UNREGISTER_DEVICE, data, NULL) != HDF_SUCCESS) {
        HdfIoServiceRecycle(testService);
        HDF_LOGE("%{public}s: Dispatch pnp unregister device err", __func__);
        goto OUT;
    }
    return HDF_SUCCESS;
OUT:
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    HdfIoServiceRecycle(serv);
    return HDF_FAILURE;
}
