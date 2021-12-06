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
#include "usbd_function.h"

#include <hdf_sbuf.h>
#include <servmgr_hdi.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include "devmgr_hdi.h"
#include "hdf_log.h"
#include "hdf_remote_service.h"
#include "osal_time.h"
#include "securec.h"
#include "sys_param.h"

#define DEV_SERVICE_NAME "usbfn_master"
#define ACM_SERVICE_NAME "usbfn_cdcacm"
#define ECM_SERVICE_NAME "usbfn_cdcecm"

#define SYS_USB_FFS_READY "sys.usb.ffs.ready"
#define SYS_USB_CONFIGFS "sys.usb.configfs"
#define SYS_USB_CONFIG "sys.usb.config"
#define HDC_CONFIG_OFF "none"
#define HDC_CONFIG_ON "hdc"
#define HDC_CONFIGFS_OFF "0"
#define HDC_CONFIGFS_ON "1"

#define FUNCTION_ADD 1
#define FUNCTION_DEL 2

#define USB_INIT 100
#define USB_RELEASE 101
#define USB_ACM_OPEN 0
#define USB_ACM_CLOSE 1

#define USB_FUNCTION_ACM_ECM 3
#define FUNCTIONS_MAX 7

static uint8_t currentFuncs = USB_FUNCTION_NONE;
static uint8_t pre_acm_ecm;
static uint8_t WAIT_SLEEP_TIME = 10;

static int SendCmdToService(const char *name, int cmd, unsigned char funcMask)
{
    int status;
    struct HdfRemoteService *service = NULL;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    struct HDIServiceManager *servmgr = NULL;
    servmgr = HDIServiceManagerGet();
    if (servmgr == NULL) {
        HDF_LOGE("%{public}s:%{public}d HDIServiceManagerGet err\n", __func__, __LINE__);
        return HDF_FAILURE;
    }
    service = servmgr->GetService(servmgr, name);
    HDIServiceManagerRelease(servmgr);
    if (service == NULL) {
        HDF_LOGE("%{public}s:%{public}d GetService err\n", __func__, __LINE__);
        return HDF_FAILURE;
    }

    data = HdfSBufTypedObtain(SBUF_IPC);
    reply = HdfSBufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        HDF_LOGE("%{public}s:%{public}d data or reply err\n", __func__, __LINE__);
        status = HDF_FAILURE;
        HdfRemoteServiceRecycle(service);
        return status;
    }
    if (!HdfSbufWriteInt8(data, funcMask)) {
        HDF_LOGE("%{public}s:%{public}d HdfSbufWriteInt8 error\n", __func__, __LINE__);
        status = HDF_FAILURE;
        HdfSBufRecycle(data);
        HdfSBufRecycle(reply);
        HdfRemoteServiceRecycle(service);
        return status;
    }
    status = service->dispatcher->Dispatch(service, cmd, data, reply);
    if (status) {
        HDF_LOGE("%{public}s:%{public}d serice %{public}s dispatch cmd : %{public}d error\n", __func__, __LINE__, name,
                 cmd);
    }
    HdfSBufRecycle(data);
    HdfSBufRecycle(reply);
    HdfRemoteServiceRecycle(service);
    return status;
}

static int32_t RemoveHdc(int funcs)
{
    if (!(funcs & USB_FUNCTION_HDC)) {
        if (currentFuncs != funcs) {
            HDF_LOGI("%{public}s:%{public}d remove hdc\n", __func__, __LINE__);
            uint8_t status = SystemSetParameter(SYS_USB_CONFIG, HDC_CONFIG_OFF);
            if (status) {
                HDF_LOGE("%{public}s:%{public}d remove hdc config error = %{public}d\n", __func__, __LINE__, status);
                return HDF_FAILURE;
            }
            status = SystemSetParameter(SYS_USB_CONFIGFS, HDC_CONFIGFS_OFF);
            if (status) {
                HDF_LOGE("%{public}s:%{public}d remove hdc configs error = %{public}d\n", __func__, __LINE__, status);
                return HDF_FAILURE;
            }
        }
    }
    return HDF_SUCCESS;
}

int32_t AddHdc(int funcs)
{
    if (funcs & USB_FUNCTION_HDC) {
        HDF_LOGI("%{public}s:%{public}d add hdc\n", __func__, __LINE__);
        uint8_t status = SystemSetParameter(SYS_USB_CONFIGFS, HDC_CONFIGFS_ON);
        if (status) {
            HDF_LOGE("%{public}s:%{public}d add hdc configfs error = %{public}d\n", __func__, __LINE__, status);
            return HDF_FAILURE;
        }
        status = SystemSetParameter(SYS_USB_CONFIG, HDC_CONFIG_ON);
        if (status) {
            HDF_LOGE("%{public}s:%{public}d add hdc config error = %{public}d\n", __func__, __LINE__, status);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

int32_t ReleaseAcmEcm(uint8_t pre_acm_ecm)
{
    HDF_LOGI("%{public}s:%{public}d remove pre_acm_ecm = %{public}d \n", __func__, __LINE__, pre_acm_ecm);
    if (pre_acm_ecm & USB_FUNCTION_ACM) {
        uint8_t status = SendCmdToService(ACM_SERVICE_NAME, USB_RELEASE, pre_acm_ecm);
        if (status) {
            HDF_LOGE("%{public}s:%{public}d release acm error = %{public}d\n", __func__, __LINE__, status);
            return HDF_FAILURE;
        }
    }
    if (pre_acm_ecm & USB_FUNCTION_ECM) {
        uint8_t status = SendCmdToService(ECM_SERVICE_NAME, USB_RELEASE, pre_acm_ecm);
        if (status) {
            HDF_LOGE("%{public}s:%{public}d release ecm error = %{public}d\n", __func__, __LINE__, status);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

int32_t RemoveAcmEcm(uint8_t _acm_ecm)
{
    uint8_t status;
    if (_acm_ecm & USB_FUNCTION_ACM) {
        status = SendCmdToService(ACM_SERVICE_NAME, USB_INIT, _acm_ecm);
        if (status) {
            HDF_LOGE("%{public}s:%{public}d remove acm error = %{public}d\n", __func__, __LINE__, status);
            return HDF_FAILURE;
        }
    }
    if (_acm_ecm & USB_FUNCTION_ECM) {
        status = SendCmdToService(ECM_SERVICE_NAME, USB_INIT, _acm_ecm);
        if (status) {
            HDF_LOGE("%{public}s:%{public}d remove ecm error = %{public}d\n", __func__, __LINE__, status);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

int UsbdSetFunction(int funcs)
{
    uint8_t _acm_ecm = funcs & USB_FUNCTION_ACM_ECM;
    uint8_t status;
    if (funcs < 0 || funcs >= FUNCTIONS_MAX) {
        HDF_LOGI("%{public}s:%{public}d funcs invalid \n", __func__, __LINE__);
        return HDF_FAILURE;
    }
    if ((currentFuncs & USB_FUNCTION_HDC) || (funcs == 0)) {
        if (!(funcs & USB_FUNCTION_HDC)) {
            if (RemoveHdc(funcs)) {
                return HDF_FAILURE;
            }
        }
    } else {
        if (AddHdc(funcs)) {
            return HDF_FAILURE;
        }
    }
    if (pre_acm_ecm != _acm_ecm) {
        if ((pre_acm_ecm > 0) || (funcs == 0)) {
            if (ReleaseAcmEcm(pre_acm_ecm)) {
                return HDF_FAILURE;
            }
            status = SendCmdToService(DEV_SERVICE_NAME, FUNCTION_DEL, pre_acm_ecm);
            if (status) {
                HDF_LOGE("%{public}s:%{public}d remove device error = %{public}d\n", __func__, __LINE__, status);
                return HDF_FAILURE;
            }
        }
        if (_acm_ecm > 0) {
            HDF_LOGI("%{public}s:%{public}d add _acm_ecm = %{public}d\n", __func__, __LINE__, _acm_ecm);
            status = SendCmdToService(DEV_SERVICE_NAME, FUNCTION_ADD, _acm_ecm);
            if (status) {
                HDF_LOGE("%{public}s:%{public}d add device _acm_ecm:%{public}d error = %{public}d\n", __func__,
                         __LINE__, _acm_ecm, status);
                return HDF_FAILURE;
            }
            if (RemoveAcmEcm(_acm_ecm)) {
                return HDF_FAILURE;
            }
        }
    }
    OsalMSleep(WAIT_SLEEP_TIME);
    currentFuncs = funcs;
    pre_acm_ecm = _acm_ecm;
    return HDF_SUCCESS;
}

int32_t UsbdGetFunction(void)
{
    HDF_LOGI("%{public}s:%{public}d currentFuncs:%{public}d\n", __func__, __LINE__, currentFuncs);
    return currentFuncs;
}
