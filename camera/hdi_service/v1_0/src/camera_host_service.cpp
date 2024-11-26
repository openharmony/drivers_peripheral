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

#include <dlfcn.h>
#include <algorithm>
#include "camera_host_service.h"
#include "camera_device_service.h"
#include "v1_0/icamera_device.h"
#include "camera_host_service_callback.h"
#include "camera_device_service_callback.h"
#include "camera_hal_hisysevent.h"

namespace OHOS::Camera {
OHOS::sptr<CameraHostService> CameraHostService::cameraHostService_ = nullptr;

extern "C" ICameraHost *CameraHostServiceGetInstance(void)
{
    OHOS::sptr<CameraHostService> service = CameraHostService::GetInstance();
    if (service == nullptr) {
        CAMERA_LOGE("Camera host service is nullptr");
        return nullptr;
    }

    return service.GetRefPtr();
}

int32_t CameraHostService::GetVdiLibList(std::vector<std::string> &vdiLibList)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:GetVdiLibList");
    std::vector<std::string>().swap(vdiLibList);
    ReleaseHcsTree();
    const struct DeviceResourceIface *pDevResIns = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (pDevResIns == nullptr) {
        CAMERA_LOGE("get hcs interface failed.");
        return OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT;
    }

    SetHcsBlobPath(CONFIG_PATH_NAME);
    const struct DeviceResourceNode *pRootNode = pDevResIns->GetRootNode();
    if (pRootNode == nullptr) {
        CAMERA_LOGE("GetRootNode failed");
        return OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT;
    }
    if (pRootNode->name != nullptr) {
        CAMERA_LOGI("pRootNode = %{public}s", pRootNode->name);
    }

    const char *vdiLib = nullptr;
    int32_t elemNum = pDevResIns->GetElemNum(pRootNode, "vdiLibList");
    for (int i = 0; i < elemNum; i++) {
        pDevResIns->GetStringArrayElem(pRootNode, "vdiLibList", i, &vdiLib, nullptr);
        if (vdiLib == nullptr) {
            CAMERA_LOGE("Get vdi lib list failed");
            return OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT;
        }
        vdiLibList.push_back(std::string(vdiLib));
    }

    if (vdiLibList.size() == 0) {
        CAMERA_LOGE("Vdi library list is empty");
        return OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT;
    }

    return OHOS::HDI::Camera::V1_0::NO_ERROR;
}

void CameraHostService::HdfCloseVdiLoaderList(std::vector<struct HdfVdiObject *> &cameraHostVdiLoaderList)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:HdfCloseVdiLoaderList");
    for (auto cameraHostVdiLoader : cameraHostVdiLoaderList) {
        if (cameraHostVdiLoader != nullptr) {
            HdfCloseVdi(cameraHostVdiLoader);
            cameraHostVdiLoader = nullptr;
        }
    }
    std::vector<struct HdfVdiObject *>().swap(cameraHostVdiLoaderList);
}

OHOS::sptr<CameraHostService> CameraHostService::GetInstance()
{
    if (cameraHostService_ != nullptr) {
        return cameraHostService_;
    }
    std::vector<std::string> vdiLibList;
    if (GetVdiLibList(vdiLibList) != OHOS::HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("Can not get vdi lib name");
        return nullptr;
    }
    std::vector<ICameraHostVdi*> cameraHostVdiList;
    std::vector<struct HdfVdiObject *> cameraHostVdiLoaderList;
    for (auto vdiLib : vdiLibList) {
        struct HdfVdiObject *cameraHostVdiLoader = HdfLoadVdi(vdiLib.c_str());
        if (cameraHostVdiLoader == nullptr || cameraHostVdiLoader->vdiBase == nullptr) {
            CAMERA_LOGE("Hdf load camera host vdi failed!");
            return nullptr;
        }
        uint32_t version = HdfGetVdiVersion(cameraHostVdiLoader);
        if (version != 1) {
            HdfCloseVdi(cameraHostVdiLoader);
            HdfCloseVdiLoaderList(cameraHostVdiLoaderList);
            CAMERA_LOGE("Get camera host vdi version failed!");
            return nullptr;
        }
        struct VdiWrapperCameraHost *vdiWrapper = reinterpret_cast<struct VdiWrapperCameraHost *>(
            cameraHostVdiLoader->vdiBase);
        if (vdiWrapper->module == nullptr) {
            HdfCloseVdi(cameraHostVdiLoader);
            HdfCloseVdiLoaderList(cameraHostVdiLoaderList);
            CAMERA_LOGE("Hdf load camera host vdi failed, module is nullptr!");
            return nullptr;
        }
        ICameraHostVdi *cameraHostVdi = reinterpret_cast<ICameraHostVdi *>(vdiWrapper->module);
        cameraHostVdiList.push_back(cameraHostVdi);
        cameraHostVdiLoaderList.push_back(cameraHostVdiLoader);
    }
    cameraHostService_ = new (std::nothrow) CameraHostService(cameraHostVdiList, cameraHostVdiLoaderList);
    if (cameraHostService_ == nullptr) {
        CAMERA_LOGE("Camera host service is nullptr");
        HdfCloseVdiLoaderList(cameraHostVdiLoaderList);
        return nullptr;
    }

    return cameraHostService_;
}

CameraHostService::CameraHostService(std::vector<ICameraHostVdi*> cameraHostVdiList,
    std::vector<struct HdfVdiObject *> cameraHostVdiLoaderList)
    : cameraHostVdiList_(cameraHostVdiList), cameraHostVdiLoaderList_(cameraHostVdiLoaderList)
{
    CAMERA_LOGD("ctor, instance");
}

CameraHostService::~CameraHostService()
{
    HdfCloseVdiLoaderList(cameraHostVdiLoaderList_);
    CAMERA_LOGD("dtor, instance");
}

int32_t CameraHostService::SetCallback(const OHOS::sptr<ICameraHostCallback> &callbackObj)
{
    for (auto cameraHostVdi : cameraHostVdiList_) {
        CHECK_IF_PTR_NULL_RETURN_VALUE(cameraHostVdi, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
        OHOS::sptr<ICameraHostVdiCallback> vdiCallbackObj = new CameraHostServiceCallback(callbackObj,
            cameraHostVdi, cameraIdInfoList_);
        if (vdiCallbackObj == nullptr) {
            CAMERA_LOGE("Camera host service set callback failed, vdiCallbackObj is nullptr");
            return OHOS::HDI::Camera::V1_0::INSUFFICIENT_RESOURCES;
        }
        int32_t ret = cameraHostVdi->SetCallback(vdiCallbackObj);
        if (ret != OHOS::HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGE("Camera host service set callback failed");
            return ret;
        }
    }

    return OHOS::HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraHostService::GetCameraIds(std::vector<std::string> &cameraIds)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:GetCameraIds");
    std::vector<std::string>().swap(cameraIds);
    if (cameraIdInfoList_.size() == 0) {
        int32_t ret = UpdateCameraIdMapList();
        if (ret != OHOS::HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGE("Camera get cameraIds failed");
            return ret;
        }
    }
    for (auto cameraIdInfo : cameraIdInfoList_) {
        if (cameraIdInfo.isDeleted == false) {
            cameraIds.push_back(cameraIdInfo.currentCameraId);
        }
    }

    return OHOS::HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraHostService::GetCameraAbility(const std::string &cameraId,
    std::vector<uint8_t> &cameraAbility)
{
    ICameraHostVdi* cameraHostVdi = GetCameraHostVdi(cameraId);
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraHostVdi, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);

    std::string vdiCameraId = GetVendorCameraId(cameraId);
    if (vdiCameraId == "") {
        CAMERA_LOGE("Get vendor camera id failed");
        return OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT;
    }

    return cameraHostVdi->GetCameraAbility(vdiCameraId, cameraAbility);
}

int32_t CameraHostService::OpenCamera(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
    sptr<ICameraDevice> &device)
{
    CAMERAHALPERFSYSEVENT(TIME_FOR_OPEN_CAMERA);
    ICameraHostVdi* cameraHostVdi = GetCameraHostVdi(cameraId);
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraHostVdi, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);

    std::string vdiCameraId = GetVendorCameraId(cameraId);
    if (vdiCameraId == "") {
        CAMERA_LOGE("Get vendor camera id failed");
        return OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT;
    }

    OHOS::sptr<ICameraDeviceVdi> deviceVdi = nullptr;
    OHOS::sptr<ICameraDeviceVdiCallback> vdiCallbackObj = new CameraDeviceServiceCallback(callbackObj);
    if (vdiCallbackObj == nullptr) {
        CAMERA_LOGE("Open camera error, vdiCallbackObj is nullptr");
        return OHOS::HDI::Camera::V1_0::INSUFFICIENT_RESOURCES;
    }
    int32_t ret = cameraHostVdi->OpenCamera(vdiCameraId, vdiCallbackObj, deviceVdi);
    if (ret != OHOS::HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("Open camera error, ret=%{public}d", ret);
        return ret;
    }
    if (deviceVdi == nullptr) {
        CAMERA_LOGE("Open camera error, deviceVdi is nullptr");
        return OHOS::HDI::Camera::V1_0::INSUFFICIENT_RESOURCES;
    }
    device = new CameraDeviceService(deviceVdi);
    if (device == nullptr) {
        CAMERA_LOGE("Open camera error, device is nullptr");
        return OHOS::HDI::Camera::V1_0::INSUFFICIENT_RESOURCES;
    }

    return OHOS::HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraHostService::SetFlashlight(const std::string &cameraId, bool isEnable)
{
    ICameraHostVdi* cameraHostVdi = GetCameraHostVdi(cameraId);
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraHostVdi, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);

    std::string vdiCameraId = GetVendorCameraId(cameraId);
    if (vdiCameraId == "") {
        CAMERA_LOGE("Get vendor camera id failed");
        return OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT;
    }

    return cameraHostVdi->SetFlashlight(vdiCameraId, isEnable);
}

int32_t CameraHostService::UpdateCameraIdMapList()
{
    std::vector<CameraIdInfo>().swap(cameraIdInfoList_);
    int32_t currentCameraIndex = 1;
    for (auto cameraHostVdi : cameraHostVdiList_) {
        CHECK_IF_PTR_NULL_RETURN_VALUE(cameraHostVdi, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);

        std::vector<std::string> vdiCameraIds;
        int32_t ret = cameraHostVdi->GetCameraIds(vdiCameraIds);
        if (ret != OHOS::HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGE("Camera host service set callback failed");
            return ret;
        }
        for (auto id : vdiCameraIds) {
            struct CameraIdInfo cameraIdInfo;
            std::string currentCameraId = "lcam00" + std::to_string(currentCameraIndex);
            cameraIdInfo.currentCameraId = currentCameraId;
            cameraIdInfo.cameraHostVdi = cameraHostVdi;
            cameraIdInfo.vendorCameraId = id;
            cameraIdInfo.isDeleted = false;
            cameraIdInfoList_.push_back(cameraIdInfo);
            currentCameraIndex++;
        }
    }

    return OHOS::HDI::Camera::V1_0::NO_ERROR;
}

ICameraHostVdi* CameraHostService::GetCameraHostVdi(const std::string &currentCameraId)
{
    auto itr = std::find_if(cameraIdInfoList_.begin(), cameraIdInfoList_.end(),
        [&currentCameraId](const struct CameraIdInfo &cameraIdInfo) {
            return currentCameraId == cameraIdInfo.currentCameraId;
        });
    if (itr == cameraIdInfoList_.end()) {
        CAMERA_LOGE("Get camera host vdi failed, current camera id = %{public}s doesn't exist",
            currentCameraId.c_str());
        return nullptr;
    }

    return itr->cameraHostVdi;
}

const std::string CameraHostService::GetVendorCameraId(const std::string &currentCameraId)
{
    auto itr = std::find_if(cameraIdInfoList_.begin(), cameraIdInfoList_.end(),
        [&currentCameraId](const struct CameraIdInfo &cameraIdInfo) {
            return currentCameraId == cameraIdInfo.currentCameraId;
        });
    if (itr == cameraIdInfoList_.end()) {
        CAMERA_LOGE("Get vendor camera id failed, current camera id = %{public}s doesn't exist",
            currentCameraId.c_str());
        return std::string("");
    }

    return itr->vendorCameraId;
}
} // end namespace OHOS::Camera
