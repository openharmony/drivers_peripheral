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

#include "sensor_if_service.h"
#include <refbase.h>
#include <cinttypes>
#include "sensor_uhdf_log.h"
#include "sensor_type.h"
#include "sensor_callback_vdi.h"
#include "callback_death_recipient.h"
#include "sensor_hdi_dump.h"
#include "devhost_dump_reg.h"

constexpr int DISABLE_SENSOR = 0;
constexpr int REPORT_INTERVAL = 0;
constexpr int UNREGISTER_SENSOR = 0;
constexpr int REGISTER_SENSOR = 1;
constexpr int ENABLE_SENSOR = 1;
constexpr int COMMON_REPORT_FREQUENCY = 1000000000;
constexpr int COPY_SENSORINFO = 1;

enum BatchSeniorMode {
        SA = 0,
        SDC = 1
};

#define HDF_LOG_TAG uhdf_sensor_service
#define DEFAULT_SENSOR(sensorId) {0, sensorId, 0, 0}

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {

namespace {
    constexpr int32_t CALLBACK_CTOUNT_THRESHOLD = 1;
    using CallBackDeathRecipientMap = std::unordered_map<IRemoteObject *, sptr<CallBackDeathRecipient>>;
    CallBackDeathRecipientMap g_callBackDeathRecipientMap;
}

SensorIfService::SensorIfService()
{
    int32_t ret = GetSensorVdiImplV1_1();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get sensor vdi instance failed", __func__);
    }
}

SensorIfService::~SensorIfService()
{
    if (vdi_ != nullptr) {
        HdfCloseVdi(vdi_);
    }
    RemoveDeathNotice(TRADITIONAL_SENSOR_TYPE);
    RemoveDeathNotice(MEDICAL_SENSOR_TYPE);
}

void SensorIfService::RegisteDumpHost()
{
    int32_t ret = DevHostRegisterDumpHost(GetSensorDump);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: DevHostRegisterDumpHost error", __func__);
    }
    return;
}

int32_t SensorIfService::GetSensorVdiImplV1_1()
{
    struct OHOS::HDI::Sensor::V1_1::WrapperSensorVdi *wrapperSensorVdi = nullptr;
    uint32_t version = 0;
    vdi_ = HdfLoadVdi(HDI_SENSOR_VDI_LIBNAME);
    if (vdi_ == nullptr || vdi_->vdiBase == nullptr) {
        HDF_LOGE("%{public}s: load sensor vdi failed", __func__);
        return HDF_FAILURE;
    }

    version = HdfGetVdiVersion(vdi_);
    if (version != 1) {
        HDF_LOGE("%{public}s: get sensor vdi version failed", __func__);
        return HDF_FAILURE;
    }

    wrapperSensorVdi = reinterpret_cast<struct OHOS::HDI::Sensor::V1_1::WrapperSensorVdi *>(vdi_->vdiBase);
    sensorVdiImplV1_1_ = wrapperSensorVdi->sensorModule;
    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor impl failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SensorIfService::Init()
{
    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = sensorVdiImplV1_1_->Init();
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s Init failed, error code is %{public}d", __func__, ret);
    } else {
        ret = GetAllSensorInfo(hdfSensorInformations);
        if (ret != SENSOR_SUCCESS) {
            HDF_LOGE("%{public}s GetAllSensorInfo failed, error code is %{public}d", __func__, ret);
        }
    }
#ifdef SENSOR_DEBUG
    RegisteDumpHost();
#endif
    return ret;
}

sptr<SensorCallbackVdi> SensorIfService::GetSensorCb(int32_t groupId, const sptr<V3_0::ISensorCallback> &callbackObj,
                                                     bool cbFlag)
{
    SENSOR_TRACE_PID;
    if (groupId == TRADITIONAL_SENSOR_TYPE) {
        if (cbFlag) {
            traditionalCb = new SensorCallbackVdi(callbackObj);
        }
        return traditionalCb;
    }
    if (cbFlag) {
        medicalCb = new SensorCallbackVdi(callbackObj);
    }
    return medicalCb;
}

int32_t SensorIfService::SetBatchSenior(int32_t serviceId, const SensorHandle sensorHandle, int32_t mode,
                                        int64_t samplingInterval, int64_t reportInterval)
{
    SENSOR_TRACE_PID_MSG("sensorHandle " + SENSOR_HANDLE_TO_STRING(sensorHandle) + "mode " +
        std::to_string(mode) + "samplingInterval " + std::to_string(samplingInterval) + "reportInterval " +
        std::to_string(reportInterval));
    HDF_LOGI("%{public}s: serviceId is %{public}d, sensorHandle is %{public}s, mode is %{public}d, samplingInterval "
             "is %{public}s, reportInterval is %{public}s",
             __func__, serviceId, SENSOR_HANDLE_TO_C_STR(sensorHandle), mode, std::to_string(samplingInterval).c_str(),
             std::to_string(reportInterval).c_str());

    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    SensorClientsManager::GetInstance()->SetClientSenSorConfig(sensorHandle, serviceId, samplingInterval,
                                                               reportInterval);

    AdjustSensorConfig(sensorHandle, samplingInterval, reportInterval);

    int32_t ret = SetBatchConfig(sensorHandle, samplingInterval, reportInterval);
    if (ret != SENSOR_SUCCESS) {
        return ret;
    }

    UpdateSensorModeConfig(sensorHandle, mode, samplingInterval, reportInterval);

    return ret;
}

void SensorIfService::AdjustSensorConfig(const SensorHandle &sensorHandle, int64_t &samplingInterval,
                                         int64_t &reportInterval)
{
    int64_t saSamplingInterval = samplingInterval;
    int64_t saReportInterval = reportInterval;
    int64_t sdcSamplingInterval = samplingInterval;
    int64_t sdcReportInterval = reportInterval;

    SensorClientsManager::GetInstance()->SetSensorBestConfig(sensorHandle, saSamplingInterval,
                                                             saReportInterval);
    SensorClientsManager::GetInstance()->SetSdcSensorBestConfig(sensorHandle, sdcSamplingInterval,
                                                                sdcReportInterval);

    samplingInterval = std::min(saSamplingInterval, sdcSamplingInterval);
    reportInterval = std::min(saReportInterval, sdcReportInterval);
}

int32_t SensorIfService::SetBatchConfig(const SensorHandle &sensorHandle, int64_t samplingInterval,
                                        int64_t reportInterval)
{
    SENSOR_TRACE_START("sensorVdiImplV1_1_->SetBatch");
    int32_t ret = sensorVdiImplV1_1_->SetBatch(sensorHandle.sensorType, samplingInterval, reportInterval);
    SENSOR_TRACE_FINISH;

    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetBatch failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

void SensorIfService::UpdateSensorModeConfig(const SensorHandle &sensorHandle, int32_t mode, int64_t samplingInterval,
                                             int64_t reportInterval)
{
    if (mode == SA) {
        SetDelay(sensorHandle, samplingInterval, reportInterval);
        SensorClientsManager::GetInstance()->UpdateSensorConfig(sensorHandle, samplingInterval, reportInterval);
        SensorClientsManager::GetInstance()->UpdateClientPeriodCount(sensorHandle, samplingInterval, reportInterval);
    } else if (mode == SDC) {
        SensorClientsManager::GetInstance()->UpdateSdcSensorConfig(sensorHandle, samplingInterval, reportInterval);
    }

    SensorClientsManager::GetInstance()->GetSensorBestConfig(sensorHandle, samplingInterval, reportInterval);

    SENSOR_TRACE_START("sensorVdiImplV1_1_->SetSaBatch");
    int32_t ret = sensorVdiImplV1_1_->SetSaBatch(sensorHandle.sensorType, samplingInterval, reportInterval);
    SENSOR_TRACE_FINISH;

    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetSaBatch failed, error code is %{public}d", __func__, ret);
    }
}

int32_t SensorIfService::SetDelay(SensorHandle sensorHandle, int64_t &samplingInterval, int64_t &reportInterval)
{
    SENSOR_TRACE_PID_MSG("sensorHandle " + SENSOR_HANDLE_TO_STRING(sensorHandle) + "samplingInterval " +
                         std::to_string(samplingInterval) + "reportInterval " + std::to_string(reportInterval));
    HDF_LOGD("%{public}s: sensorHandle is %{public}s, samplingInterval is [%{public}" PRId64 "], reportInterval is "
             "[%{public}" PRId64 "].", __func__, SENSOR_HANDLE_TO_C_STR(sensorHandle), samplingInterval,
             reportInterval);
    for (auto it = hdfSensorInformations.begin(); it != hdfSensorInformations.end(); ++it) {
        if (it->deviceSensorInfo.deviceId == sensorHandle.deviceId &&
            it->deviceSensorInfo.sensorType == sensorHandle.sensorType &&
            it->deviceSensorInfo.sensorId == sensorHandle.sensorId &&
            it->deviceSensorInfo.location == sensorHandle.location) {
            if (samplingInterval < it->minDelay) {
                samplingInterval = it->minDelay;
                HDF_LOGD("%{public}s samplingInterval has been set minDelay %{public}s", __func__,
                         std::to_string(samplingInterval).c_str());
                return SENSOR_SUCCESS;
            }
            if (samplingInterval > it->maxDelay && it->maxDelay != REPORT_INTERVAL) {
                samplingInterval = it->maxDelay;
                HDF_LOGD("%{public}s samplingInterval has been set maxDelay %{public}s", __func__,
                         std::to_string(samplingInterval).c_str());
                return SENSOR_SUCCESS;
            }
        }
    }
    HDF_LOGD("%{public}s samplingInterval not change", __func__);
    return SENSOR_SUCCESS;
}

int32_t SensorIfService::AddCallbackMap(int32_t groupId, const sptr<IRemoteObject> &iRemoteObject)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: service %{public}d", __func__, serviceId);
    auto groupCallBackIter = callbackMap.find(groupId);
    if (groupCallBackIter != callbackMap.end()) {
        auto iRemoteObjectIter =
            find_if(callbackMap[groupId].begin(), callbackMap[groupId].end(),
            [&iRemoteObject](const sptr<IRemoteObject> &iRemoteObjectRegistered) {
                return iRemoteObject == iRemoteObjectRegistered;
            });
        if (iRemoteObjectIter == callbackMap[groupId].end()) {
            int32_t addResult = AddSensorDeathRecipient(iRemoteObject);
            if (addResult != SENSOR_SUCCESS) {
                return HDF_FAILURE;
            }
            callbackMap[groupId].push_back(iRemoteObject);
        }
    } else {
        int32_t addResult = AddSensorDeathRecipient(iRemoteObject);
        if (addResult != SENSOR_SUCCESS) {
            return HDF_FAILURE;
        }
        std::vector<sptr<IRemoteObject>> remoteVec;
        remoteVec.push_back(iRemoteObject);
        callbackMap[groupId] = remoteVec;
    }
    return SENSOR_SUCCESS;
}

int32_t SensorIfService::RemoveCallbackMap(int32_t groupId, int serviceId,
    const sptr<IRemoteObject> &iRemoteObject)
{
    SENSOR_TRACE_PID;
    HDF_LOGI("%{public}s: service %{public}d", __func__, serviceId);

    if (!ValidateCallbackMap(groupId, iRemoteObject)) {
        return HDF_FAILURE;
    }

    if (!RemoveCallbackFromMap(groupId, iRemoteObject)) {
        return HDF_FAILURE;
    }

    DisableUnusedSensors(serviceId);

    return SENSOR_SUCCESS;
}

bool SensorIfService::ValidateCallbackMap(int32_t groupId, const sptr<IRemoteObject> &iRemoteObject)
{
    auto groupIdCallBackIter = callbackMap.find(groupId);
    if (groupIdCallBackIter == callbackMap.end()) {
        HDF_LOGE("%{public}s: groupId [%{public}d] callbackObj not registered", __func__, groupId);
        return false;
    }

    auto iRemoteObjectIter =
        find_if(callbackMap[groupId].begin(), callbackMap[groupId].end(),
        [&iRemoteObject](const sptr<IRemoteObject> &iRemoteObjectRegistered) {
            return iRemoteObject == iRemoteObjectRegistered;
        });
    if (iRemoteObjectIter == callbackMap[groupId].end()) {
        HDF_LOGE("%{public}s: groupId [%{public}d] callbackObj not registered", __func__, groupId);
        return false;
    }

    return true;
}

bool SensorIfService::RemoveCallbackFromMap(int32_t groupId, const sptr<IRemoteObject> &iRemoteObject)
{
    auto iRemoteObjectIter =
        find_if(callbackMap[groupId].begin(), callbackMap[groupId].end(),
        [&iRemoteObject](const sptr<IRemoteObject> &iRemoteObjectRegistered) {
            return iRemoteObject == iRemoteObjectRegistered;
        });

    int32_t removeResult = RemoveSensorDeathRecipient(*iRemoteObjectIter);
    if (removeResult != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s: last callback RemoveSensorDeathRecipient fail, groupId[%{public}d]", __func__, groupId);
    }

    if (callbackMap[groupId].size() > CALLBACK_CTOUNT_THRESHOLD) {
        callbackMap[groupId].erase(iRemoteObjectIter);
    } else {
        callbackMap.erase(groupId);
    }

    return true;
}

void SensorIfService::DisableUnusedSensors(int serviceId)
{
    std::unordered_map<SensorHandle, std::set<int32_t>> sensorEnabled =
        SensorClientsManager::GetInstance()->GetSensorUsed();

    for (auto iter : sensorEnabled) {
        if (iter.second.find(serviceId) == iter.second.end()) {
            continue;
        }

        if (!SensorClientsManager::GetInstance()->IsUpadateSensorState(iter.first, serviceId, DISABLE_SENSOR)) {
            continue;
        }

        std::unordered_map<SensorHandle, std::set<int32_t>> sensorUsed =
            SensorClientsManager::GetInstance()->GetSensorUsed();
        if (sensorUsed.find(iter.first) == sensorUsed.end()) {
            DisableSensorHandle(iter.first);
        }
    }
}

void SensorIfService::DisableSensorHandle(const SensorHandle &sensorHandle)
{
    SENSOR_TRACE_START("sensorVdiImplV1_1_->Disable");
#ifdef TV_FLAG
    int32_t ret = sensorVdiImplV1_1_->Disable(sensorHandle);
#else
    int32_t ret = sensorVdiImplV1_1_->Disable(sensorHandle.sensorType);
#endif
    SENSOR_TRACE_FINISH;

    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s Disable failed, error code is %{public}d", __func__, ret);
    }
}

int32_t SensorIfService::AddSensorDeathRecipient(const sptr<IRemoteObject> &iRemoteObject)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: service %{public}d", __func__, serviceId);
    sptr<CallBackDeathRecipient> callBackDeathRecipient = new CallBackDeathRecipient(this);
    if (callBackDeathRecipient == nullptr) {
        HDF_LOGE("%{public}s: new CallBackDeathRecipient fail", __func__);
        return HDF_FAILURE;
    }
    bool result = iRemoteObject->AddDeathRecipient(callBackDeathRecipient);
    if (!result) {
        HDF_LOGE("%{public}s: AddDeathRecipient fail", __func__);
        return HDF_FAILURE;
    }
    g_callBackDeathRecipientMap[iRemoteObject.GetRefPtr()] = callBackDeathRecipient;
    return SENSOR_SUCCESS;
}

int32_t SensorIfService::RemoveSensorDeathRecipient(const sptr<IRemoteObject> &iRemoteObject)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: service %{public}d", __func__, serviceId);
    auto callBackDeathRecipientIter = g_callBackDeathRecipientMap.find(iRemoteObject.GetRefPtr());
    if (callBackDeathRecipientIter == g_callBackDeathRecipientMap.end()) {
        HDF_LOGE("%{public}s: not find recipient", __func__);
        return HDF_FAILURE;
    }
    bool result = iRemoteObject->RemoveDeathRecipient(callBackDeathRecipientIter->second);
    g_callBackDeathRecipientMap.erase(callBackDeathRecipientIter);
    if (!result) {
        HDF_LOGE("%{public}s: RemoveDeathRecipient fail", __func__);
        return HDF_FAILURE;
    }
    return SENSOR_SUCCESS;
}

void SensorIfService::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    SENSOR_TRACE_PID;
    HDF_LOGI("%{public}s: service %{public}d", __func__, static_cast<uint32_t>(HdfRemoteGetCallingPid()));
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    sptr<IRemoteObject> iRemoteObject = object.promote();
    if (iRemoteObject == nullptr) {
        return;
    }

    for (int32_t groupId = TRADITIONAL_SENSOR_TYPE; groupId < SENSOR_GROUP_TYPE_MAX; groupId++) {
        auto groupIdIter = callbackMap.find(groupId);
        if (groupIdIter == callbackMap.end()) {
            continue;
        }
        auto callBackIter =
        find_if(callbackMap[groupId].begin(), callbackMap[groupId].end(),
        [&iRemoteObject](const sptr<IRemoteObject> &iRemoteObjectRegistered) {
            return iRemoteObject.GetRefPtr() == iRemoteObjectRegistered.GetRefPtr();
        });
        if (callBackIter != callbackMap[groupId].end()) {
            int32_t serviceId = SensorClientsManager::GetInstance()->GetServiceId(groupId, iRemoteObject);
            int32_t ret = RemoveCallbackMap(groupId, serviceId, iRemoteObject);
            if (ret != SENSOR_SUCCESS) {
                HDF_LOGE("%{public}s: Unregister failed groupId[%{public}d]", __func__, groupId);
            }
            if (!SensorClientsManager::GetInstance()->IsClientsEmpty(groupId)) {
                HDF_LOGD("%{public}s: clients is not empty, do not unregister", __func__);
                continue;
            }
            const sptr<V3_0::ISensorCallback> &cb = OHOS::HDI::hdi_facecast<V3_0::ISensorCallback>(*callBackIter);
            sptr<SensorCallbackVdi> sensorCb = GetSensorCb(groupId, cb, UNREGISTER_SENSOR);
            if (sensorCb == nullptr) {
                HDF_LOGE("%{public}s: get sensorcb fail, groupId[%{public}d]", __func__, groupId);
                continue;
            }
            SENSOR_TRACE_START("sensorVdiImplV1_1_->Unregister");
#ifdef TV_FLAG
            ret = sensorVdiImplV1_1_->Unregister(groupId, sensorCb);
#else
            ret = sensorVdiImplV1_1_->Unregister(groupId, sensorCb);
#endif
            SENSOR_TRACE_FINISH;
            if (ret != SENSOR_SUCCESS) {
                HDF_LOGE("%{public}s: Unregister failed, error code is %{public}d", __func__, ret);
            }
        }
    }
}

void SensorIfService::RemoveDeathNotice(int32_t groupId)
{
    SENSOR_TRACE_PID_MSG("sensorType " + std::to_string(groupId));
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: service %{public}d, groupId %{public}d", __func__, serviceId, groupId);
    auto iter = callbackMap.find(groupId);
    if (iter != callbackMap.end()) {
        return;
    }
    for (const auto &iRemoteObject : callbackMap[groupId]) {
        auto recipientIter = g_callBackDeathRecipientMap.find(iRemoteObject.GetRefPtr());
        if (recipientIter != g_callBackDeathRecipientMap.end()) {
            bool removeResult = iRemoteObject->RemoveDeathRecipient(recipientIter->second);
            if (!removeResult) {
                HDF_LOGE("%{public}s: sensor destroyed, callback RemoveSensorDeathRecipient fail", __func__);
            }
        }
    }
}

int32_t SensorIfService::DisableSensor(const SensorHandle sensorHandle, uint32_t serviceId)
{
    SENSOR_TRACE_PID_MSG("sensorHandle " + SENSOR_HANDLE_TO_STRING(sensorHandle));
    if (!SensorClientsManager::GetInstance()->IsUpadateSensorState(sensorHandle, serviceId, DISABLE_SENSOR)) {
        HDF_LOGD("%{public}s There are still some services enable", __func__);
        return HDF_SUCCESS;
    }

    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = SENSOR_SUCCESS;
    if (SensorClientsManager::GetInstance()->IsExistSdcSensorEnable(sensorHandle)) {
        SENSOR_TRACE_START("sensorVdiImplV1_1_->SetSaBatch");
#ifdef TV_FLAG
        ret = sensorVdiImplV1_1_->SetSaBatch(sensorHandle, REPORT_INTERVAL, REPORT_INTERVAL);
#else
        ret = sensorVdiImplV1_1_->SetSaBatch(sensorHandle.sensorType, REPORT_INTERVAL, REPORT_INTERVAL);
#endif
        SENSOR_TRACE_FINISH;
        if (ret != SENSOR_SUCCESS) {
            HDF_LOGE("%{public}s SetSaBatch failed, error code is %{public}d, sensorHandle = %{public}s, serviceId = "
                     "%{public}d", __func__, ret, SENSOR_HANDLE_TO_C_STR(sensorHandle), serviceId);
            return ret;
        }
        return HDF_SUCCESS;
    }

    ret = HDF_FAILURE;
    SENSOR_TRACE_START("sensorVdiImplV1_1_->Disable");
#ifdef TV_FLAG
    ret = sensorVdiImplV1_1_->Disable(sensorHandle);
#else
    ret = sensorVdiImplV1_1_->Disable(sensorHandle.sensorType);
#endif
    SENSOR_TRACE_FINISH;
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d, sensorHandle = %{public}s, serviceId = %{public}d",
                 __func__, ret, SENSOR_HANDLE_TO_C_STR(sensorHandle), serviceId);
    }

    return ret;
}

extern "C" ISensorInterface *SensorInterfaceImplGetInstance(void)
{
    SensorIfService *impl = new (std::nothrow) SensorIfService();
    if (impl == nullptr) {
        return nullptr;
    }

    int32_t ret = impl->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: service init failed, error code is %{public}d", __func__, ret);
        delete impl;
        return nullptr;
    }

    return impl;
}

//V3_0 interface
int32_t SensorIfService::GetAllSensorInfo(std::vector<V3_0::HdfSensorInformation> &info)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: serviceId = %{public}d", __func__, serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    std::vector<OHOS::HDI::Sensor::V3_0::HdfSensorInformationVdi> sensorInfoVdi = {};
    SENSOR_TRACE_START("sensorVdiImplV1_1_->GetAllSensorInfo");
    int32_t ret = sensorVdiImplV1_1_->GetAllSensorInfo(sensorInfoVdi);
    SENSOR_TRACE_FINISH;
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s GetAllSensors failed, error code is %{public}d", __func__, ret);
        return ret;
    }

    if (sensorInfoVdi.empty()) {
        HDF_LOGI("%{public}s no sensor info in list, sensorInfoVdi is empty", __func__);
    }

    for (const auto &it : sensorInfoVdi) {
        struct V3_0::HdfSensorInformation sensorInfo = {};
        sensorInfo.sensorName = it.sensorName;
        sensorInfo.vendorName = it.vendorName;
        sensorInfo.firmwareVersion = it.firmwareVersion;
        sensorInfo.hardwareVersion = it.hardwareVersion;
        sensorInfo.maxRange = it.maxRange;
#ifdef TV_FLAG
        sensorInfo.deviceSensorInfo = {it.sensorHandle.deviceId, it.sensorHandle.sensorType, it.sensorHandle.sensorId,
                                       it.sensorHandle.location};
#else
        sensorInfo.deviceSensorInfo = {DEFAULT_DEVICE_ID, it.sensorId, DEFAULT_SENSOR_ID, DEFAULT_LOCATION};
#endif
        sensorInfo.accuracy = it.accuracy;
        sensorInfo.power = it.power;
        sensorInfo.minDelay = it.minDelay;
        sensorInfo.maxDelay = it.maxDelay;
        sensorInfo.fifoMaxEventCount = it.fifoMaxEventCount;
        info.push_back(std::move(sensorInfo));
    }

    SensorClientsManager::GetInstance()->CopySensorInfo(info, COPY_SENSORINFO);

    return HDF_SUCCESS;
}

int32_t SensorIfService::Enable(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo)
{
    SensorHandle sensorHandle = {deviceSensorInfo.deviceId, deviceSensorInfo.sensorType, deviceSensorInfo.sensorId,
                                 deviceSensorInfo.location};
    SENSOR_TRACE_PID_MSG("sensorHandle " + SENSOR_HANDLE_TO_STRING(sensorHandle));
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: sensorHandle %{public}s, serviceId = %{public}d", __func__,
             SENSOR_HANDLE_TO_C_STR(sensorHandle), serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    SensorClientsManager::GetInstance()->ReSetSensorPrintTime(sensorHandle);
    if (!SensorClientsManager::GetInstance()->IsUpadateSensorState(sensorHandle, serviceId, ENABLE_SENSOR)) {
        return HDF_SUCCESS;
    }

    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    SensorClientsManager::GetInstance()->OpenSensor(sensorHandle, serviceId);
    int32_t ret = HDF_FAILURE;
    SENSOR_TRACE_START("sensorVdiImplV1_1_->Enable");
#ifdef TV_FLAG
    ret = sensorVdiImplV1_1_->Enable(sensorHandle);
#else
    ret = sensorVdiImplV1_1_->Enable(sensorHandle.sensorType);
#endif
    SENSOR_TRACE_FINISH;
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d, sensorHandle = %{public}s, serviceId = %{public}d",
                 __func__, ret, SENSOR_HANDLE_TO_C_STR(sensorHandle), serviceId);
        SensorClientsManager::GetInstance()->IsUpadateSensorState(sensorHandle, serviceId, DISABLE_SENSOR);
    }

    return ret;
}

int32_t SensorIfService::Disable(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo)
{
    SensorHandle sensorHandle = {deviceSensorInfo.deviceId, deviceSensorInfo.sensorType, deviceSensorInfo.sensorId,
                                 deviceSensorInfo.location};
    SENSOR_TRACE_PID_MSG("sensorHandle " + SENSOR_HANDLE_TO_STRING(sensorHandle));
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: sensorHandle %{public}s, serviceId = %{public}d", __func__,
             SENSOR_HANDLE_TO_C_STR(sensorHandle), serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    return DisableSensor(sensorHandle, serviceId);
}

int32_t SensorIfService::SetBatch(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo,
                                  int64_t samplingInterval, int64_t reportInterval)
{
    SensorHandle sensorHandle = {deviceSensorInfo.deviceId, deviceSensorInfo.sensorType, deviceSensorInfo.sensorId,
                                 deviceSensorInfo.location};
    SENSOR_TRACE;
    HDF_LOGD("%{public}s: sensorHandle is %{public}s, samplingInterval is [%{public}" PRId64 "], \
        reportInterval is [%{public}" PRId64 "].", __func__, SENSOR_HANDLE_TO_C_STR(sensorHandle),
        samplingInterval, reportInterval);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());

    int32_t ret = SetBatchSenior(serviceId, sensorHandle, SA, samplingInterval, reportInterval);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetBatch failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t SensorIfService::SetMode(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo, int32_t mode)
{
    SensorHandle sensorHandle = {deviceSensorInfo.deviceId, deviceSensorInfo.sensorType, deviceSensorInfo.sensorId,
                                 deviceSensorInfo.location};
    SENSOR_TRACE_PID_MSG("sensorHandle " + SENSOR_HANDLE_TO_STRING(sensorHandle) + "mode " + std::to_string(mode));
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: sensorHandle is %{public}s, mode is %{public}d, serviceId = %{public}d", __func__,
             SENSOR_HANDLE_TO_C_STR(sensorHandle), mode,
             serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = HDF_FAILURE;
    SENSOR_TRACE_START("sensorVdiImplV1_1_->SetMode");
#ifdef TV_FLAG
    ret = sensorVdiImplV1_1_->SetMode(sensorHandle, mode);
#else
    ret = sensorVdiImplV1_1_->SetMode(sensorHandle.sensorType, mode);
#endif
    SENSOR_TRACE_FINISH;
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetMode failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t SensorIfService::SetOption(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo, uint32_t option)
{
    SensorHandle sensorHandle = {deviceSensorInfo.deviceId, deviceSensorInfo.sensorType, deviceSensorInfo.sensorId,
                                 deviceSensorInfo.location};
    SENSOR_TRACE_PID_MSG("sensorHandle " + SENSOR_HANDLE_TO_STRING(sensorHandle) + "option " + std::to_string(option));
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: sensorHandle is %{public}s, option is %{public}d, serviceId = %{public}d", __func__,
             SENSOR_HANDLE_TO_C_STR(sensorHandle),
             option, serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    SENSOR_TRACE_START("sensorVdiImplV1_1_->SetOption");
#ifdef TV_FLAG
    int32_t ret = sensorVdiImplV1_1_->SetOption(sensorHandle, option);
#else
    int32_t ret = sensorVdiImplV1_1_->SetOption(sensorHandle.sensorType, option);
#endif
    SENSOR_TRACE_FINISH;
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetOption failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t SensorIfService::Register(int32_t groupId, const sptr<V3_0::ISensorCallback> &callbackObj)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: groupId %{public}d, service %{public}d", __func__, groupId, serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    int32_t ret = HDF_SUCCESS;
    const sptr<IRemoteObject> &iRemoteObject = OHOS::HDI::hdi_objcast<V3_0::ISensorCallback>(callbackObj);
    int32_t result = AddCallbackMap(groupId, iRemoteObject);
    if (result != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s: AddCallbackMap failed groupId[%{public}d]", __func__, groupId);
    }
    if (SensorClientsManager::GetInstance()->IsClientsEmpty(groupId)) {
        if (sensorVdiImplV1_1_ == nullptr) {
            HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
            return HDF_FAILURE;
        }
        sptr<SensorCallbackVdi> sensorCb = GetSensorCb(groupId, callbackObj, REGISTER_SENSOR);
        if (sensorCb == nullptr) {
            HDF_LOGE("%{public}s: get sensorcb fail, groupId[%{public}d]", __func__, groupId);
            return HDF_FAILURE;
        }
        SENSOR_TRACE_START("sensorVdiImplV1_1_->Register");
#ifdef TV_FLAG
        ret = sensorVdiImplV1_1_->Register(groupId, sensorCb);
#else
        ret = sensorVdiImplV1_1_->Register(groupId, sensorCb);
#endif
        SENSOR_TRACE_FINISH;
        if (ret != SENSOR_SUCCESS) {
            HDF_LOGE("%{public}s Register failed, error code is %{public}d", __func__, ret);
            int32_t removeResult = RemoveSensorDeathRecipient(iRemoteObject);
            if (removeResult != SENSOR_SUCCESS) {
                HDF_LOGE("%{public}s: callback RemoveSensorDeathRecipient fail, groupId[%{public}d]",
                         __func__, groupId);
            }
        } else {
            SensorClientsManager::GetInstance()->ReportDataCbRegister(groupId, serviceId, callbackObj, false);
        }
    } else {
        SensorClientsManager::GetInstance()->ReportDataCbRegister(groupId, serviceId, callbackObj, false);
    }
    return ret;
}

int32_t SensorIfService::Unregister(int32_t groupId, const sptr<V3_0::ISensorCallback> &callbackObj)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: groupId %{public}d, service %{public}d", __func__, groupId, serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    if (groupId < TRADITIONAL_SENSOR_TYPE || groupId >= SENSOR_GROUP_TYPE_MAX) {
        HDF_LOGE("%{public}s: groupId %{public}d is error", __func__, groupId);
        return SENSOR_INVALID_PARAM;
    }
    const sptr<IRemoteObject> &iRemoteObject = OHOS::HDI::hdi_objcast<V3_0::ISensorCallback>(callbackObj);
    int32_t result = RemoveCallbackMap(groupId, serviceId, iRemoteObject);
    if (result !=SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s: RemoveCallbackMap failed groupId[%{public}d]", __func__, groupId);
    }
    SensorClientsManager::GetInstance()->ReportDataCbUnRegister(groupId, serviceId, callbackObj);
    if (!SensorClientsManager::GetInstance()->IsClientsEmpty(groupId)) {
        HDF_LOGD("%{public}s: clients is not empty, do not unregister", __func__);
        return HDF_SUCCESS;
    }
    if (!SensorClientsManager::GetInstance()->IsNoSensorUsed()) {
        HDF_LOGD("%{public}s: sensorUsed is not empty, do not unregister", __func__);
        return HDF_SUCCESS;
    }

    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    sptr<SensorCallbackVdi> sensorCb = GetSensorCb(groupId, callbackObj, UNREGISTER_SENSOR);
    if (sensorCb == nullptr) {
        HDF_LOGE("%{public}s: get sensorcb fail, groupId[%{public}d]", __func__, groupId);
        return HDF_FAILURE;
    }
    SENSOR_TRACE_START("sensorVdiImplV1_1_->Unregister");
#ifdef TV_FLAG
    int32_t ret = sensorVdiImplV1_1_->Unregister(groupId, sensorCb);
#else
    int32_t ret = sensorVdiImplV1_1_->Unregister(groupId, sensorCb);
#endif
    SENSOR_TRACE_FINISH;
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s: Unregister failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t SensorIfService::ReadData(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo,
                                  std::vector<V3_0::HdfSensorEvents> &event)
{
    SensorHandle sensorHandle = {deviceSensorInfo.deviceId, deviceSensorInfo.sensorType, deviceSensorInfo.sensorId,
                                 deviceSensorInfo.location};
    SENSOR_TRACE_PID_MSG("sensorHandle " + SENSOR_HANDLE_TO_STRING(sensorHandle));
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: service %{public}d", __func__, serviceId);
    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void SensorIfService::VoteEnable(const SensorHandle sensorHandle, uint32_t serviceId, bool& enabled)
{
    static std::map<SensorHandle, std::map<uint32_t, bool>> sdcEnableMap;
    if (enabled) {
        sdcEnableMap[sensorHandle][serviceId] = enabled;
    } else {
        sdcEnableMap[sensorHandle].erase(serviceId);
    }
    for (auto it = sdcEnableMap[sensorHandle].begin(); it != sdcEnableMap[sensorHandle].end(); ++it) {
        if (it->second == true) {
            enabled = true;
        }
    }
}

void SensorIfService::VoteInterval(const SensorHandle sensorHandle, uint32_t serviceId,
    int64_t &samplingInterval, bool &enabled)
{
    static std::map<SensorHandle, std::map<uint32_t, int64_t>> sdcIntervalMap;
    if (enabled) {
        sdcIntervalMap[sensorHandle][serviceId] = samplingInterval;
    } else {
        samplingInterval = 0;
        sdcIntervalMap[sensorHandle].erase(serviceId);
    }
    for (auto it = sdcIntervalMap[sensorHandle].begin(); it != sdcIntervalMap[sensorHandle].end(); ++it) {
        if (samplingInterval == 0) {
            samplingInterval = it->second;
        }
        samplingInterval = samplingInterval < it->second ? samplingInterval : it->second;
    }
    HDF_LOGI("%{public}s: samplingInterval is %{public}s", __func__, std::to_string(samplingInterval).c_str());
}

int32_t SensorIfService::SetSdcSensor(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo, bool enabled,
                                      int32_t rateLevel)
{
    SensorHandle sensorHandle = {deviceSensorInfo.deviceId, deviceSensorInfo.sensorType, deviceSensorInfo.sensorId,
                                 deviceSensorInfo.location};
    SENSOR_TRACE_PID_MSG("sensorHandle " + SENSOR_HANDLE_TO_STRING(sensorHandle) + "enabled " +
        std::to_string(enabled) + "rateLevel " + std::to_string(rateLevel));
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: sensorHandle %{public}s, enabled %{public}u, rateLevel %{public}u, serviceId %{public}d",
             __func__, SENSOR_HANDLE_TO_C_STR(sensorHandle), enabled, rateLevel, serviceId);

    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    if (rateLevel < REPORT_INTERVAL) {
        HDF_LOGE("%{public}s: rateLevel cannot be less than zero", __func__);
        return HDF_FAILURE;
    }

    int64_t samplingInterval = CalculateSamplingInterval(rateLevel);
    int64_t reportInterval = REPORT_INTERVAL;

    VoteInterval(sensorHandle, serviceId, samplingInterval, enabled);
    VoteEnable(sensorHandle, serviceId, enabled);

    return enabled ? EnableSdcSensor(serviceId, sensorHandle, samplingInterval, reportInterval)
                   : DisableSdcSensor(serviceId, sensorHandle, samplingInterval);
}

int64_t SensorIfService::CalculateSamplingInterval(int32_t rateLevel)
{
    return rateLevel == REPORT_INTERVAL ? REPORT_INTERVAL : COMMON_REPORT_FREQUENCY / rateLevel;
}

int32_t SensorIfService::EnableSdcSensor(uint32_t serviceId, const SensorHandle& sensorHandle,
                                         int64_t samplingInterval, int64_t reportInterval)
{
    int32_t ret = SetBatchSenior(serviceId, sensorHandle, SDC, samplingInterval, reportInterval);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetBatchSenior SDC failed, error code is %{public}d", __func__, ret);
        return ret;
    }

    SENSOR_TRACE_START("sensorVdiImplV1_1_->Enable");
#ifdef TV_FLAG
    ret = sensorVdiImplV1_1_->Enable(sensorHandle);
#else
    ret = sensorVdiImplV1_1_->Enable(sensorHandle.sensorType);
#endif
    SENSOR_TRACE_FINISH;

    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s Enable failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t SensorIfService::DisableSdcSensor(uint32_t serviceId, const SensorHandle& sensorHandle,
                                          int64_t samplingInterval)
{
    SensorClientsManager::GetInstance()->EraseSdcSensorBestConfig(sensorHandle);

    int32_t ret = DisableSensor(sensorHandle, serviceId);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s Disable failed, error code is %{public}d", __func__, ret);
        return ret;
    }

    SensorClientsManager::GetInstance()->GetSensorBestConfig(sensorHandle, samplingInterval, samplingInterval);

    SENSOR_TRACE_START("sensorVdiImplV1_1_->SetSaBatch");
#ifdef TV_FLAG
    ret = sensorVdiImplV1_1_->SetSaBatch(sensorHandle, samplingInterval, samplingInterval);
#else
    ret = sensorVdiImplV1_1_->SetSaBatch(sensorHandle.sensorType, samplingInterval, samplingInterval);
#endif
    SENSOR_TRACE_FINISH;

    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetSaBatch failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t SensorIfService::GetSdcSensorInfo(std::vector<V3_0::SdcSensorInfo>& sdcSensorInfo)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: serviceId %{public}d", __func__, serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    SENSOR_TRACE_START("sensorVdiImplV1_1_->GetSdcSensorInfo");
    std::vector<OHOS::HDI::Sensor::V1_1::SdcSensorInfoVdi> sdcSensorInfoVdi1_1;
#ifdef TV_FLAG
    int32_t ret = sensorVdiImplV1_1_->GetSdcSensorInfo(sdcSensorInfoVdi1_1);
#else
    int32_t ret = sensorVdiImplV1_1_->GetSdcSensorInfo(sdcSensorInfoVdi1_1);
#endif
    SENSOR_TRACE_FINISH;
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s GetSdcSensorInfo failed, error code is %{public}d", __func__, ret);
    }

    for (auto infoVdi : sdcSensorInfoVdi1_1) {
        V3_0::SdcSensorInfo info;
        info.offset = infoVdi.offset;
#ifdef TV_FLAG
        info.deviceSensorInfo = {infoVdi.sensorHandle.deviceId, infoVdi.sensorHandle.sensorType,
                                 infoVdi.sensorHandle.sensorId,
                                 infoVdi.sensorHandle.location};
#else
        info.deviceSensorInfo = {DEFAULT_DEVICE_ID, infoVdi.sensorId, DEFAULT_SENSOR_ID,
                                 DEFAULT_LOCATION};
#endif
        info.ddrSize = infoVdi.ddrSize;
        info.minRateLevel = infoVdi.minRateLevel;
        info.maxRateLevel = infoVdi.maxRateLevel;
        info.memAddr = infoVdi.memAddr;
        info.reserved = infoVdi.reserved;
        sdcSensorInfo.push_back(std::move(info));
    }

    return ret;
}

int32_t SensorIfService::RegisterAsync(int32_t groupId, const sptr<V3_0::ISensorCallback> &callbackObj)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: groupId %{public}d, service %{public}d", __func__, groupId, serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    int32_t ret = HDF_SUCCESS;
    const sptr<IRemoteObject> &iRemoteObject = OHOS::HDI::hdi_objcast<V3_0::ISensorCallback>(callbackObj);
    int32_t result = AddCallbackMap(groupId, iRemoteObject);
    if (result != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s: AddCallbackMap failed groupId[%{public}d]", __func__, groupId);
    }
    if (SensorClientsManager::GetInstance()->IsClientsEmpty(groupId)) {
        if (sensorVdiImplV1_1_ == nullptr) {
            HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
            return HDF_FAILURE;
        }
        sptr<SensorCallbackVdi> sensorCb = GetSensorCb(groupId, callbackObj, REGISTER_SENSOR);
        if (sensorCb == nullptr) {
            HDF_LOGE("%{public}s: get sensorcb fail, groupId[%{public}d]", __func__, groupId);
            return HDF_FAILURE;
        }
        SENSOR_TRACE_START("sensorVdiImplV1_1_->Register");
#ifdef TV_FLAG
        ret = sensorVdiImplV1_1_->Register(groupId, sensorCb);
#else
        ret = sensorVdiImplV1_1_->Register(groupId, sensorCb);
#endif
        SENSOR_TRACE_FINISH;
        if (ret != SENSOR_SUCCESS) {
            HDF_LOGE("%{public}s Register failed, error code is %{public}d", __func__, ret);
            int32_t removeResult = RemoveSensorDeathRecipient(iRemoteObject);
            if (removeResult != SENSOR_SUCCESS) {
                HDF_LOGE("%{public}s: callback RemoveSensorDeathRecipient fail, groupId[%{public}d]",
                         __func__, groupId);
            }
        } else {
            SensorClientsManager::GetInstance()->ReportDataCbRegister(groupId, serviceId, callbackObj, true);
        }
    } else {
        SensorClientsManager::GetInstance()->ReportDataCbRegister(groupId, serviceId, callbackObj, true);
    }
    return ret;
}

int32_t SensorIfService::UnregisterAsync(int32_t groupId, const sptr<V3_0::ISensorCallback> &callbackObj)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: groupId %{public}d, service %{public}d", __func__, groupId, serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);
    if (groupId < TRADITIONAL_SENSOR_TYPE || groupId >= SENSOR_GROUP_TYPE_MAX) {
        HDF_LOGE("%{public}s: groupId %{public}d is error", __func__, groupId);
        return SENSOR_INVALID_PARAM;
    }
    const sptr<IRemoteObject> &iRemoteObject = OHOS::HDI::hdi_objcast<V3_0::ISensorCallback>(callbackObj);
    int32_t result = RemoveCallbackMap(groupId, serviceId, iRemoteObject);
    if (result !=SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s: RemoveCallbackMap failed groupId[%{public}d]", __func__, groupId);
    }
    SensorClientsManager::GetInstance()->ReportDataCbUnRegister(groupId, serviceId, callbackObj);
    if (!SensorClientsManager::GetInstance()->IsClientsEmpty(groupId)) {
        HDF_LOGD("%{public}s: clients is not empty, do not unregister", __func__);
        return HDF_SUCCESS;
    }
    if (!SensorClientsManager::GetInstance()->IsNoSensorUsed()) {
        HDF_LOGD("%{public}s: sensorUsed is not empty, do not unregister", __func__);
        return HDF_SUCCESS;
    }

    if (sensorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    sptr<SensorCallbackVdi> sensorCb = GetSensorCb(groupId, callbackObj, UNREGISTER_SENSOR);
    if (sensorCb == nullptr) {
        HDF_LOGE("%{public}s: get sensorcb fail, groupId[%{public}d]", __func__, groupId);
        return HDF_FAILURE;
    }
    SENSOR_TRACE_START("sensorVdiImplV1_1_->Unregister");
#ifdef TV_FLAG
    int32_t ret = sensorVdiImplV1_1_->Unregister(groupId, sensorCb);
#else
    int32_t ret = sensorVdiImplV1_1_->Unregister(groupId, sensorCb);
#endif
    SENSOR_TRACE_FINISH;
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s: Unregister failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t SensorIfService::GetDeviceSensorInfo(int32_t deviceId, std::vector<V3_0::HdfSensorInformation> &info)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: serviceId = %{public}d", __func__, serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);

    std::vector<OHOS::HDI::Sensor::V3_0::HdfSensorInformationVdi> sensorInfoVdi = {};

    int32_t ret = SENSOR_FAILURE;
    SENSOR_TRACE_START("sensorVdiImplV1_1_->GetAllSensorInfo");
#ifdef TV_FLAG
    ret = sensorVdiImplV1_1_->GetDeviceSensorInfo(deviceId, sensorInfoVdi);
#else
    HDF_LOGI("%{public}s: sensorVdiImplV1_1_ not support", __func__);
    ret = SENSOR_SUCCESS;
#endif
    SENSOR_TRACE_FINISH;

    if (sensorInfoVdi.empty()) {
        HDF_LOGI("%{public}s no sensor info in list, sensorInfoVdi is empty", __func__);
    }

    for (const auto &it : sensorInfoVdi) {
        struct V3_0::HdfSensorInformation sensorInfo = {};
        sensorInfo.sensorName = it.sensorName;
        sensorInfo.vendorName = it.vendorName;
        sensorInfo.firmwareVersion = it.firmwareVersion;
        sensorInfo.hardwareVersion = it.hardwareVersion;
        sensorInfo.maxRange = it.maxRange;
#ifdef TV_FLAG
        sensorInfo.deviceSensorInfo = {it.sensorHandle.deviceId, it.sensorHandle.sensorType, it.sensorHandle.sensorId,
                                       it.sensorHandle.location};
#else
        sensorInfo.deviceSensorInfo = {DEFAULT_DEVICE_ID, it.sensorId, DEFAULT_SENSOR_ID, DEFAULT_LOCATION};
#endif
        sensorInfo.accuracy = it.accuracy;
        sensorInfo.power = it.power;
        sensorInfo.minDelay = it.minDelay;
        sensorInfo.maxDelay = it.maxDelay;
        sensorInfo.fifoMaxEventCount = it.fifoMaxEventCount;
        info.push_back(std::move(sensorInfo));
    }

    return ret;
}

int32_t SensorIfService::RegSensorPlugCallBack(const sptr<V3_0::ISensorPlugCallback> &callbackObj)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: serviceId = %{public}d", __func__, serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);

    int32_t ret = SENSOR_FAILURE;
    SENSOR_TRACE_START("sensorVdiImplV1_1_->RegSensorPlugCallBack");
#ifdef TV_FLAG
    ret = sensorVdiImplV1_1_->RegSensorPlugCallBack(callbackObj);
#else
    HDF_LOGI("%{public}s: sensorVdiImplV1_1_ not support", __func__);
    ret = SENSOR_SUCCESS;
#endif
    SENSOR_TRACE_FINISH;

    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetOption failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t SensorIfService::UnRegSensorPlugCallBack(const sptr<V3_0::ISensorPlugCallback> &callbackObj)
{
    SENSOR_TRACE_PID;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s: serviceId = %{public}d", __func__, serviceId);
    std::unique_lock<std::mutex> lock(sensorServiceMutex_);

    int32_t ret = SENSOR_FAILURE;
    SENSOR_TRACE_START("sensorVdiImplV1_1_->UnRegSensorPlugCallBack");
#ifdef TV_FLAG
    ret = sensorVdiImplV1_1_->UnRegSensorPlugCallBack(callbackObj);
#else
    HDF_LOGI("%{public}s: sensorVdiImplV1_1_ not support", __func__);
    ret = SENSOR_SUCCESS;
#endif
    SENSOR_TRACE_FINISH;

    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetOption failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

} // namespace V3_0
} // namespace Sensor
} // namespace HDI
} // namespace OHOS