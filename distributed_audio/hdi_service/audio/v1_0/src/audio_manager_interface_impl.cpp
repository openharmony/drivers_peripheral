/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "audio_manager_interface_impl.h"

#include <cstdlib>
#include <hdf_base.h>
#include "hdf_device_object.h"
#include "iservice_registry.h"
#include "iproxy_broker.h"
#include "iservmgr_hdi.h"
#include <sstream>

#include "daudio_constants.h"
#include "daudio_errcode.h"
#include "daudio_events.h"
#include "daudio_log.h"
#include "daudio_utils.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioManagerInterfaceImpl"

using namespace OHOS::DistributedHardware;
namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
AudioManagerInterfaceImpl *AudioManagerInterfaceImpl::audioManager_ = nullptr;
std::mutex AudioManagerInterfaceImpl::audioManagerMtx_;
extern "C" IAudioManager *AudioManagerImplGetInstance(void)
{
    return AudioManagerInterfaceImpl::GetAudioManager();
}

AudioManagerInterfaceImpl::AudioManagerInterfaceImpl()
{
    DHLOGD("Distributed audio manager constructed.");
    audioManagerRecipient_ = sptr<AudioManagerRecipient>(new AudioManagerRecipient());
}

AudioManagerInterfaceImpl::~AudioManagerInterfaceImpl()
{
    DHLOGD("Distributed audio manager destructed.");
}

int32_t AudioManagerInterfaceImpl::GetAllAdapters(std::vector<AudioAdapterDescriptor> &descs)
{
    DHLOGI("Get all distributed audio adapters.");
    std::lock_guard<std::mutex> adpLck(adapterMapMtx_);

    std::transform(mapAudioAdapter_.begin(), mapAudioAdapter_.end(), std::back_inserter(descs),
        [](auto& adp) { return adp.second->GetAdapterDesc(); });

    DHLOGI("Get adapters success, total is (%{public}zu). ", mapAudioAdapter_.size());
    return HDF_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::LoadAdapter(const AudioAdapterDescriptor &desc, sptr<IAudioAdapter> &adapter)
{
    DHLOGI("Load distributed audio adapter: %{public}s.", GetAnonyString(desc.adapterName).c_str());
    std::lock_guard<std::mutex> adpLck(adapterMapMtx_);
    auto adp = mapAudioAdapter_.find(desc.adapterName);
    if (adp == mapAudioAdapter_.end()) {
        DHLOGE("Load audio adapter failed, can not find adapter.");
        adapter = nullptr;
        return HDF_FAILURE;
    }

    if (adp->second == nullptr) {
        DHLOGE("adapterimpl is nullptr.");
        return HDF_FAILURE;
    }

    int32_t ret = adp->second->AdapterLoad();
    if (ret != DH_SUCCESS) {
        DHLOGE("Load audio adapter failed, adapter return: %{public}d.", ret);
        adapter = nullptr;
        return HDF_FAILURE;
    }

    mapAddFlags_.clear();
    adapter = adp->second;
    DHLOGI("Load adapter success.");
    return HDF_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::UnloadAdapter(const std::string &adapterName)
{
    DHLOGI("Unload distributed audio adapter: %{public}s.", GetAnonyString(adapterName).c_str());
    std::lock_guard<std::mutex> adpLck(adapterMapMtx_);
    auto adp = mapAudioAdapter_.find(adapterName);
    if (adp == mapAudioAdapter_.end()) {
        DHLOGE("Unload audio adapter failed, can not find adapter.");
        return HDF_SUCCESS;
    }

    if (adp->second == nullptr) {
        DHLOGE("adapterimpl is nullptr.");
        return HDF_FAILURE;
    }
    
    int32_t ret = adp->second->AdapterUnload();
    if (ret != DH_SUCCESS) {
        DHLOGE("Unload audio adapter failed, adapter return: %{public}d.", ret);
        return ret;
    }
    DHLOGI("Unload adapter success.");
    return HDF_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::ReleaseAudioManagerObject()
{
    DHLOGD("Release distributed audio manager object.");
    return HDF_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::AddAudioDevice(const std::string &adpName, const uint32_t dhId,
    const std::string &caps, const sptr<IDAudioCallback> &callback)
{
    DHLOGI("Add audio device name: %{public}s, device: %{public}d.", GetAnonyString(adpName).c_str(), dhId);
    std::lock_guard<std::mutex> adpLck(adapterMapMtx_);
    auto adp = mapAudioAdapter_.find(adpName);
    if (adp == mapAudioAdapter_.end()) {
        int32_t ret = CreateAdapter(adpName, dhId, callback);
        if (ret != DH_SUCCESS) {
            DHLOGE("Create audio adapter failed.");
            return ERR_DH_AUDIO_HDF_FAIL;
        }
    }
    adp = mapAudioAdapter_.find(adpName);
    if (adp == mapAudioAdapter_.end() || adp->second == nullptr) {
        DHLOGE("Audio device has not been created  or is null ptr.");
        return ERR_DH_AUDIO_HDF_INVALID_OPERATION;
    }
    switch (GetDevTypeByDHId(dhId)) {
        case AUDIO_DEVICE_TYPE_SPEAKER:
            adp->second->SetSpeakerCallback(dhId, callback);
            break;
        case AUDIO_DEVICE_TYPE_MIC:
            adp->second->SetMicCallback(dhId, callback);
            break;
        default:
            DHLOGE("DhId is illegal, devType is unknow.");
            return ERR_DH_AUDIO_HDF_FAIL;
    }
    int32_t ret = adp->second->AddAudioDevice(dhId, caps);
    if (ret != DH_SUCCESS) {
        DHLOGE("Add audio device failed, adapter return: %{public}d.", ret);
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    std::string flagString = adpName + std::to_string(dhId);
    if (mapAddFlags_.find(flagString) == mapAddFlags_.end()) {
        DAudioDevEvent event = { adpName, dhId, HDF_AUDIO_DEVICE_ADD, 0, adp->second->GetVolumeGroup(dhId),
            adp->second->GetInterruptGroup(dhId), caps };
        ret = AddAudioDeviceInner(dhId, event);
        if (ret != DH_SUCCESS) {
            return ret;
        }
        mapAddFlags_.insert(std::make_pair(flagString, true));
    }
    sptr<IRemoteObject> remote = GetRemote(adpName);
    if (remote != nullptr) {
        AddClearRegisterRecipient(remote, adpName, dhId);
    }
    DHLOGI("Add audio device success.");
    return DH_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::AddAudioDeviceInner(const uint32_t dhId, const DAudioDevEvent &event)
{
    int32_t ret = DH_SUCCESS;
    if (dhId != LOW_LATENCY_RENDER_ID) {
        int32_t ret = NotifyFwk(event);
        if (ret != DH_SUCCESS) {
            DHLOGE("Notify audio fwk failed, ret = %{public}d.", ret);
            return ret;
        }
    }
    return ret;
}

int32_t AudioManagerInterfaceImpl::RemoveAudioDevice(const std::string &adpName, const uint32_t dhId)
{
    DHLOGI("Remove audio device name: %{public}s, device: %{public}d.", GetAnonyString(adpName).c_str(), dhId);
    auto adapter = GetAdapterFromMap(adpName);
    CHECK_NULL_RETURN(adapter, ERR_DH_AUDIO_HDF_INVALID_OPERATION);

    int32_t ret = adapter->RemoveAudioDevice(dhId);
    if (ret != DH_SUCCESS) {
        DHLOGE("Remove audio device failed, adapter return: %{public}d.", ret);
        return ret;
    }
    DAudioDevEvent event = { adpName, dhId, HDF_AUDIO_DEVICE_REMOVE, 0, 0, 0 };
    ret = NotifyFwk(event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify audio fwk failed, ret = %{public}d.", ret);
    }
    mapAddFlags_.erase(adpName + std::to_string(dhId));
    {
        std::lock_guard<std::mutex> adpLck(adapterMapMtx_);
        if (adapter->IsPortsNoReg()) {
            mapAudioAdapter_.erase(adpName);
            sptr<IRemoteObject> remote = GetRemote(adpName);
            if (remote != nullptr) {
                RemoveClearRegisterRecipient(remote, adpName, dhId);
            }
            mapAudioCallback_.erase(adpName);
        }
        DHLOGI("Remove audio device success, mapAudioAdapter size() is : %zu .", mapAudioAdapter_.size());
    }
    return DH_SUCCESS;
}

sptr<AudioAdapterInterfaceImpl> AudioManagerInterfaceImpl::GetAdapterFromMap(const std::string &adpName)
{
    std::lock_guard<std::mutex> adpLck(adapterMapMtx_);
    auto adp = mapAudioAdapter_.find(adpName);
    if (adp == mapAudioAdapter_.end()) {
        DHLOGE("Audio device is not found.");
        return nullptr;
    }
    return adp->second;
}

int32_t AudioManagerInterfaceImpl::Notify(const std::string &adpName, const uint32_t devId,
    const uint32_t streamId, const DAudioEvent &event)
{
    DHLOGI("Notify event, adapter name: %{public}s. event type: %{public}d", GetAnonyString(adpName).c_str(),
        event.type);
    sptr<AudioAdapterInterfaceImpl> adp = nullptr;
    {
        std::lock_guard<std::mutex> adpLck(adapterMapMtx_);
        auto adpIter = mapAudioAdapter_.find(adpName);
        if (adpIter == mapAudioAdapter_.end()) {
            DHLOGE("Notify failed, can not find adapter.");
            return ERR_DH_AUDIO_HDF_INVALID_OPERATION;
        }
        adp = adpIter->second;
    }
    if (adp == nullptr) {
        DHLOGE("The audio adapter is nullptr.");
        return ERR_DH_AUDIO_HDF_NULLPTR;
    }
    int32_t ret = adp->Notify(devId, streamId, event);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify failed, adapter return: %{public}d.", ret);
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    return DH_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::NotifyFwk(const DAudioDevEvent &event)
{
    DHLOGD("Notify audio fwk event(type:%{public}d, adapter:%{public}s, pin:%{public}d).", event.eventType,
        GetAnonyString(event.adapterName).c_str(), event.dhId);
    std::stringstream ss;
    ss << "EVENT_TYPE=" << event.eventType << ";NID=" << event.adapterName << ";PIN=" << event.dhId << ";VID=" <<
        event.volGroupId << ";IID=" << event.iptGroupId;

    if (event.caps.find("Daudio") == std::string::npos) {
        DHLOGI("Not daudio.");
        ss << ";CAPS=" << event.caps;
    } else {
        DHLOGI("Is daudio.");
    }

    std::string eventInfo = ss.str();
    int ret = HdfDeviceObjectSetServInfo(deviceObject_, eventInfo.c_str());
    if (ret != HDF_SUCCESS) {
        DHLOGE("Set service info failed, ret = %{public}d.", ret);
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    ret = HdfDeviceObjectUpdate(deviceObject_);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Update service info failed, ret = %{public}d.", ret);
        return ERR_DH_AUDIO_HDF_FAIL;
    }

    DHLOGI("Notify audio fwk success.");
    return DH_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::CreateAdapter(const std::string &adpName, const uint32_t devId,
    const sptr<IDAudioCallback> &callback)
{
    DHLOGI("Create adapter, pin id: %{public}s.", GetChangeDevIdMap(static_cast<int32_t>(devId)).c_str());
    if (callback == nullptr) {
        DHLOGE("Adapter callback is null.");
        return ERR_DH_AUDIO_HDF_NULLPTR;
    }
    if (devId != DEFAULT_RENDER_ID && devId != DEFAULT_CAPTURE_ID && devId != LOW_LATENCY_RENDER_ID) {
        DHLOGE("Pin is not default, can not create audio adapter.");
        return ERR_DH_AUDIO_HDF_FAIL;
    }

    AudioAdapterDescriptor desc = { adpName };
    sptr<AudioAdapterInterfaceImpl> adapter(new AudioAdapterInterfaceImpl(desc));
    if (adapter == nullptr) {
        DHLOGE("Create new audio adapter failed.");
        return ERR_DH_AUDIO_HDF_NULLPTR;
    }
    mapAudioAdapter_.insert(std::make_pair(adpName, adapter));
    mapAudioCallback_.insert(std::make_pair(adpName, callback));
    return DH_SUCCESS;
}

void AudioManagerInterfaceImpl::SetDeviceObject(struct HdfDeviceObject *deviceObject)
{
    deviceObject_ = deviceObject;
}

int32_t AudioManagerInterfaceImpl::RegisterAudioHdfListener(const std::string &serviceName,
    const sptr<IDAudioHdfCallback> &callbackObj)
{
    DHLOGI("Register audio HDF listener, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    if (callbackObj == nullptr) {
        DHLOGE("Audio hdf callback is null.");
        return HDF_FAILURE;
    }
    sptr<IRemoteObject> remote = OHOS::HDI::hdi_objcast<IDAudioHdfCallback>(callbackObj);
    if (remote == nullptr) {
        DHLOGE("Remote callback is nullptr.");
        return ERR_DH_AUDIO_HDF_NULLPTR;
    }
    if (!remote->AddDeathRecipient(audioManagerRecipient_)) {
        DHLOGE("AddDeathRecipient failed, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    std::lock_guard<std::mutex> lock(hdfCallbackMapMtx_);
    if (mapAudioHdfCallback_.find(serviceName) != mapAudioHdfCallback_.end()) {
        DHLOGI("The callback has been registered and will be replaced, serviceName: %{public}s.",
            GetAnonyString(serviceName).c_str());
    }
    mapAudioHdfCallback_[serviceName] = callbackObj;
    DHLOGI("Register audio HDF listener suncess, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    return DH_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::UnRegisterAudioHdfListener(const std::string &serviceName)
{
    DHLOGI("Unregister audio HDF listener, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    std::lock_guard<std::mutex> lock(hdfCallbackMapMtx_);
    auto itCallback = mapAudioHdfCallback_.find(serviceName);
    if (itCallback == mapAudioHdfCallback_.end() || itCallback->second == nullptr) {
        DHLOGE("Audio HDF callback has not been created or is null ptr.");
        return ERR_DH_AUDIO_HDF_NULLPTR;
    }
    sptr<IRemoteObject> remote = OHOS::HDI::hdi_objcast<IDAudioHdfCallback>(itCallback->second);
    if (remote == nullptr) {
        DHLOGE("Remote callback is nullptr.");
        return ERR_DH_AUDIO_HDF_NULLPTR;
    }
    if (!remote->RemoveDeathRecipient(audioManagerRecipient_)) {
        DHLOGE("RemoveDeathRecipient failed, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    mapAudioHdfCallback_.erase(itCallback);
    DHLOGI("Unregister audio HDF listener suncess, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    return DH_SUCCESS;
}

void AudioManagerInterfaceImpl::ClearRegisterRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    DHLOGI("Remote died, remote daudio device begin.");
    auto audioMgr = AudioManagerInterfaceImpl::GetAudioManager();
    if (audioMgr != nullptr) {
        audioMgr->RemoveAudioDevice(deviceId_, dhId_);
    }
    needErase_ = true;
    DHLOGI("Remote died, remote daudio device end.");
}

void AudioManagerInterfaceImpl::AudioManagerRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    DHLOGE("Exit the current process.");
    _Exit(0);
}

sptr<IRemoteObject> AudioManagerInterfaceImpl::GetRemote(const std::string &adpName)
{
    auto call = mapAudioCallback_.find(adpName);
    if (call == mapAudioCallback_.end() || call->second == nullptr) {
        DHLOGE("Audio callback has not been created or is null ptr.");
        return nullptr;
    }
    sptr<IRemoteObject> remote = OHOS::HDI::hdi_objcast<IDAudioCallback>(call->second);
    if (remote == nullptr) {
        DHLOGE("Remote callback is nullptr.");
        return nullptr;
    }
    return remote;
}

int32_t AudioManagerInterfaceImpl::AddClearRegisterRecipient(sptr<IRemoteObject> &remote,
    const std::string &deviceId, uint32_t dhId)
{
    DHLOGI("add clear register recipient begin.");
    auto clearRegisterRecipient = sptr<ClearRegisterRecipient>(new ClearRegisterRecipient(deviceId, dhId));
    if (clearRegisterRecipient == nullptr) {
        DHLOGE("Create clear register recipient object failed.");
        return ERR_DH_AUDIO_HDF_NULLPTR;
    }
    if (remote->AddDeathRecipient(clearRegisterRecipient) == false) {
        DHLOGE("call AddDeathRecipient failed.");
        return ERR_DH_AUDIO_HDF_FAIL;
    }
    std::lock_guard<std::mutex> lock(clearRegisterRecipientsMtx_);
    clearRegisterRecipients_.erase(std::remove_if(clearRegisterRecipients_.begin(), clearRegisterRecipients_.end(),
        [](sptr<ClearRegisterRecipient> &clearRegisterRecipient) {
            return clearRegisterRecipient->IsNeedErase();
        }), clearRegisterRecipients_.end());
    clearRegisterRecipients_.push_back(clearRegisterRecipient);
    DHLOGI("add clear register recipient end.");
    return DH_SUCCESS;
}

int32_t AudioManagerInterfaceImpl::RemoveClearRegisterRecipient(sptr<IRemoteObject> &remote,
    const std::string &deviceId, uint32_t dhId)
{
    DHLOGI("remove clear register recipient begin.");
    std::lock_guard<std::mutex> lock(clearRegisterRecipientsMtx_);
    for (auto itRecipient = clearRegisterRecipients_.begin();
        itRecipient != clearRegisterRecipients_.end(); ++itRecipient) {
        auto &clearRegisterRecipient = *itRecipient;
        if (clearRegisterRecipient->IsMatch(deviceId, dhId)) {
            if (remote->RemoveDeathRecipient(clearRegisterRecipient) == false) {
                DHLOGE("call RemoveDeathRecipient failed.");
            }
            clearRegisterRecipients_.erase(itRecipient);
            DHLOGI("remove one clear register recipient.");
            break;
        }
    }
    DHLOGI("remove clear register recipient end.");
    return DH_SUCCESS;
}
} // V1_0
} // Audio
} // Distributedaudio
} // HDI
} // OHOSf
