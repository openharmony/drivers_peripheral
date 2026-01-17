/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002BD0
#include "midi_driver_controller.h"
#include "ump_packet.h"
#include "ump_processor.h"
#include <fstream>
#include <hdf_base.h>
#include <hdf_log.h>
#include <iostream>
#include <sstream>
#include <sys/eventfd.h>
#include <unordered_set>
#include <iomanip>


#define HDF_LOG_TAG midi_driver_controller

namespace OHOS {
namespace HDI {
namespace Midi {
namespace V1_0 {
static constexpr size_t WorkBufferSize = sizeof(uint32_t) * 256;
static void ReadVendorIdAndProductId(int32_t card, std::string &idVendor, std::string &idProduct)
{
    std::string path = "/proc/asound/card" + std::to_string(card) + "/usbid";
    std::ifstream file(path);
    idVendor = "";
    idProduct = "";
    if (!file.is_open()) {
        return;
    }
    std::string line;
    if (!std::getline(file, line)) {
        return;
    }
    size_t colon_pos = line.find(':');
    if (colon_pos == std::string::npos) {
        return;
    }

    idVendor = line.substr(0, colon_pos);
    idProduct = line.substr(colon_pos + 1);
}

static void ReadUsbBus(int32_t card, std::string &bus)
{
    std::string path = "/proc/asound/card" + std::to_string(card) + "/usbbus";
    std::ifstream file(path);
    if (!file.is_open()) {
        return;
    }
    if (!std::getline(file, bus)) {
        return;
    }
}

static int64_t MakeDeviceId(int32_t card)
{
    std::string idVendor;
    std::string idProduct;
    std::string usbbus;

    ReadVendorIdAndProductId(card, idVendor, idProduct);
    ReadUsbBus(card, usbbus);
    std::hash<std::string> hasher;
    return hasher(idVendor + idProduct + usbbus);
}

static std::string MakeDeviceFileName(int32_t card, int32_t device)
{
    char devfile[128];
    ::snprintf(devfile, sizeof(devfile), "midiC%dD%d", card, device);
    return devfile;
}

static std::string MakeHwName(int32_t card, int32_t device, int32_t subdevice)
{
    return "hw:" + std::to_string(card) + "," + std::to_string(device) + "," + std::to_string(subdevice);
}

static std::vector<MidiPortInfo> MakeMidiPortInfos(const DeviceInfo device)
{
    std::vector<MidiPortInfo> portInfos;
    uint32_t portId = 0;
    for (const auto &port : device.outputPorts) {
        MidiPortInfo portInfo;
        portInfo.portId = portId++;
        portInfo.name = port.name;
        portInfo.direction = PORT_DIRECTION_OUTPUT;
        portInfos.push_back(portInfo);
    }

    for (const auto &port : device.inputPorts) {
        MidiPortInfo portInfo;
        portInfo.portId = portId++;
        portInfo.name = port.name;
        portInfo.direction = PORT_DIRECTION_INPUT;
        portInfos.push_back(portInfo);
    }
    return portInfos;
}

static std::vector<MidiDeviceInfo> MakeMidiDeviceInfos(const std::vector<DeviceInfo> &deviceInfos)
{
    std::vector<MidiDeviceInfo> devices;
    for (const auto &device : deviceInfos) {
        MidiDeviceInfo dev;
        dev.deviceId = device.deviceId;
        dev.productName = device.idProduct;
        dev.vendorName = device.idVendor;
        dev.protocol = device.is_ump ? MIDI_PROTOCOL_2_0 : MIDI_PROTOCOL_1_0;
        dev.ports = MakeMidiPortInfos(device);
        devices.push_back(dev);
    }
    return devices;
}

static void ConvertUmpToMidi1(const uint32_t* umpData, size_t count, std::vector<uint8_t>& midi1Bytes)
{
    for (size_t i = 0; i < count; ++i) {
        uint32_t ump = umpData[i];
        uint8_t mt = (ump >> 28) & 0xF; // Message Type

        if (mt == 0x2) { 
            // Type 2: MIDI 1.0 Channel Voice Messages (32-bit)
            // Format: [4b MT][4b Group][4b Status][4b Channel] [8b Note/Data1][8b Vel/Data2]
            // Note: In UMP, Status includes Channel. UMP: 0x2GSCDD       
            uint8_t status = (ump >> 16) & 0xFF;
            uint8_t data1 = (ump >> 8) & 0xFF;
            uint8_t data2 = ump & 0xFF;
            
            uint8_t cmd = status & 0xF0;

            midi1Bytes.push_back(status);
            
            // Program Change (0xC0) and Channel Pressure (0xD0) are 2 bytes
            if (cmd == 0xC0 || cmd == 0xD0) {
                midi1Bytes.push_back(data1);
            } else {
                // Note On, Note Off, Poly Pressure, Control Change, Pitch Bend are 3 bytes
                midi1Bytes.push_back(data1);
                midi1Bytes.push_back(data2);
            }
        } 
        else if (mt == 0x1) {
            // Type 1: System Common / Real Time Messages (32-bit)
            // Format: [4b MT][4b Group][8b Status][8b Data1][8b Data2]
            uint8_t status = (ump >> 16) & 0xFF;
            uint8_t data1 = (ump >> 8) & 0xFF;
            uint8_t data2 = ump & 0xFF;

            midi1Bytes.push_back(status);

            switch (status) {
                case 0xF1: // MIDI Time Code Quarter Frame (2 bytes)
                case 0xF3: // Song Select (2 bytes)
                    midi1Bytes.push_back(data1);
                    break;
                case 0xF2: // Song Position Pointer (3 bytes)
                    midi1Bytes.push_back(data1);
                    midi1Bytes.push_back(data2);
                    break;
                case 0xF6: // Tune Request (1 byte)
                case 0xF8: // Timing Clock (1 byte)
                case 0xFA: // Start (1 byte)
                case 0xFB: // Continue (1 byte)
                case 0xFC: // Stop (1 byte)
                case 0xFE: // Active Sensing (1 byte)
                case 0xFF: // Reset (1 byte)
                    // No data bytes
                    break;
                default:
                    // 0xF0 (Sysex Start) and 0xF7 (Sysex End) are handled in Type 3 usually, 
                    // but simple 1-packet sysex might appear here.
                    break;
            }
        }
    }
}

// 单例实例
static MidiDriverController *g_instance = nullptr;

MidiDriverController *MidiDriverController::GetInstance()
{
    if (g_instance == nullptr) {
        g_instance = new MidiDriverController();
    }
    return g_instance;
}

void MidiDriverController::CleanupRemovedDevices(const std::vector<DeviceInfo> &oldDeviceList)
{
    std::unordered_set<int64_t> newDeviceIds;
    std::unordered_set<int64_t> oldDeviceIds;

    // 收集新旧设备ID
    for (const auto &device : deviceList_) {
        newDeviceIds.insert(device.deviceId);
    }
    for (const auto &device : oldDeviceList) {
        oldDeviceIds.insert(device.deviceId);
    }

    std::vector<int64_t> removedDevices;
    for (const auto &deviceId : oldDeviceIds) {
        if (newDeviceIds.find(deviceId) == newDeviceIds.end()) {
            removedDevices.push_back(deviceId);
        }
    }

    for (const auto &deviceId : removedDevices) {
        HDF_LOGI("%{public}s: Cleaning up resources for removed device: %{public}lld", __func__,
            static_cast<long long>(deviceId));
        CleanupDeviceInputPorts(deviceId);
        auto it = std::find(activeDevice_.begin(), activeDevice_.end(), deviceId);
        if (it != activeDevice_.end()) {
            activeDevice_.erase(it);
            HDF_LOGI("%{public}s: Removed device %{public}lld from active device list", __func__,
                static_cast<long long>(deviceId));
        }
    }
}

void MidiDriverController::CleanupDeviceInputPorts(int64_t deviceId)
{
    std::vector<std::shared_ptr<InputThreadContext>> portsToClose;
    for (auto it = inputCtxs.begin(); it != inputCtxs.end();) {
        if ((*it)->deviceId == deviceId) {
            portsToClose.push_back(*it);
            it = inputCtxs.erase(it);
        } else {
            ++it;
        }
    }
    for (auto &ctx : portsToClose) {
        HDF_LOGI("%{public}s: Closing input port for device %{public}lld, port %{public}d", __func__,
            static_cast<long long>(deviceId), ctx->portIndex);
        ctx->quit = true;
        if (ctx->thread.joinable()) {
            ctx->thread.join();
        }
        if (ctx->rawmidi != nullptr) {
            ::snd_rawmidi_close(ctx->rawmidi);
            ctx->rawmidi = nullptr;
        }
    }
}

void MidiDriverController::EnumerationDeviceMidi1()
{
    std::vector<DeviceInfo> oldDeviceList = deviceList_;
    deviceList_.clear();
    HDF_LOGI("%{public}s EnumerationDeviceMidi1 Start,", __func__);
    int32_t card = -1;
    while (1) {
        if (::snd_card_next(&card) < 0 || card < 0) {
            break;
        }
        char card_name[32];
        ::snprintf(card_name, sizeof(card_name), "hw:%d", card);
        snd_ctl_t *ctl = nullptr;
        if (::snd_ctl_open(&ctl, card_name, 0) < 0) {
            continue;
        }
        int32_t device = -1;
        while (1) {
            if (::snd_ctl_rawmidi_next_device(ctl, &device) < 0 || device < 0) {
                break;
            }
            DeviceInfo devinfo;
            devinfo.deviceId = MakeDeviceId(card);
            devinfo.devfile = MakeDeviceFileName(card, device);
            devinfo.card = card;
            devinfo.device = device;
            devinfo.is_ump = false;
            ReadVendorIdAndProductId(card, devinfo.idVendor, devinfo.idProduct);

            for (auto direction = 0; direction < 2; ++direction) { // 0 : output, 1 : input
                snd_rawmidi_info_t *info;
                snd_rawmidi_info_alloca(&info);
                ::snd_rawmidi_info_set_device(info, device);
                ::snd_rawmidi_info_set_stream(info, static_cast<snd_rawmidi_stream_t>(direction));
                ::snd_rawmidi_info_set_subdevice(info, 0);
                if (::snd_ctl_rawmidi_info(ctl, info) < 0) {
                    continue;
                }
                std::string devname = ::snd_rawmidi_info_get_name(info);
                int32_t subdevices_count = ::snd_rawmidi_info_get_subdevices_count(info);

                for (int32_t sub = 0; sub < subdevices_count; ++sub) {
                    ::snd_rawmidi_info_set_subdevice(info, sub);
                    if (::snd_ctl_rawmidi_info(ctl, info) < 0) {
                        continue;
                    }
                    PortInfo portInfo;
                    const char *name = ::snd_rawmidi_info_get_subdevice_name(info);
                    portInfo.name = name != nullptr ? name : devname + " " + std::to_string(sub);
                    portInfo.card = card;
                    portInfo.device = device;
                    portInfo.subdevice = sub;
                    portInfo.groups = 0;
                    portInfo.umpStartGroup = 0;
                    portInfo.numUmpGroupsSpanned = 0;
                    if (direction == 0) {
                        devinfo.outputPorts.push_back(portInfo);
                    } else {
                        devinfo.inputPorts.push_back(portInfo);
                    }
                }
            }
            HDF_LOGI("%{public}s Card: %{public}d, device:%{public}d idVendor:%{public}s, idProduct:%{public}s,",
                __func__, devinfo.card, devinfo.device, devinfo.idVendor.c_str(), devinfo.idProduct.c_str());
            deviceList_.push_back(devinfo);
        }
        ::snd_ctl_close(ctl);
    }
    CleanupRemovedDevices(oldDeviceList);
}

void MidiDriverController::EnumerationDeviceMidi2()
{
    // todo: implement
}

int32_t MidiDriverController::GetDeviceList(std::vector<MidiDeviceInfo> &deviceList)
{
    std::vector<MidiDeviceInfo> deviceInfos;
    EnumerationDeviceMidi1();
    EnumerationDeviceMidi2();
    deviceList = MakeMidiDeviceInfos(deviceList_);
    return HDF_SUCCESS;
}

static int32_t Find(std::vector<DeviceInfo> deviceList, int64_t deviceId)
{
    for (size_t i = 0; i < deviceList.size(); i++) {
        if (deviceList[i].deviceId == deviceId) {
            return i;
        }
    }
    return -1;
}

int32_t MidiDriverController::OpenDevice(int64_t deviceId)
{

    if (Find(deviceList_, deviceId) == -1) {
        return HDF_FAILURE;
    }
    auto it = std::find(activeDevice_.begin(), activeDevice_.end(), deviceId);
    if (it != activeDevice_.end()) {
        return HDF_FAILURE;
    }
    activeDevice_.push_back(deviceId);
    return HDF_SUCCESS;
}

int32_t MidiDriverController::CloseDevice(int64_t deviceId)
{
    auto it = std::find(activeDevice_.begin(), activeDevice_.end(), deviceId);
    if (it == activeDevice_.end()) {
        return HDF_FAILURE;
    }
    activeDevice_.erase(it);
    return HDF_SUCCESS;
}

std::shared_ptr<InputThreadContext> MidiDriverController::FindInputContext(int64_t deviceId, uint32_t portId)
{
    for (auto ctx : inputCtxs) {
        if (ctx != nullptr && ctx->deviceId == deviceId && ctx->portIndex == portId) {
            return ctx;
        }
    }
    return nullptr;
}

int32_t MidiDriverController::OpenInputPort(int64_t deviceId, uint32_t portId, const sptr<IMidiCallback> &dataCallback)
{
    auto index = Find(deviceList_, deviceId);
    if (index == -1) {
        HDF_LOGI("%{public}s can not find deviceId : %{public}ld.", __func__, deviceId);
        return HDF_FAILURE;
    }

    auto it = std::find(activeDevice_.begin(), activeDevice_.end(), deviceId);
    if (it == activeDevice_.end()) {
        HDF_LOGI("%{public}s can not find deviceId: %{public}ld.", __func__, deviceId);
        return HDF_FAILURE;
    }

    if (portId < deviceList_[index].outputPorts.size()) {
        HDF_LOGI("%{public}s portId error.", __func__);
        return HDF_FAILURE;
    }
    if (FindInputContext(deviceId, portId) != nullptr) {
        HDF_LOGI("%{public}s already opened.", __func__);
        return HDF_FAILURE;
    }
    auto portIndex = portId - deviceList_[index].outputPorts.size();
    if (portIndex >= deviceList_[index].inputPorts.size()) {
        HDF_LOGI("%{public}s portId error.", __func__);
        return HDF_FAILURE;
    }
    const auto &port = deviceList_[index].inputPorts[portIndex];
    snd_rawmidi_t * rawmidi;
    auto hwname = MakeHwName(port.card, port.device, port.subdevice);
    auto result = ::snd_rawmidi_open(&rawmidi, nullptr, hwname.c_str(), SND_RAWMIDI_NONBLOCK);
    if (result < 0) {
        HDF_LOGI("%{public}s snd_rawmidi_open error : %{public}d, name :%{public}s", __func__, result, hwname.c_str());
        return HDF_FAILURE;
    }
    auto count = ::snd_rawmidi_poll_descriptors_count(rawmidi);
    if (count <= 0) {
        ::snd_rawmidi_close(rawmidi);
        HDF_LOGI("%{public}s snd_rawmidi_poll_descriptors_count error : %{public}d", __func__, count);
        return HDF_FAILURE;
    }

    std::vector<struct pollfd> pfds {static_cast<std::size_t>(count)};
    ::snd_rawmidi_poll_descriptors(rawmidi, &pfds[0], POLLIN);
    auto ctx = std::make_shared<InputThreadContext>();
    ctx->deviceId = deviceId;
    ctx->portIndex = portId;
    ctx->quit = false;
    ctx->rawmidi = rawmidi;
    ctx->pfds = pfds;
    ctx->dataCallback = dataCallback;
    ctx->thread = std::thread(
        [this](std::shared_ptr<InputThreadContext> ctx) {
            this->InputThread(ctx);
        },
        ctx);
    inputCtxs.push_back(std::move(ctx));
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

void MidiDriverController::InputThread(std::shared_ptr<InputThreadContext> ctx)
{
    HDF_LOGI("%{public}s enter", __func__);
    EpollHandler epoll;
    struct epoll_event event[ctx->pfds.size()];
    for (size_t i = 0; i < ctx->pfds.size(); i++) {
        epoll.add(ctx->pfds[i].fd, event[i], EPOLLIN);
    }
    auto src = std::make_unique<uint8_t[]>(WorkBufferSize);
    std::vector<MidiMessage> eventList;
    while (ctx->quit == false) {
        epoll.poll([&](void *, int32_t) {
            // struct timespec ts;
            auto len = ::snd_rawmidi_read(ctx->rawmidi, src.get(), WorkBufferSize);
            if (len < 0) {
                HDF_LOGI("%{public}s snd_rawmidi_read error : %{public}ld", __func__, len);
                ctx->quit = true;
                return;
            }
            // uint64_t tstamp = (ts.tv_sec * 1000 * 1000 * 1000) + ts.tv_nsec;
            std::ostringstream midiStream;
            for (size_t i = 0; i < static_cast<size_t>(len); i++) {
                midiStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(src[i]) << " ";
            }
            HDF_LOGI("%{public}s midiStream 1.0: %{public}s", __func__, midiStream.str().c_str());
            if (len == 1 && src[0] == 0xF8) {
                return;
            }
            UmpProcessor processor;
            std::vector<UmpPacket> results;
            processor.ProcessBytes(src.get(), static_cast<size_t>(len), [&](const UmpPacket &p) {
                results.push_back(p);
            });
            for (auto p : results) {
                std::ostringstream umpStream;
                for (uint8_t i = 0; i < p.WordCount(); i++) {
                    umpStream << std::hex << std::setw(8) << std::setfill('0') << p.Word(i) << " ";
                }
                HDF_LOGI("%{public}s umpStream 1.0: %{public}s", __func__, umpStream.str().c_str());
            }
            if (ctx->dataCallback) {
                MidiMessage message;
                message.timestamp = 0;
                for (auto p : results) {
                    for (uint8_t i = 0; i < p.WordCount(); i++) {
                        message.data.push_back(p.Word(i));
                    }
                }
                eventList.push_back(message);
                ctx->dataCallback->OnMidiDataReceived(eventList);
                eventList.clear();
            }
        });
    }
    for (size_t i = 0; i < ctx->pfds.size(); i++) {
        epoll.del(ctx->pfds[i].fd, event[i]);
    }
    epoll.finalize();
    HDF_LOGI("%{public}s InputThread: end\n", __func__);
}

int32_t MidiDriverController::CloseInputPort(int64_t deviceId, uint32_t portId)
{
    auto ctx = FindInputContext(deviceId, portId);
    if (ctx == nullptr) {
        return HDF_FAILURE;
    }
    ctx->quit = true;
    ctx->thread.join();
    if (ctx->rawmidi != nullptr) {
        ::snd_rawmidi_close(ctx->rawmidi);
    }
    for (auto it = inputCtxs.begin(); it != inputCtxs.end(); it++) {
        if (it->get()->deviceId == deviceId && it->get()->portIndex == portId) {
            inputCtxs.erase(it);
            return HDF_SUCCESS;
        }
    }
    return HDF_SUCCESS;
}

std::shared_ptr<OutputContext> MidiDriverController::FindOutputContext(int64_t deviceId, uint32_t portId)
{
    std::lock_guard<std::mutex> lock(outputMutex_);
    for (auto ctx : outputCtxs_) {
        if (ctx != nullptr && ctx->deviceId == deviceId && ctx->portIndex == portId) {
            return ctx;
        }
    }
    return nullptr;
}

int32_t MidiDriverController::OpenOutputPort(int64_t deviceId, uint32_t portId)
{
    HDF_LOGI("%{public}s deviceId:%{public}lld portId:%{public}u", __func__, (long long)deviceId, portId);

    auto index = Find(deviceList_, deviceId);
    if (index == -1) {
        HDF_LOGE("%{public}s cannot find deviceId", __func__);
        return HDF_FAILURE;
    }

    auto it = std::find(activeDevice_.begin(), activeDevice_.end(), deviceId);
    if (it == activeDevice_.end()) {
        HDF_LOGE("%{public}s device not active", __func__);
        return HDF_FAILURE;
    }

    if (FindOutputContext(deviceId, portId) != nullptr) {
        HDF_LOGI("%{public}s port already opened", __func__);
        return HDF_SUCCESS;
    }

    const auto &devInfo = deviceList_[index];
    bool isUmp = devInfo.is_ump;

    if (portId >= devInfo.outputPorts.size()) {
        HDF_LOGE("%{public}s Invalid output port index", __func__);
        return HDF_FAILURE;
    }
    const auto &portInfo = devInfo.outputPorts[portId];

    auto ctx = std::make_shared<OutputContext>();
    ctx->deviceId = deviceId;
    ctx->portIndex = portId;
    ctx->isUmp = isUmp;

    if (isUmp) {
        // todo: implement
    } else {
        snd_rawmidi_t *rawmidi = nullptr;
        std::string hwname = MakeHwName(portInfo.card, portInfo.device, portInfo.subdevice);
        int err = ::snd_rawmidi_open(NULL, &rawmidi, hwname.c_str(), 0); 
        if (err < 0) {
            HDF_LOGE("%{public}s snd_rawmidi_open failed: %{public}d", __func__, err);
            return HDF_FAILURE;
        }
        ctx->rawmidi = rawmidi;
    }
    {
        std::lock_guard<std::mutex> lock(outputMutex_);
        outputCtxs_.push_back(ctx);
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t MidiDriverController::CloseOutputPort(int64_t deviceId, uint32_t portId)
{
    HDF_LOGI("%{public}s deviceId:%{public}lld portId:%{public}u", __func__, (long long)deviceId, portId);
    
    std::shared_ptr<OutputContext> ctx = nullptr;
    {
        std::lock_guard<std::mutex> lock(outputMutex_);
        for (auto it = outputCtxs_.begin(); it != outputCtxs_.end(); ++it) {
            if ((*it)->deviceId == deviceId && (*it)->portIndex == portId) {
                ctx = *it;
                outputCtxs_.erase(it);
                break;
            }
        }
    }

    if (ctx == nullptr) {
        HDF_LOGW("%{public}s context not found or already closed", __func__);
        return HDF_SUCCESS;
    }

    if (ctx->isUmp && ctx->ump) {
        // todo: implement
    } else if (!ctx->isUmp && ctx->rawmidi) {
        ::snd_rawmidi_close(ctx->rawmidi);
        ctx->rawmidi = nullptr;
    }

    return HDF_SUCCESS;
}

int32_t MidiDriverController::SendMidiMessages(
    int64_t deviceId, uint32_t portId, const std::vector<MidiMessage> &messages)
{

    auto ctx = FindOutputContext(deviceId, portId);
    if (ctx == nullptr) {
        HDF_LOGE("%{public}s output port not open", __func__);
        return HDF_FAILURE;
    }

    if (ctx->isUmp) {
        // todo: implement
    } else {
        if (ctx->rawmidi) {
            for (const auto& msg : messages) {
                std::vector<uint8_t> midi1Buffer;
                ConvertUmpToMidi1(msg.data.data(), msg.data.size(), midi1Buffer);
                if (!midi1Buffer.empty()) {
                    long written = ::snd_rawmidi_write(ctx->rawmidi, midi1Buffer.data(), midi1Buffer.size());
                    if (written < 0) {
                        HDF_LOGE("%{public}s snd_rawmidi_write failed: %{public}ld", __func__, written);
                        return HDF_FAILURE;
                    }
                }
            }
        }
    }

    return HDF_SUCCESS;
}
} // namespace V1_0
} // namespace Midi
} // namespace HDI
} // namespace OHOS