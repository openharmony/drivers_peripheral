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

#ifndef OHOS_HDI_MIDI_V1_0_MIDIDRIVERCONTROLLER_H
#define OHOS_HDI_MIDI_V1_0_MIDIDRIVERCONTROLLER_H

#include "v1_0/imidi_interface.h"

#include <alsa/asoundlib.h>
#include <alsa/rawmidi.h>
#include <functional>
#include <poll.h>
#include <string>
#include <sys/epoll.h>
#include <thread>
#include <vector>
#include <map>
#include <mutex>

namespace OHOS {
namespace HDI {
namespace Midi {
namespace V1_0 {
struct PortInfo {
    std::string name;
    int32_t card;
    int32_t device;
    int32_t subdevice;
    size_t groups;
    uint8_t umpStartGroup;
    uint8_t numUmpGroupsSpanned;
};

struct DeviceInfo {
    int64_t deviceId;
    std::string devfile;
    int32_t card;
    int32_t device;
    std::string idVendor;
    std::string idProduct;
    bool is_ump;
    std::vector<PortInfo> outputPorts;
    std::vector<PortInfo> inputPorts;
};

class MidiDeviceBase {
public:
    MidiDeviceBase(const DeviceInfo& info) : info_(info) {}
    virtual ~MidiDeviceBase() = default;

    virtual int32_t OpenInputPort(uint32_t portId, const sptr<IMidiCallback> &callback) = 0;
    virtual int32_t CloseInputPort(uint32_t portId) = 0;
    virtual int32_t OpenOutputPort(uint32_t portId) = 0;
    virtual int32_t CloseOutputPort(uint32_t portId) = 0;
    virtual int32_t SendMidiMessages(uint32_t portId, const std::vector<MidiMessage> &messages)= 0;

    int64_t GetDeviceId() const { return info_.deviceId; }

protected:
    DeviceInfo info_;
};

class Midi1Device : public MidiDeviceBase {
public:
    Midi1Device(const DeviceInfo& info) : MidiDeviceBase(info) {}
    ~Midi1Device();

    int32_t OpenInputPort(uint32_t portId, const sptr<IMidiCallback> &callback) override;
    int32_t CloseInputPort(uint32_t portId) override;
    int32_t OpenOutputPort(uint32_t portId) override;
    int32_t CloseOutputPort(uint32_t portId) override;
    int32_t SendMidiMessages(uint32_t portId, const std::vector<MidiMessage> &messages) override;

private:
    struct InputContext {
        std::atomic<bool> quit{false};
        snd_rawmidi_t *rawmidi = nullptr;
        std::vector<struct pollfd> pfds;
        sptr<IMidiCallback> dataCallback;
        std::thread thread;
        int eventFd = -1; // 用于唤醒 epoll
    };
        
    struct OutputContext {
        snd_rawmidi_t *rawmidi = nullptr;
    };
    void InputThreadLoop(std::shared_ptr<InputContext> ctx);

    std::mutex mutex_;
    std::map<uint32_t, std::shared_ptr<InputContext>> inputs_;
    std::map<uint32_t, std::shared_ptr<OutputContext>> outputs_;
};

class EpollHandler {
    static constexpr int32_t EventNum = 8;
    static constexpr int32_t InvaildFD = -1;
    int32_t epollFd_ = InvaildFD;

public:
    EpollHandler()
    {
        epollFd_ = ::epoll_create1(0);
    }
    ~EpollHandler()
    {
        finalize();
    } // Ensure close on destruct

    void finalize()
    {
        if (epollFd_ != InvaildFD) {
            ::close(epollFd_);
            epollFd_ = InvaildFD;
        }
    }

    int32_t poll(std::function<void(void *, int32_t)> callback, int32_t tmout = 100)
    {
        struct epoll_event events[EventNum];
        int32_t ready = ::epoll_wait(epollFd_, events, EventNum, tmout);
        if (callback && ready > 0) {
            for (int32_t i = 0; i < ready; i++) {
                if (events[i].events & EPOLLIN) {
                    callback(events[i].data.ptr, EPOLLIN);
                }
                if (events[i].events & EPOLLOUT) {
                    callback(events[i].data.ptr, EPOLLOUT);
                }
                if (events[i].events & EPOLLRDHUP) {
                    callback(events[i].data.ptr, EPOLLRDHUP);
                }
                if (events[i].events & EPOLLERR) {
                    callback(events[i].data.ptr, EPOLLERR);
                }
            }
        }
        return ready;
    }

    int32_t nonblock(int32_t fd, int32_t sw)
    {
        int32_t flag = ::fcntl(fd, F_GETFL);
        if (sw) {
            ::fcntl(fd, F_SETFL, flag | O_NONBLOCK);
        } else {
            ::fcntl(fd, F_SETFL, flag & ~O_NONBLOCK);
        }
        return (flag & O_NONBLOCK);
    }

    int32_t add(int32_t fd, struct epoll_event &ev, uint32_t events, void *user_data = nullptr)
    {
        ev.events = events;
        ev.data.ptr = user_data;
        return ::epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &ev);
    }

    int32_t mod(int32_t fd, struct epoll_event ev, uint32_t events)
    {
        if (ev.events == events) {
            return 0;
        }
        ev.events = events;
        return ::epoll_ctl(epollFd_, EPOLL_CTL_MOD, fd, &ev);
    }

    int32_t del(int32_t fd, struct epoll_event ev)
    {
        return ::epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, &ev);
    }
};

class MidiDriverController {
public:
    MidiDriverController() = default;
    virtual ~MidiDriverController() = default;

    static MidiDriverController *GetInstance();

    int32_t GetDeviceList(std::vector<MidiDeviceInfo> &deviceList);

    int32_t OpenDevice(int64_t deviceId);

    int32_t CloseDevice(int64_t deviceId);

    int32_t OpenInputPort(int64_t deviceId, uint32_t portId, const sptr<IMidiCallback> &dataCallback);

    int32_t CloseInputPort(int64_t deviceId, uint32_t portId);

    int32_t OpenOutputPort(int64_t deviceId, uint32_t portId);

    int32_t CloseOutputPort(int64_t deviceId, uint32_t portId);

    int32_t SendMidiMessages(int64_t deviceId, uint32_t portId, const std::vector<MidiMessage> &messages);

private:
    void EnumerationMidi1();
    void CleanupDeviceInputPorts(int64_t deviceId);
    void CleanupRemovedDevices(const std::vector<DeviceInfo> &oldDeviceList);
    std::shared_ptr<MidiDeviceBase> GetDeviceDriver(int64_t deviceId);
    std::vector<DeviceInfo> deviceList_;
    std::mutex deviceListMutex_;
    std::map<int64_t, std::shared_ptr<MidiDeviceBase>> activeDrivers_;
    std::mutex deviceMapMutex_;
};
} // namespace V1_0
} // namespace Midi
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_MIDI_V1_0_MIDIDRIVERCONTROLLER_H