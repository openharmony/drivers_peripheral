/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#ifndef WIFI_CPP_BINDINGS_H
#define WIFI_CPP_BINDINGS_H

#include "wifi_hal.h"
#include "common.h"
#include "sync.h"
#include "securec.h"

class WifiEvent {
    static const unsigned nL80211AttrMaxInternal = 256;
public:
    explicit WifiEvent(nl_msg *msg) : mMsg(msg), mHeader(nullptr)
    {
        if (memset_s(mAttributes, sizeof(mAttributes), 0, sizeof(mAttributes)) != EOK) {
            HDF_LOGI("mAttributes memset error");
            return;
        }
    }
    ~WifiEvent() {}

    void Log();

    int Parse();

    genlmsghdr *header()
    {
        return mHeader;
    }

    int GetCmd()
    {
        return mHeader->cmd;
    }

    int GetVendorId()
    {
        return GetU32(NL80211_ATTR_VENDOR_ID);
    }

    int GetVendorSubcmd()
    {
        return GetU32(NL80211_ATTR_VENDOR_SUBCMD);
    }

    void *GetVendorData()
    {
        return GetData(NL80211_ATTR_VENDOR_DATA);
    }

    int GetVendorDataLen()
    {
        return GetLen(NL80211_ATTR_VENDOR_DATA);
    }

    nlattr **Attributes()
    {
        return mAttributes;
    }

    nlattr *GetAttribute(int attribute)
    {
        return mAttributes[attribute];
    }

    uint8_t GetU8(int attribute)
    {
        return mAttributes[attribute] ? nla_get_u8(mAttributes[attribute]) : 0;
    }

    uint16_t GetU16(int attribute)
    {
        return mAttributes[attribute] ? nla_get_u16(mAttributes[attribute]) : 0;
    }

    uint32_t GetU32(int attribute)
    {
        return mAttributes[attribute] ? nla_get_u32(mAttributes[attribute]) : 0;
    }

    uint64_t GetU64(int attribute)
    {
        return mAttributes[attribute] ? nla_get_u64(mAttributes[attribute]) : 0;
    }

    int GetLen(int attribute)
    {
        return mAttributes[attribute] ? nla_len(mAttributes[attribute]) : 0;
    }

    void *GetData(int attribute)
    {
        return mAttributes[attribute] ? nla_data(mAttributes[attribute]) : NULL;
    }

    void *GetString(int attribute)
    {
        return mAttributes[attribute] ? nla_get_string(mAttributes[attribute]) : NULL;
    }
private:
    WifiEvent(const WifiEvent&); // hide copy constructor to prevent copies
    WifiEvent& operator = (const WifiEvent&);

private:
    struct nl_msg *mMsg;
    struct genlmsghdr *mHeader;
    struct nlattr *mAttributes[nL80211AttrMaxInternal + 1];
};

class NlIterator {
    struct nlattr *pos;
    int rem;
public:
    explicit NlIterator(struct nlattr *attr)
    {
        pos = reinterpret_cast<struct nlattr *>(nla_data(attr));
        rem = nla_len(attr);
    }
    bool HasNext()
    {
        return nla_ok(pos, rem);
    }
    void Next()
    {
        pos = reinterpret_cast<struct nlattr *>(nla_next(pos, &(rem)));
    }
    struct nlattr *Get()
    {
        return pos;
    }
    uint16_t GetType()
    {
        return nla_type(pos);
    }
    uint8_t GetU8()
    {
        return nla_get_u8(pos);
    }
    uint16_t GetU16()
    {
        return nla_get_u16(pos);
    }
    uint32_t GetU32()
    {
        return nla_get_u32(pos);
    }
    uint64_t GetU64()
    {
        return nla_get_u64(pos);
    }
    void* GetData()
    {
        return nla_data(pos);
    }
    int GetLen()
    {
        return nla_len(pos);
    }
    void* GetString()
    {
        return nla_get_string(pos);
    }
private:
    NlIterator(const NlIterator&);    // hide copy constructor to prevent copies
    NlIterator& operator = (const NlIterator&);
};

class WifiRequest {
public:
    explicit WifiRequest(int family)
    {
        mMsg = nullptr;
        mFamily = family;
        mIface = -1;
    }

    WifiRequest(int family, int iface)
    {
        mMsg = nullptr;
        mFamily = family;
        mIface = iface;
    }

    ~WifiRequest()
    {
        Destroy();
    }

    void Destroy()
    {
        if (mMsg) {
            nlmsg_free(mMsg);
            mMsg = nullptr;
        }
    }

    nl_msg *GetMessage()
    {
        return mMsg;
    }

    /* Command assembly helpers */
    int Create(int family, uint8_t cmd, int flags, int hdrlen);
    int Create(uint8_t cmd)
    {
        return Create(mFamily, cmd, 0, 0);
    }

    int Create(uint32_t id, int subcmd);

    int Put(int attribute, void *ptr, unsigned len)
    {
        return nla_put(mMsg, attribute, len, ptr);
    }
    int PutS8(int attribute, int8_t value)
    {
        return nla_put(mMsg, attribute, sizeof(value), &value);
    }
    int PutU8(int attribute, uint8_t value)
    {
        return nla_put(mMsg, attribute, sizeof(value), &value);
    }
    int PutU16(int attribute, uint16_t value)
    {
        return nla_put(mMsg, attribute, sizeof(value), &value);
    }
    int PutU32(int attribute, uint32_t value)
    {
        return nla_put(mMsg, attribute, sizeof(value), &value);
    }
    int PutU64(int attribute, uint64_t value)
    {
        return nla_put(mMsg, attribute, sizeof(value), &value);
    }
    int PutString(int attribute, const char *value)
    {
        return nla_put(mMsg, attribute, strlen(value) + 1, value);
    }
    int PutAddr(int attribute, macAddr value)
    {
        return nla_put(mMsg, attribute, sizeof(macAddr), value);
    }
    int PutFlag(int attribute)
    {
        return nla_put_flag(mMsg, attribute);
    }
    struct nlattr *AttrStart(int attribute)
    {
        return nla_nest_start(mMsg, attribute);
    }
    void AttrEnd(struct nlattr *attr)
    {
        nla_nest_end(mMsg, attr);
    }

    int SetIfaceId(int ifindex)
    {
        return PutU32(NL80211_ATTR_IFINDEX, ifindex);
    }

private:
    WifiRequest(const WifiRequest&);        // hide copy constructor to prevent copies
    WifiRequest& operator = (const WifiRequest&);
private:
    int mFamily;
    int mIface;
    struct nl_msg *mMsg;
};

class WifiCommand {
public:
    WifiCommand(const char *type, wifiHandle handle, int id)
        : mType(type), mMsg(GetHalInfo(handle)->nl80211FamilyId), mId(id), mRefs(1)
    {
        mIfaceInfo = nullptr;
        mInfo = GetHalInfo(handle);
    }

    WifiCommand(const char *type, wifiInterfaceHandle iface, int id)
        : mType(type), mMsg(GetHalInfo(iface)->nl80211FamilyId, GetIfaceInfo(iface)->id),
          mId(id), mRefs(1)
    {
        mIfaceInfo = GetIfaceInfo(iface);
        mInfo = GetHalInfo(iface);
    }

    virtual ~WifiCommand() {}

    int Id()
    {
        return mId;
    }

    const char *GetType()
    {
        return mType;
    }

    virtual void AddRef()
    {
        int refs = __sync_add_and_fetch(&mRefs, 1);
        HDF_LOGD("AddRef: WifiCommand %p has %d references", this, refs);
    }

    virtual void ReleaseRef()
    {
        int refs = __sync_sub_and_fetch(&mRefs, 1);
        if (refs == 0) {
            delete this;
        } else {
        }
    }

    virtual int Create()
    {
        HDF_LOGD("WifiCommand %p can't be created", this);
        return HAL_NOT_SUPPORTED;
    }

    virtual int Cancel()
    {
        return HAL_NOT_SUPPORTED;
    }

    int RequestResponse();
    int RequestEvent(int cmd);
    int RequestVendorEvent(uint32_t id, int subcmd);
    int RequestResponse(WifiRequest& request);

protected:
    wifiHandle WifiHandle()
    {
        return GetWifiHandle(mInfo);
    }

    wifiInterfaceHandle IfaceHandle()
    {
        return GetIfaceHandle(mIfaceInfo);
    }

    int FamilyId()
    {
        return mInfo->nl80211FamilyId;
    }

    int IfaceId()
    {
        return mIfaceInfo->id;
    }

    virtual int HandleResponse(WifiEvent& reply)
    {
        HDF_LOGI("skipping a response");
        return NL_SKIP;
    }

    virtual int HandleEvent(WifiEvent& event)
    {
        HDF_LOGI("skipping an event %{public}d", event.GetCmd());
        return NL_SKIP;
    }

    int RegisterHandler(int cmd)
    {
        return WifiRegisterHandler(WifiHandle(), cmd, &EventHandler, this);
    }

    void UnregisterHandler(int cmd)
    {
        WifiUnregisterHandler(WifiHandle(), cmd);
    }

    int RegisterVendorHandler(uint32_t id, int subcmd)
    {
        return WifiRegisterVendorHandler(WifiHandle(), id, subcmd, &EventHandler, this);
    }

    void UnregisterVendorHandlerWithoutLock(uint32_t id, int subcmd)
    {
        WifiUnregisterVendorHandlerWithoutLock(WifiHandle(), id, subcmd);
    }

    void UnregisterVendorHandler(uint32_t id, int subcmd)
    {
        WifiUnregisterVendorHandler(WifiHandle(), id, subcmd);
    }

protected:
    const char *mType;
    HalInfo *mInfo;
    WifiRequest mMsg;
    Condition mCondition;
    int mId;
    InterfaceInfo *mIfaceInfo;
    int mRefs;

private:
    WifiCommand(const WifiCommand&);           // hide copy constructor to prevent copies
    WifiCommand& operator = (const WifiCommand&);

    static int ResponseHandler(struct nl_msg *msg, void *arg);

    static int EventHandler(struct nl_msg *msg, void *arg);

    static int ValidHandler(struct nl_msg *msg, void *arg);

    static int AckHandler(struct nl_msg *msg, void *arg);

    static int FinishHandler(struct nl_msg *msg, void *arg);

    static int ErrorHandler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
};

/* nl message processing macros (required to pass C++ type checks) */

#define FOR_EACH_ATTR(pos, nla, rem) \
    for ((pos) = reinterpret_cast<nlattr *>(nla_data(nla)), (rem) = nla_len(nla); \
        nla_ok(pos, rem); \
        pos = reinterpret_cast<nlattr *>(nla_next(pos, &(rem))))

extern void InitResponseLock(void);
extern void DestroyResponseLock(void);

#endif