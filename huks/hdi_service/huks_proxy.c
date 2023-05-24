#include <hdi_support.h>
#include "v1_0/ihuks.h"

#define HDF_LOG_TAG    huks_proxy

struct IHuks *IHuksGet(bool isStub)
{
    return IHuksGetInstance("huks_hdi_service", isStub);
}

struct IHuks *IHuksGetInstance(const char *serviceName, bool isStub)
{
    if (isStub) {
        const char *instName = serviceName;
        if (strcmp(instName, "huks_hdi_service") == 0) {
            instName = "hdi_service";
        }
        return LoadHdiImpl(IHUKS_INTERFACE_DESC, instName);
    }
    return NULL;
}

void IHuksRelease(struct IHuks *instance, bool isStub)
{
    IHuksReleaseInstance("huks_hdi_service", instance, isStub);
}

void IHuksReleaseInstance(const char *serviceName, struct IHuks *instance, bool isStub)
{
    if (instance == NULL) {
        return;
    }

    if (isStub) {
        const char *instName = serviceName;
        if (strcmp(instName, "huks_hdi_service") == 0) {
            instName = "hdi_service";
        }
        UnloadHdiImpl(IHUKS_INTERFACE_DESC, instName, instance);
        return;
    }
}
