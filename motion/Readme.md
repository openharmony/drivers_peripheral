# Motion

## Introduction

The motion driver is developed based on the Hardware Driver Foundation (HDF). It shields hardware differences and provides stable motion capabilities for upper-layer services. The motion capabilities include enabling or disabling motion and subscribing to or unsubscribing from motion data.

The figure below shows the motion driver architecture. The framework layer provides MSDP services, and interacts with the Motion Hardware Device Interface (HDI) Server through the Motion HDI Client. The Motion HDI Server calls the Motion HDI Impl APIs to provide motion recognition capabilities for upper-layer services.

**Figure 1** Architecture of the motion module

![](figures/motion-driver-module-architecture.png)

## Directory Structure

The directory structure of the motion module is as follows:

```
/drivers/peripheral/motion
├── hdi_service                          # Driver capability provided by the motion module for upper-layer services
├── test                                 # Test codes for the motion module
│   └── unittest\hdi                     # HDI unit test code of the motion driver module
```

## Description

### Available APIs

The motion driver module provides upper-layer services with APIs that can be directly called for various purposes, such as enabling or disabling motion and subscribing to or unsubscribing from motion data. Table 1 lists the APIs provided by the motion driver module.

**Table 1** Motion HDI APIs

| API                                                      | Description                                                    |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| int32_t EnableMotion(int32_t motionType)                     | Enables a motion type. The motion data can be obtained only when motion is enabled.|
| int32_t DisableMotion(int32_t motionType)                    | Disables a motion type.                                    |
| int32_t Register(const sptr<IMotionCallback> &callbackObj)   | Registers the callback for motion data. When the registration is successful, the system will report the motion data to the subscriber.|
| int32_t Unregister(const sptr<IMotionCallback> &callbackObj) | Unregisters from the callback for motion data.                          |

### How to Use

This section describes how to subscribe to pickup data.

Sample Code

```
#include "v1_0/imotion_interface.h"

/* MotionCallbackService class */
class MotionCallbackService : public IMotionCallback {
public:
    MotionCallbackService() = default;
    virtual ~MotionCallbackService() = default;
    int32_t OnDataEvent(const HdfMotionEvent &event) override;
};

/* Callback */
int32_t MotionCallbackService::OnDataEvent(const HdfMotionEvent &event)
{
    printf("moton :[%d], result[%d]:, status[%d]\n\r", event.motion, event.result, event.status);
    return HDF_SUCCESS;
}

void MotionSample(void)
{
    int32_t ret;
    sptr<IMotionInterface> g_motionInterface = nullptr;
    sptr<IMotionCallback> g_motionCallback = new MotionCallbackService();
    sptr<IMotionCallback> g_motionCallbackUnregistered = new MotionCallbackService();

    /* 1. Obtain the motion service. */
    g_motionInterface = IMotionInterface::Get();
    if (g_motionInterface == nullptr) {
        return;
    }
    /* 2. Register the callback for motion data. */
    ret = g_motionInterface->Register(g_motionCallback);
    if (ret != 0) {
        return;
    }
    /* 3. Enable motion. */
    ret = g_motionInterface->EnableMotion(HDF_MOTION_TYPE_PICKUP);
    if (ret != 0) {
        return;
    }
    /* 4. Disable motion. */
    ret = g_motionInterface->DisableMotion(HDF_MOTION_TYPE_PICKUP);
    if (ret != 0) {
        return;
    }
    /* 5. Unregister from the callback for motion data. */
    ret = g_motionInterface->Unregister(g_motionCallback);
    if (ret != 0) {
        return;
    }
}
```

## Repositories Involved

[Driver](https://gitee.com/openharmony/docs/blob/master/en/readme/driver.md)

[drivers_hdf_core](https://gitee.com/openharmony/drivers_hdf_core)

[drivers_interface](https://gitee.com/openharmony/drivers_interface)

[**drivers\_peripheral**](https://gitee.com/openharmony/drivers_peripheral)
