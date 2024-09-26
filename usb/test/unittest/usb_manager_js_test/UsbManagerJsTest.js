/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import usbManager from '@ohos.usbManager';
//import CheckEmptyUtils from './CheckEmptyUtils.js';
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'


export default function UsbManagerJsTest() {
describe('UsbManagerJsTest', function () {

    const TAG = "[UsbManagerJsTest]";
    const PARAM_NULL = null;
    const PARAM_UNDEFINED = undefined;
    const PARAM_NULLSTRING = "";
    const PARAM_NUMBEREX = 123;
    let gDeviceList;
    let devices;
    let usbPortList;
    let gPipe;
    let isDeviceConnected;
    let tmpPipe = {
        busNum: null,
        devAddress: null
    };
    function deviceConnected() {
        if (usbPortList == undefined) {
            console.info(TAG, "Test USB device is not supported");
            return false;
        }
        if (gDeviceList.length > 0) {
            console.info(TAG, "Test USB device is connected");
            return true;
        }
        console.info(TAG, "Test USB device is not connected");
        return false;
    }

    beforeAll(async function () {
        console.log(TAG, '*************Usb Unit UsbManagerJsTest Begin*************');
        const Version = usbManager.getVersion();
        console.info(TAG, 'usb unit begin test getversion :' + Version);

        // version > 17  host currentMode = 2 device currentMode = 1
        usbPortList = usbManager.getPortList();

        gDeviceList = usbManager.getDevices();
        isDeviceConnected = deviceConnected();
        if (isDeviceConnected) {
            if (usbPortList.length > 0) {
                if (usbPortList[0].status.currentMode == 1) {
                    try {
                        let data = await usbManager.setPortRoleTypes(usbPortList[0].id,
                            usbManager.SOURCE, usbManager.HOST);
                        console.info(TAG, 'usb case setPortRoleTypesEx return: ' + data);
                    } catch (error) {
                        console.info(TAG, 'usb case setPortRoleTypesEx error : ' + error);
                    }
                    CheckEmptyUtils.sleep(4000);
                    console.log(TAG, '*************Usb Unit Begin switch to host*************');
                }
            }
            tmpPipe.busNum = gDeviceList[0].busNum;
            tmpPipe.devAddress = gDeviceList[0].devAddress;
        }
    })

    beforeEach(function () {
        console.info(TAG, 'beforeEach: *************Usb Unit Test CaseEx*************');
        gDeviceList = usbManager.getDevices();
        if (isDeviceConnected) {
            devices = gDeviceList[0];
            console.info(TAG, 'beforeEach return devices : ' + JSON.stringify(devices));
        }
    })

    afterEach(function () {
        console.info(TAG, 'afterEach: *************Usb Unit Test CaseEx*************');
        devices = null;
        gPipe = null;
        console.info(TAG, 'afterEach return devices : ' + JSON.stringify(devices));
    })

    afterAll(function () {
        console.log(TAG, '*************Usb Unit UsbManagerJsTest End*************');
    })

    function getPipe(testCaseName) {
        gPipe = usbManager.connectDevice(devices);
        console.info(TAG, `usb ${testCaseName} connectDevice getPipe ret: ${JSON.stringify(gPipe)}`);
        expect(gPipe !== null).assertTrue();
    }

    function toReleaseInterface(testCaseName, tInterface) {
        let ret = usbManager.releaseInterface(tmpPipe, tInterface);
        console.info(TAG, `usb ${testCaseName} releaseInterface ret: ${ret}`);
        expect(ret).assertEqual(0);
    }
    
    function toClosePipe(testCaseName) {
        let isPipClose = usbManager.closePipe(tmpPipe);
        console.info(TAG, `usb ${testCaseName} closePipe ret: ${isPipClose}`);
        expect(isPipClose).assertEqual(0);
    }

    /**
     * @tc.number   : USB_HostManager_JS_0100
     * @tc.name     : testHasRight001
     * @tc.desc     : Negative test: Param is null string
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testHasRight001', 0, function () {
        console.info(TAG, 'usb testHasRight001 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let isHasRight = usbManager.hasRight(PARAM_NULLSTRING);
            console.info(TAG, 'usb case hasRight ret : ' + isHasRight);
            expect(isHasRight).assertFalse();
        } catch (err) {
            console.info(TAG, 'testHasRight001 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS_0200
     * @tc.name     : testHasRight002
     * @tc.desc     : Negative test: Param add number '123'
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
     it('testHasRight002', 0, function () {
        console.info(TAG, 'usb testHasRight002 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            for (var i = 0; i < gDeviceList.length; i++) {
                let deviceName = gDeviceList[i].name;
                deviceName = deviceName + "123";
                let isHasRight = usbManager.hasRight(deviceName);
                console.info(TAG, 'usb [', deviceName, '] hasRight ret : ' + isHasRight);
                expect(isHasRight).assertFalse();
            }
        } catch (err) {
            console.info(TAG, 'testHasRight002 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__0300
     * @tc.name     : testRequestRight001
     * @tc.desc     : Negative test: Param is null string
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testRequestRight001', 0, async function () {
        console.info(TAG, 'usb testRequestRight001 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let isHasRight = await usbManager.requestRight(PARAM_NULLSTRING);
            console.info(TAG, 'usb case requestRight ret : ' + isHasRight);
            expect(isHasRight).assertFalse();
        } catch (err) {
            console.info(TAG, 'testRequestRight001 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__0400
     * @tc.name     : testRequestRight002
     * @tc.desc     : Negative test: Param add number 'abc'
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testRequestRight002', 0, async function () {
        console.info(TAG, 'usb testRequestRight002 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            for (var i = 0; i < gDeviceList.length; i++) {
                let deviceName = gDeviceList[i].name;
                deviceName = deviceName + "abc";
                let isHasRight = await usbManager.requestRight(deviceName);
                console.info(TAG, 'usb [', deviceName, '] requestRight ret : ' + isHasRight);
                expect(isHasRight).assertFalse();
            }
        } catch (err) {
            console.info(TAG, 'testRequestRight002 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__0500
     * @tc.name     : testRemoveRight001
     * @tc.desc     : Negative test: Param is null string
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testRemoveRight001', 0, function () {
        console.info(TAG, 'usb testRemoveRight001 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let remRight = usbManager.removeRight(PARAM_NULLSTRING);
            console.info(TAG, 'usb case removeRight ret : ' + remRight);
            expect(remRight).assertFalse();
        } catch (err) {
            console.info(TAG, 'testRemoveRight001 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__0600
     * @tc.name     : testRemoveRight002
     * @tc.desc     : Negative test: Param add letter 'abc'
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testRemoveRight002', 0, function () {
        console.info(TAG, 'usb testRemoveRight002 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            for (var i = 0; i < gDeviceList.length; i++) {
                let deviceName = gDeviceList[i].name;
                deviceName = deviceName + "abc";
                let remRight = usbManager.removeRight(deviceName);
                console.info(TAG, 'usb [', deviceName, '] removeRight ret : ', remRight);
                expect(remRight).assertFalse();
            }
        } catch (err) {
            console.info(TAG, 'testRemoveRight002 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__0700
     * @tc.name     : testRemoveRight003
     * @tc.desc     : Negative test: Param add special characters '@#'
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testRemoveRight003', 0, function () {
        console.info(TAG, 'usb testRemoveRight003 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            for (var i = 0; i < gDeviceList.length; i++) {
                let deviceName = gDeviceList[i].name;
                deviceName = deviceName + "@#";
                let remRight = usbManager.removeRight(deviceName);
                console.info(TAG, 'usb [', deviceName, '] removeRight ret : ', remRight);
                expect(remRight).assertFalse();
            }
        } catch (err) {
            console.info(TAG, 'testRemoveRight003 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__0800
     * @tc.name     : testRemoveRight004
     * @tc.desc     : Negative test: Param add number '123'
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testRemoveRight004', 0, function () {
        console.info(TAG, 'usb testRemoveRight004 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            for (var i = 0; i < gDeviceList.length; i++) {
                let deviceName = gDeviceList[i].name;
                deviceName = deviceName + "123";
                let remRight = usbManager.removeRight(deviceName);
                console.info(TAG, 'usb [', deviceName, '] removeRight ret : ', remRight);
                expect(remRight).assertFalse();
            }
        } catch (err) {
            console.info(TAG, 'testRemoveRight004 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__0900
     * @tc.name     : testConnectDevice001
     * @tc.desc     : Negative test: Param add number '123'
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDevice001', 0, function () {
        console.info(TAG, 'usb testConnectDevice001 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let deviceName = devices.name + "123";
            devices.name = deviceName;
            let gPipe = usbManager.connectDevice(devices);

            console.info(TAG, 'usb [', devices.name, '] connectDevice ret : ', JSON.stringify(gPipe));
            expect(CheckEmptyUtils.isEmpty(gPipe)).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDevice001 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__1000
     * @tc.name     : testConnectDevice002
     * @tc.desc     : Negative test: Param add letter 'abc'
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDevice002', 0, function () {
        console.info(TAG, 'usb testConnectDevice002 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let deviceName = devices.name + "abc";
            devices.name = deviceName;
            let gPipe = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [', devices.name, '] connectDevice ret : ', JSON.stringify(gPipe));
            expect(CheckEmptyUtils.isEmpty(gPipe)).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDevice002 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__1100
     * @tc.name     : testConnectDevice003
     * @tc.desc     : Negative test: Param add special characters '@#'
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDevice003', 0, function () {
        console.info(TAG, 'usb testConnectDevice003 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let deviceName = devices.name + "@#";
            devices.name = deviceName;
            let gPipe = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [', devices.name, '] connectDevice ret : ', JSON.stringify(gPipe));
            expect(CheckEmptyUtils.isEmpty(gPipe)).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDevice003 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__1200
     * @tc.name     : testConnectDevice004
     * @tc.desc     : Negative test: devices name is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDevice004', 0, function () {
        console.info(TAG, 'usb testConnectDevice004 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.name = PARAM_NULLSTRING;
            let gPipe = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [', devices.name, '] connectDevice ret : ', JSON.stringify(gPipe));
            expect(CheckEmptyUtils.isEmpty(gPipe)).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDevice004 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__1300
     * @tc.name     : testConnectDevice005
     * @tc.desc     : Negative test: devices serial is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDevice005', 0, function () {
        console.info(TAG, 'usb testConnectDevice005 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.serial = PARAM_NULLSTRING;
            let gPipe = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [', devices.serial, '] connectDevice ret : ', JSON.stringify(gPipe));
            expect(CheckEmptyUtils.isEmpty(gPipe)).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDevice005 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : USB_HostManager_JS__1400
     * @tc.name     : testConnectDevice006
     * @tc.desc     : Negative test: devices serial add letter abc
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDevice006', 0, function () {
        console.info(TAG, 'usb testConnectDevice006 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let devSerial = devices.serial + "abc";
            devices.serial = devSerial;
            let gPipe = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [', devices.serial, '] connectDevice ret : ', JSON.stringify(gPipe));
            expect(CheckEmptyUtils.isEmpty(gPipe)).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDevice006 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })
})
}