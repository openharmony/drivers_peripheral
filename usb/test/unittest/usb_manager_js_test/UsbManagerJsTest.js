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

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_1800
     * @tc.name     : testConnectDeviceParamErr007
     * @tc.desc     : Negative test: devices name is number 123
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
     it('testConnectDeviceParamErr007', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr007 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.name = PARAM_NUMBERTYPE;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [', devices.name, '] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr007 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_1900
     * @tc.name     : testConnectDeviceParamErr008
     * @tc.desc     : Negative test: devices busNum is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr008', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr008 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.busNum = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [busNum:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr008 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_2000
     * @tc.name     : testConnectDeviceParamErr009
     * @tc.desc     : Negative test: devices busNum is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr009', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr009 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.busNum = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [busNum:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr009 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_2100
     * @tc.name     : testConnectDeviceParamErr010
     * @tc.desc     : Negative test: devices busNum null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr010', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr010 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.busNum = PARAM_NULLSTRING;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [busNum:null string] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr010 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_2200
     * @tc.name     : testConnectDeviceParamErr011
     * @tc.desc     : Negative test: devices devAddress is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr011', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr011 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.devAddress = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [devAddress:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr011 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_2300
     * @tc.name     : testConnectDeviceParamErr012
     * @tc.desc     : Negative test: devices devAddress is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr012', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr012 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.devAddress = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [devAddress:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr012 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_2400
     * @tc.name     : testConnectDeviceParamErr013
     * @tc.desc     : Negative test: devices devAddress is null string
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr013', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr013 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.devAddress = PARAM_NULLSTRING;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [devAddress:null string] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr013 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_2500
     * @tc.name     : testConnectDeviceParamErr014
     * @tc.desc     : Negative test: devices serial is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr014', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr014 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.serial = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [serial:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr014 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_2600
     * @tc.name     : testConnectDeviceParamErr015
     * @tc.desc     : Negative test: devices serial is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr015', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr015 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.serial = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [serial:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr015 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_2700
     * @tc.name     : testConnectDeviceParamErr016
     * @tc.desc     : Negative test: devices serial is number 123
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr016', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr016 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.serial = PARAM_NUMBERTYPE;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [serial:123] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr016 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_2800
     * @tc.name     : testConnectDeviceParamErr017
     * @tc.desc     : Negative test: devices manufacturerName is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr017', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr017 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.manufacturerName = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [manufacturerName:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr017 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_2900
     * @tc.name     : testConnectDeviceParamErr018
     * @tc.desc     : Negative test: devices manufacturerName is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr018', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr018 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.manufacturerName = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [manufacturerName:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr018 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_3000
     * @tc.name     : testConnectDeviceParamErr019
     * @tc.desc     : Negative test: devices manufacturerName is number 123
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr019', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr019 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.manufacturerName = PARAM_NUMBERTYPE;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [manufacturerName:123] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr019 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_3100
     * @tc.name     : testConnectDeviceParamErr020
     * @tc.desc     : Negative test: devices productName is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr020', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr020 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.productName = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [productName:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr020 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_3200
     * @tc.name     : testConnectDeviceParamErr021
     * @tc.desc     : Negative test: devices productName is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr021', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr021 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.productName = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [productName:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr021 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_3300
     * @tc.name     : testConnectDeviceParamErr022
     * @tc.desc     : Negative test: devices productName is number 123
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr022', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr022 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.productName = PARAM_NUMBERTYPE;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [productName:123] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr022 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_3400
     * @tc.name     : testConnectDeviceParamErr023
     * @tc.desc     : Negative test: devices version is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr023', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr023 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.version = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [version:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr023 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_3500
     * @tc.name     : testConnectDeviceParamErr024
     * @tc.desc     : Negative test: devices version is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr024', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr024 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.version = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [version:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr024 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_3600
     * @tc.name     : testConnectDeviceParamErr025
     * @tc.desc     : Negative test: devices vendorId is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr025', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr025 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.vendorId = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [vendorId:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr025 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_3700
     * @tc.name     : testConnectDeviceParamErr026
     * @tc.desc     : Negative test: devices vendorId is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr026', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr026 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.vendorId = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [vendorId:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr026 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_3800
     * @tc.name     : testConnectDeviceParamErr027
     * @tc.desc     : Negative test: devices vendorId is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr027', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr027 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.vendorId = PARAM_NULLSTRING;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [vendorId:""] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr027 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_3900
     * @tc.name     : testConnectDeviceParamErr028
     * @tc.desc     : Negative test: devices productId is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr028', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr028 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.productId = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [productId:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr028 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_4000
     * @tc.name     : testConnectDeviceParamErr029
     * @tc.desc     : Negative test: devices productId is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr029', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr029 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.productId = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [productId:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr029 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_4100
     * @tc.name     : testConnectDeviceParamErr030
     * @tc.desc     : Negative test: devices productId is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr030', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr030 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.productId = PARAM_NULLSTRING;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [productId:" "] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr030 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_4200
     * @tc.name     : testConnectDeviceParamErr031
     * @tc.desc     : Negative test: devices clazz is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr031', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr031 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.clazz = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [clazz:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr031 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_4300
     * @tc.name     : testConnectDeviceParamErr032
     * @tc.desc     : Negative test: devices clazz is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr032', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr032 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.clazz = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [clazz:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr032 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_4400
     * @tc.name     : testConnectDeviceParamErr033
     * @tc.desc     : Negative test: devices clazz is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr033', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr033 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.clazz = PARAM_NULLSTRING;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [clazz:""] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr033 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_4500
     * @tc.name     : testConnectDeviceParamErr034
     * @tc.desc     : Negative test: devices subClass is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr034', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr034 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.subClass = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [subClass:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr034 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_4600
     * @tc.name     : testConnectDeviceParamErr035
     * @tc.desc     : Negative test: devices subClass is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr035', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr035 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.subClass = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [subClass:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr035 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_4700
     * @tc.name     : testConnectDeviceParamErr036
     * @tc.desc     : Negative test: devices subClass is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr036', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr036 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.subClass = PARAM_NULLSTRING;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [subClass:""] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr036 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_4800
     * @tc.name     : testConnectDeviceParamErr037
     * @tc.desc     : Negative test: devices protocol is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr037', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr037 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.protocol = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [protocol:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr037 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_4900
     * @tc.name     : testConnectDeviceParamErr038
     * @tc.desc     : Negative test: devices protocol is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr038', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr038 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.protocol = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [protocol:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr038 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_5000
     * @tc.name     : testConnectDeviceParamErr039
     * @tc.desc     : Negative test: devices protocol is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr039', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr039 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.protocol = PARAM_NULLSTRING;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [protocol:""] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr039 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_5100
     * @tc.name     : testConnectDeviceParamErr040
     * @tc.desc     : Negative test: devices configs is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr040', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr040 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.configs = PARAM_NULL;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [configs:null] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr040 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_5200
     * @tc.name     : testConnectDeviceParamErr041
     * @tc.desc     : Negative test: devices configs is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr041', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr041 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.configs = PARAM_UNDEFINED;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [configs:undefined] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr041 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_5300
     * @tc.name     : testConnectDeviceParamErr042
     * @tc.desc     : Negative test: devices configs is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr042', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr042 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.configs = PARAM_NULLSTRING;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [configs:""] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr042 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_5400
     * @tc.name     : testConnectDeviceParamErr043
     * @tc.desc     : Negative test: devices configs is number 123
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testConnectDeviceParamErr043', 0, function () {
        console.info(TAG, 'usb testConnectDeviceParamErr043 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            devices.configs = PARAM_NULLSTRING;
            let ret = usbManager.connectDevice(devices);
            console.info(TAG, 'usb [configs:123] connectDevice ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testConnectDeviceParamErr043 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_5500
     * @tc.name     : testClosePipeParamErr001
     * @tc.desc     : Negative test: Enter two parameters
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClosePipeParamErr001', 0, function () {
        console.info(TAG, 'usb testClosePipeParamErr001 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        getPipe('testClosePipeParamErr001');
        try {
            let ret = usbManager.closePipe(gPipe, gPipe);
            console.info(TAG, 'usb Enter two parameters closePipe ret : ', ret);
            expect(ret).assertEqual(0);
        } catch (err) {
            console.info(TAG, 'testClosePipeParamErr001 catch err : ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_5600
     * @tc.name     : testClosePipeParamErr002
     * @tc.desc     : Negative test: pipe busNum is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClosePipeParamErr002', 0, function () {
        console.info(TAG, 'usb testClosePipeParamErr002 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_NULL;
            let ret = usbManager.closePipe(gPipe);
            console.info(TAG, 'usb [busNum:null] closePipe ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClosePipeParamErr002 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_5700
     * @tc.name     : testClosePipeParamErr003
     * @tc.desc     : Negative test: pipe busNum is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClosePipeParamErr003', 0, function () {
        console.info(TAG, 'usb testClosePipeParamErr003 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_UNDEFINED;
            let ret = usbManager.closePipe(gPipe);
            console.info(TAG, 'usb [busNum:undefined] closePipe ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClosePipeParamErr003 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_5800
     * @tc.name     : testClosePipeParamErr004
     * @tc.desc     : Negative test: pipe busNum is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClosePipeParamErr004', 0, function () {
        console.info(TAG, 'usb testClosePipeParamErr004 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_NULLSTRING;
            let ret = usbManager.closePipe(gPipe);
            console.info(TAG, 'usb [busNum:""] closePipe ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClosePipeParamErr004 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_5900
     * @tc.name     : testClosePipeParamErr005
     * @tc.desc     : Negative test: pipe devAddress is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClosePipeParamErr005', 0, function () {
        console.info(TAG, 'usb testClosePipeParamErr005 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_NULL;
            let ret = usbManager.closePipe(gPipe);
            console.info(TAG, 'usb [devAddress:null] closePipe ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClosePipeParamErr005 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_6000
     * @tc.name     : testClosePipeParamErr006
     * @tc.desc     : Negative test: pipe devAddress is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClosePipeParamErr006', 0, function () {
        console.info(TAG, 'usb testClosePipeParamErr006 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_UNDEFINED;
            let ret = usbManager.closePipe(gPipe);
            console.info(TAG, 'usb [devAddress:undefined] closePipe ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClosePipeParamErr006 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_6100
     * @tc.name     : testClosePipeParamErr007
     * @tc.desc     : Negative test: devices devAddress is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClosePipeParamErr007', 0, function () {
        console.info(TAG, 'usb testClosePipeParamErr007 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_NULLSTRING;
            let ret = usbManager.closePipe(gPipe);
            console.info(TAG, 'usb [devAddress:""] closePipe ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClosePipeParamErr007 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_6200
     * @tc.name     : testClosePipeParamErr008
     * @tc.desc     : Negative test: Param is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClosePipeParamErr008', 0, function () {
        console.info(TAG, 'usb testClosePipeParamErr008 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.closePipe(PARAM_NULL);
            console.info(TAG, 'usb [param:null] closePipe ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClosePipeParamErr008 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_6300
     * @tc.name     : testClosePipeParamErr009
     * @tc.desc     : Negative test: Param is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClosePipeParamErr009', 0, function () {
        console.info(TAG, 'usb testClosePipeParamErr009 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.closePipe(PARAM_UNDEFINED);
            console.info(TAG, 'usb [param:undefined] closePipe ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClosePipeParamErr009 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_6400
     * @tc.name     : testClosePipeParamErr010
     * @tc.desc     : Negative test: Param is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClosePipeParamErr010', 0, function () {
        console.info(TAG, 'usb testClosePipeParamErr010 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.closePipe(PARAM_NULLSTRING);
            console.info(TAG, 'usb [param:""] closePipe ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClosePipeParamErr010 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_6500
     * @tc.name     : testGetRawDescriptorParamErr001
     * @tc.desc     : Negative test: Enter two parameters
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetRawDescriptorParamErr001', 0, function () {
        console.info(TAG, 'usb testGetRawDescriptorParamErr001 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        getPipe('testGetRawDescriptorParamErr001');
        try {
            let ret = usbManager.getRawDescriptor(gPipe, gPipe);
            console.info(TAG, 'usb Enter two parameters getRawDescriptor ret : ', JSON.stringify(ret));
            expect(ret.length >= 0).assertTrue();
        } catch (err) {
            console.info(TAG, 'testGetRawDescriptorParamErr001 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
        toClosePipe('testGetRawDescriptorParamErr001');
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_6600
     * @tc.name     : testGetRawDescriptorParamErr002
     * @tc.desc     : Negative test: Param is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetRawDescriptorParamErr002', 0, function () {
        console.info(TAG, 'usb testGetRawDescriptorParamErr002 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.getRawDescriptor(PARAM_NULL);
            console.info(TAG, 'usb [param:null] getRawDescriptor ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetRawDescriptorParamErr002 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_6700
     * @tc.name     : testGetRawDescriptorParamErr003
     * @tc.desc     : Negative test: Param is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetRawDescriptorParamErr003', 0, function () {
        console.info(TAG, 'usb testGetRawDescriptorParamErr003 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.getRawDescriptor(PARAM_UNDEFINED);
            console.info(TAG, 'usb [param:undefined] getRawDescriptor ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetRawDescriptorParamErr003 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_6800
     * @tc.name     : testGetRawDescriptorParamErr004
     * @tc.desc     : Negative test: Param is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetRawDescriptorParamErr004', 0, function () {
        console.info(TAG, 'usb testGetRawDescriptorParamErr004 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.getRawDescriptor(PARAM_NULLSTRING);
            console.info(TAG, 'usb [param:""] getRawDescriptor ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetRawDescriptorParamErr004 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_6900
     * @tc.name     : testGetRawDescriptorParamErr005
     * @tc.desc     : Negative test: pipe busNum is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetRawDescriptorParamErr005', 0, function () {
        console.info(TAG, 'usb testGetRawDescriptorParamErr005 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_NULL;
            let ret = usbManager.getRawDescriptor(gPipe);
            console.info(TAG, 'usb [busNum:null] getRawDescriptor ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetRawDescriptorParamErr005 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_7000
     * @tc.name     : testGetRawDescriptorParamErr006
     * @tc.desc     : Negative test: pipe busNum is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetRawDescriptorParamErr006', 0, function () {
        console.info(TAG, 'usb testGetRawDescriptorParamErr006 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_UNDEFINED;
            let ret = usbManager.getRawDescriptor(gPipe);
            console.info(TAG, 'usb [busNum:undefined] getRawDescriptor ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetRawDescriptorParamErr006 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_7100
     * @tc.name     : testGetRawDescriptorParamErr007
     * @tc.desc     : Negative test: pipe busNum is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetRawDescriptorParamErr007', 0, function () {
        console.info(TAG, 'usb testGetRawDescriptorParamErr007 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_NULLSTRING;
            let ret = usbManager.getRawDescriptor(gPipe);
            console.info(TAG, 'usb [busNum:""] getRawDescriptor ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetRawDescriptorParamErr007 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_7200
     * @tc.name     : testGetRawDescriptorParamErr008
     * @tc.desc     : Negative test: pipe devAddress is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetRawDescriptorParamErr008', 0, function () {
        console.info(TAG, 'usb testGetRawDescriptorParamErr008 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_NULL;
            let ret = usbManager.getRawDescriptor(gPipe);
            console.info(TAG, 'usb [devAddress:null] getRawDescriptor ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetRawDescriptorParamErr008 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_7300
     * @tc.name     : testGetRawDescriptorParamErr009
     * @tc.desc     : Negative test: pipe devAddress is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetRawDescriptorParamErr009', 0, function () {
        console.info(TAG, 'usb testGetRawDescriptorParamErr009 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_UNDEFINED;
            let ret = usbManager.getRawDescriptor(gPipe);
            console.info(TAG, 'usb [devAddress:undefined] getRawDescriptor ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetRawDescriptorParamErr009 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_7400
     * @tc.name     : testGetRawDescriptorParamErr010
     * @tc.desc     : Negative test: devices devAddress is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetRawDescriptorParamErr010', 0, function () {
        console.info(TAG, 'usb testGetRawDescriptorParamErr010 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_NULLSTRING;
            let ret = usbManager.getRawDescriptor(gPipe);
            console.info(TAG, 'usb [devAddress:""] getRawDescriptor ret : ', JSON.stringify(ret));
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetRawDescriptorParamErr010 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_7500
     * @tc.name     : testGetFileDescriptorParamErr001
     * @tc.desc     : Negative test: Enter two parameters
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetFileDescriptorParamErr001', 0, function () {
        console.info(TAG, 'usb testGetFileDescriptorParamErr001 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        getPipe('testGetRawDescriptorParamErr001');
        try {
            let ret = usbManager.getFileDescriptor(gPipe, gPipe);
            console.info(TAG, 'usb Enter two parameters getFileDescriptor ret : ', ret);
            expect(ret >= 0).assertTrue();
        } catch (err) {
            console.info(TAG, 'testGetFileDescriptorParamErr001 catch err code: ',
                err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
        toClosePipe('testGetRawDescriptorParamErr001');
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_7600
     * @tc.name     : testGetFileDescriptorParamErr002
     * @tc.desc     : Negative test: Param is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
     it('testGetFileDescriptorParamErr002', 0, function () {
        console.info(TAG, 'usb testGetFileDescriptorParamErr002 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.getFileDescriptor(PARAM_NULL);
            console.info(TAG, 'usb [param:null] getFileDescriptor ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetFileDescriptorParamErr002 catch err code: ',
                err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_7700
     * @tc.name     : testGetFileDescriptorParamErr003
     * @tc.desc     : Negative test: Param is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetFileDescriptorParamErr003', 0, function () {
        console.info(TAG, 'usb testGetFileDescriptorParamErr003 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.getFileDescriptor(PARAM_UNDEFINED);
            console.info(TAG, 'usb [param:undefined] getFileDescriptor ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetFileDescriptorParamErr003 catch err code: ',
                err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_7800
     * @tc.name     : testGetFileDescriptorParamErr004
     * @tc.desc     : Negative test: Param is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetFileDescriptorParamErr004', 0, function () {
        console.info(TAG, 'usb testGetFileDescriptorParamErr004 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.getFileDescriptor(PARAM_NULLSTRING);
            console.info(TAG, 'usb [param:""] getFileDescriptor ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetFileDescriptorParamErr004 catch err code: ',
                err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_7900
     * @tc.name     : testGetFileDescriptorParamErr005
     * @tc.desc     : Negative test: pipe busNum is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetFileDescriptorParamErr005', 0, function () {
        console.info(TAG, 'usb testGetFileDescriptorParamErr005 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_NULL;
            let ret = usbManager.getFileDescriptor(gPipe);
            console.info(TAG, 'usb [busNum:null] getFileDescriptor ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetFileDescriptorParamErr005 catch err code: ',
                err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_8000
     * @tc.name     : testGetFileDescriptorParamErr006
     * @tc.desc     : Negative test: pipe busNum is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetFileDescriptorParamErr006', 0, function () {
        console.info(TAG, 'usb testGetFileDescriptorParamErr006 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_UNDEFINED;
            let ret = usbManager.getFileDescriptor(gPipe);
            console.info(TAG, 'usb [busNum:undefined] getFileDescriptor ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetFileDescriptorParamErr006 catch err code: ',
                err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_8100
     * @tc.name     : testGetFileDescriptorParamErr007
     * @tc.desc     : Negative test: pipe busNum is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetFileDescriptorParamErr007', 0, function () {
        console.info(TAG, 'usb testGetFileDescriptorParamErr007 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_NULLSTRING;
            let ret = usbManager.getFileDescriptor(gPipe);
            console.info(TAG, 'usb [busNum:""] getFileDescriptor ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetFileDescriptorParamErr007 catch err code: ',
                err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_8200
     * @tc.name     : testGetFileDescriptorParamErr008
     * @tc.desc     : Negative test: pipe devAddress is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetFileDescriptorParamErr008', 0, function () {
        console.info(TAG, 'usb testGetFileDescriptorParamErr008 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_NULL;
            let ret = usbManager.getFileDescriptor(gPipe);
            console.info(TAG, 'usb [devAddress:null] getFileDescriptor ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetFileDescriptorParamErr008 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_8300
     * @tc.name     : testGetFileDescriptorParamErr009
     * @tc.desc     : Negative test: pipe devAddress is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetFileDescriptorParamErr009', 0, function () {
        console.info(TAG, 'usb testGetFileDescriptorParamErr009 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_UNDEFINED;
            let ret = usbManager.getFileDescriptor(gPipe);
            console.info(TAG, 'usb [devAddress:undefined] getFileDescriptor ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetFileDescriptorParamErr009 catch err code: ',
                err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_8400
     * @tc.name     : testGetFileDescriptorParamErr010
     * @tc.desc     : Negative test: devices devAddress is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testGetFileDescriptorParamErr010', 0, function () {
        console.info(TAG, 'usb testGetFileDescriptorParamErr010 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_NULLSTRING;
            let ret = usbManager.getFileDescriptor(gPipe);
            console.info(TAG, 'usb [devAddress:""] getFileDescriptor ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testGetFileDescriptorParamErr010 catch err code: ',
                err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_8500
     * @tc.name     : testClaimInterfaceParamErr001
     * @tc.desc     : Negative test: Param is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr001', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr001 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.claimInterface(PARAM_NULL);
            console.info(TAG, 'usb [param:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr001 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_8600
     * @tc.name     : testClaimInterfaceParamErr002
     * @tc.desc     : Negative test: Param is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr002', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr002 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.claimInterface(PARAM_UNDEFINED);
            console.info(TAG, 'usb [param:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr002 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_8700
     * @tc.name     : testClaimInterfaceParamErr003
     * @tc.desc     : Negative test: Param is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr003', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr003 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.claimInterface(PARAM_NULLSTRING);
            console.info(TAG, 'usb [param:""] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr003 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_8800
     * @tc.name     : testClaimInterfaceParamErr004
     * @tc.desc     : Negative test: pipe busNum is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr004', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr004 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_NULL;
            let tmpInterface = devices.configs[0].interfaces[0];
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [busNum:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr004 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_8900
     * @tc.name     : testClaimInterfaceParamErr005
     * @tc.desc     : Negative test: pipe busNum is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr005', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr005 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_UNDEFINED;
            let tmpInterface = devices.configs[0].interfaces[0];
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [busNum:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr005 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_9000
     * @tc.name     : testClaimInterfaceParamErr006
     * @tc.desc     : Negative test: pipe busNum is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr006', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr006 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = PARAM_NULLSTRING;
            let tmpInterface = devices.configs[0].interfaces[0];
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [busNum:""] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr006 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_9100
     * @tc.name     : testClaimInterfaceParamErr007
     * @tc.desc     : Negative test: pipe devAddress is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr007', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr007 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_NULL;
            let tmpInterface = devices.configs[0].interfaces[0];
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [devAddress:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr007 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_9200
     * @tc.name     : testClaimInterfaceParamErr008
     * @tc.desc     : Negative test: pipe devAddress is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr008', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr008 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_UNDEFINED;
            let tmpInterface = devices.configs[0].interfaces[0];
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [devAddress:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr008 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_9300
     * @tc.name     : testClaimInterfaceParamErr009
     * @tc.desc     : Negative test: pipe devAddress is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr009', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr009 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.devAddress = PARAM_NULLSTRING;
            let tmpInterface = devices.configs[0].interfaces[0];
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [devAddress:""] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr009 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_9400
     * @tc.name     : testClaimInterfaceParamErr010
     * @tc.desc     : Negative test: interfaces id is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr010', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr010 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.id = PARAM_NULL;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.id:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr010 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_9500
     * @tc.name     : testClaimInterfaceParamErr011
     * @tc.desc     : Negative test: interfaces id is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr011', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr011 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.id = PARAM_UNDEFINED;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.id:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr011 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_9600
     * @tc.name     : testClaimInterfaceParamErr012
     * @tc.desc     : Negative test: interfaces id is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr012', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr012 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.id = PARAM_NULLSTRING;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.id:""] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr012 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_9700
     * @tc.name     : testClaimInterfaceParamErr013
     * @tc.desc     : Negative test: interfaces protocol is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr013', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr013 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.protocol = PARAM_NULL;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.protocol:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr013 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_9800
     * @tc.name     : testClaimInterfaceParamErr014
     * @tc.desc     : Negative test: interfaces protocol is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr014', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr014 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.protocol = PARAM_UNDEFINED;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.protocol:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr014 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_9900
     * @tc.name     : testClaimInterfaceParamErr015
     * @tc.desc     : Negative test: interfaces protocol is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr015', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr015 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.protocol = PARAM_NULLSTRING;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.protocol:""] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr015 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0110
     * @tc.name     : testClaimInterfaceParamErr016
     * @tc.desc     : Negative test: interfaces clazz is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr016', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr016 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.clazz = PARAM_NULL;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.clazz:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr016 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0120
     * @tc.name     : testClaimInterfaceParamErr017
     * @tc.desc     : Negative test: interfaces clazz is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr017', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr017 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.clazz = PARAM_UNDEFINED;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.clazz:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr017 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0130
     * @tc.name     : testClaimInterfaceParamErr018
     * @tc.desc     : Negative test: interfaces clazz is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr018', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr018 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.clazz = PARAM_NULLSTRING;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.clazz:""] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr018 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0140
     * @tc.name     : testClaimInterfaceParamErr019
     * @tc.desc     : Negative test: interfaces name is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr019', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr019 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.name = PARAM_NULL;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.name:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr019 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0150
     * @tc.name     : testClaimInterfaceParamErr020
     * @tc.desc     : Negative test: interfaces name is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr020', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr020 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.name = PARAM_UNDEFINED;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.name:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr020 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0160
     * @tc.name     : testClaimInterfaceParamErr021
     * @tc.desc     : Negative test: interfaces name is number
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr021', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr021 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.name = PARAM_NUMBERTYPE;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.name:number_123] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr021 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0170
     * @tc.name     : testClaimInterfaceParamErr022
     * @tc.desc     : Negative test: interfaces subClass is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr022', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr022 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.subClass = PARAM_NULL;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.subClass:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr022 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0180
     * @tc.name     : testClaimInterfaceParamErr023
     * @tc.desc     : Negative test: interfaces subClass is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr023', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr023 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.subClass = PARAM_UNDEFINED;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.subClass:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr023 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0190
     * @tc.name     : testClaimInterfaceParamErr024
     * @tc.desc     : Negative test: interfaces subClass is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr024', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr024 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.subClass = PARAM_NULLSTRING;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.subClass:""] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr024 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0210
     * @tc.name     : testClaimInterfaceParamErr025
     * @tc.desc     : Negative test: interfaces alternateSetting is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr025', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr025 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.alternateSetting = PARAM_NULL;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.alternateSetting:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr025 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0220
     * @tc.name     : testClaimInterfaceParamErr026
     * @tc.desc     : Negative test: interfaces alternateSetting is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr026', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr026 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.alternateSetting = PARAM_UNDEFINED;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.alternateSetting:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr026 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0230
     * @tc.name     : testClaimInterfaceParamErr027
     * @tc.desc     : Negative test: interfaces alternateSetting is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr027', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr027 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.alternateSetting = PARAM_NULLSTRING;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.alternateSetting:""] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr027 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0240
     * @tc.name     : testClaimInterfaceParamErr028
     * @tc.desc     : Negative test: interfaces endpoints is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr028', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr028 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.endpoints = PARAM_NULL;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.endpoints:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr028 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0250
     * @tc.name     : testClaimInterfaceParamErr029
     * @tc.desc     : Negative test: interfaces endpoints is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr029', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr029 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.endpoints = PARAM_UNDEFINED;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.endpoints:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr029 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0260
     * @tc.name     : testClaimInterfaceParamErr030
     * @tc.desc     : Negative test: interfaces endpoints is null string ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr030', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr030 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpInterface = devices.configs[0].interfaces[0];
            tmpInterface.endpoints = PARAM_NULLSTRING;
            let ret = usbManager.claimInterface(gPipe, tmpInterface);
            console.info(TAG, 'usb [interfaces.endpoints:""] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr030 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0270
     * @tc.name     : testClaimInterfaceParamErr031
     * @tc.desc     : Negative test: Enter four parameters
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr031', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr031 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        getPipe('testClaimInterfaceParamErr031');
        let tmpInterface = devices.configs[0].interfaces[0];
        try {
            let ret = usbManager.claimInterface(gPipe, tmpInterface, true, gPipe);
            console.info(TAG, 'usb [Enter four param] claimInterface ret : ', ret);
            expect(ret).assertEqual(0);
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr031 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
        toReleaseInterface('testClaimInterfaceParamErr031', tmpInterface);
        toClosePipe('testClaimInterfaceParamErr031');
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0280
     * @tc.name     : testClaimInterfaceParamErr032
     * @tc.desc     : Negative test: iface is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr032', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr032 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let ret = usbManager.claimInterface(gPipe, PARAM_NULL);
            console.info(TAG, 'usb [iface:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr032 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0290
     * @tc.name     : testClaimInterfaceParamErr033
     * @tc.desc     : Negative test: iface is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr033', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr033 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let ret = usbManager.claimInterface(gPipe, PARAM_UNDEFINED);
            console.info(TAG, 'usb [iface:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr033 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0310
     * @tc.name     : testClaimInterfaceParamErr034
     * @tc.desc     : Negative test: iface is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr034', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr034 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let ret = usbManager.claimInterface(gPipe, PARAM_NULLSTRING);
            console.info(TAG, 'usb [iface:""] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr034 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0320
     * @tc.name     : testClaimInterfaceParamErr035
     * @tc.desc     : Negative test: pipe is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr035', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr035 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let tmpInterface = devices.configs[0].interfaces[0];
            let ret = usbManager.claimInterface(PARAM_NULL, tmpInterface);
            console.info(TAG, 'usb [iface:null] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr035 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0330
     * @tc.name     : testClaimInterfaceParamErr036
     * @tc.desc     : Negative test: pipe is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr036', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr036 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let tmpInterface = devices.configs[0].interfaces[0];
            let ret = usbManager.claimInterface(PARAM_UNDEFINED, tmpInterface);
            console.info(TAG, 'usb [iface:undefined] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr036 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0340
     * @tc.name     : testClaimInterfaceParamErr037
     * @tc.desc     : Negative test: pipe is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testClaimInterfaceParamErr037', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr037 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let tmpInterface = devices.configs[0].interfaces[0];
            let ret = usbManager.claimInterface(PARAM_NULLSTRING, tmpInterface);
            console.info(TAG, 'usb [iface:""] claimInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr037 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0350
     * @tc.name     : testClaimInterfaceParamErr038
     * @tc.desc     : Negative test: force is null string
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
     it('testClaimInterfaceParamErr038', 0, function () {
        console.info(TAG, 'usb testClaimInterfaceParamErr038 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        getPipe('testClaimInterfaceParamErr038');
        let tmpInterface = devices.configs[0].interfaces[0];
        try {
            let ret = usbManager.claimInterface(gPipe, tmpInterface, PARAM_NULLSTRING);
            console.info(TAG, 'usb [force:""] claimInterface ret : ', ret);
            expect(ret).assertEqual(0);
        } catch (err) {
            console.info(TAG, 'testClaimInterfaceParamErr038 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
        toReleaseInterface('testClaimInterfaceParamErr038', tmpInterface);
        toClosePipe('testClaimInterfaceParamErr038');
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0360
     * @tc.name     : testSetConfigurationParamErr001
     * @tc.desc     : Negative test: Enter two parameters
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr001', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr001 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        getPipe('testSetConfigurationParamErr001');
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            let ret = usbManager.setConfiguration(gPipe, tmpConfig, gPipe);
            console.info(TAG, 'usb [Enter two parameters] setConfiguration ret : ', ret);
            expect(ret).assertEqual(0);
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr001 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
        toClosePipe('testSetConfigurationParamErr001');
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0370
     * @tc.name     : testSetConfigurationParamErr002
     * @tc.desc     : Negative test: Param is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr002', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr002 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.setConfiguration(PARAM_NULL);
            console.info(TAG, 'usb [param:null] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr002 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0380
     * @tc.name     : testSetConfigurationParamErr003
     * @tc.desc     : Negative test: Param is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr003', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr003 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.setConfiguration(PARAM_UNDEFINED);
            console.info(TAG, 'usb [param:undefined] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr003 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0390
     * @tc.name     : testSetConfigurationParamErr004
     * @tc.desc     : Negative test: Param is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr004', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr004 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.setConfiguration(PARAM_NULLSTRING);
            console.info(TAG, 'usb [param:""] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr004 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0410
     * @tc.name     : testSetConfigurationParamErr005
     * @tc.desc     : Negative test: pipe is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr005', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr005 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let tmpConfig = devices.configs[0];
            let ret = usbManager.setConfiguration(PARAM_NULL, tmpConfig);
            console.info(TAG, 'usb [pipe:null] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr005 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0420
     * @tc.name     : testSetConfigurationParamErr006
     * @tc.desc     : Negative test: pipe is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr006', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr006 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let tmpConfig = devices.configs[0];
            let ret = usbManager.setConfiguration(PARAM_UNDEFINED, tmpConfig);
            console.info(TAG, 'usb [pipe:undefined] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr006 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0430
     * @tc.name     : testSetConfigurationParamErr007
     * @tc.desc     : Negative test: pipe is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr007', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr007 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let tmpConfig = devices.configs[0];
            let ret = usbManager.setConfiguration(PARAM_NULLSTRING, tmpConfig);
            console.info(TAG, 'usb [pipe:""] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr007 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0440
     * @tc.name     : testSetConfigurationParamErr008
     * @tc.desc     : Negative test: config is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr008', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr008 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let ret = usbManager.setConfiguration(gPipe, PARAM_NULL);
            console.info(TAG, 'usb [config:null] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr008 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0450
     * @tc.name     : testSetConfigurationParamErr009
     * @tc.desc     : Negative test: config is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr009', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr009 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let ret = usbManager.setConfiguration(gPipe, PARAM_UNDEFINED);
            console.info(TAG, 'usb [config:undefined] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr009 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0460
     * @tc.name     : testSetConfigurationParamErr010
     * @tc.desc     : Negative test: config is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr010', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr010 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let ret = usbManager.setConfiguration(gPipe, PARAM_NULLSTRING);
            console.info(TAG, 'usb [config:""] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr010 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0470
     * @tc.name     : testSetConfigurationParamErr011
     * @tc.desc     : Negative test: config id is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr011', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr011 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.id = PARAM_NULL;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.id:null] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr011 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0480
     * @tc.name     : testSetConfigurationParamErr012
     * @tc.desc     : Negative test: config id is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr012', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr012 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.id = PARAM_UNDEFINED;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.id:undefined] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr012 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0490
     * @tc.name     : testSetConfigurationParamErr013
     * @tc.desc     : Negative test: config id is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr013', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr013 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.id = PARAM_NULLSTRING;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.id:""] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr013 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0510
     * @tc.name     : testSetConfigurationParamErr014
     * @tc.desc     : Negative test: config attributes is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr014', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr014 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.attributes = PARAM_NULL;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.attributes:null] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr014 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0520
     * @tc.name     : testSetConfigurationParamErr015
     * @tc.desc     : Negative test: config attributes is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr015', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr015 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.attributes = PARAM_UNDEFINED;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.attributes:undefined] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr015 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0530
     * @tc.name     : testSetConfigurationParamErr016
     * @tc.desc     : Negative test: config attributes is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr016', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr016 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.attributes = PARAM_NULLSTRING;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.attributes:""] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr016 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0540
     * @tc.name     : testSetConfigurationParamErr017
     * @tc.desc     : Negative test: config maxPower is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr017', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr017 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.maxPower = PARAM_NULL;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.maxPower:null] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr017 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0550
     * @tc.name     : testSetConfigurationParamErr018
     * @tc.desc     : Negative test: config maxPower is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr018', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr018 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.maxPower = PARAM_UNDEFINED;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.maxPower:undefined] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr018 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0560
     * @tc.name     : testSetConfigurationParamErr019
     * @tc.desc     : Negative test: config maxPower is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr019', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr019 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.maxPower = PARAM_NULLSTRING;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.maxPower:""] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr019 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0570
     * @tc.name     : testSetConfigurationParamErr020
     * @tc.desc     : Negative test: config name is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr020', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr020 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.name = PARAM_NULL;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.name:null] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr020 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0580
     * @tc.name     : testSetConfigurationParamErr021
     * @tc.desc     : Negative test: config name is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr021', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr021 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.name = PARAM_UNDEFINED;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.name:undefined] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr021 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0590
     * @tc.name     : testSetConfigurationParamErr022
     * @tc.desc     : Negative test: config name is 123
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr022', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr022 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.name = PARAM_NUMBERTYPE;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.name:""] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr022 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0610
     * @tc.name     : testSetConfigurationParamErr023
     * @tc.desc     : Negative test: config isRemoteWakeup is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr023', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr023 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.isRemoteWakeup = PARAM_NULL;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.isRemoteWakeup:null] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr023 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0620
     * @tc.name     : testSetConfigurationParamErr024
     * @tc.desc     : Negative test: config isRemoteWakeup is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr024', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr024 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.isRemoteWakeup = PARAM_UNDEFINED;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.isRemoteWakeup:undefined] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr024 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0630
     * @tc.name     : testSetConfigurationParamErr025
     * @tc.desc     : Negative test: config isRemoteWakeup is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr025', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr025 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.isRemoteWakeup = PARAM_NULLSTRING;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.isRemoteWakeup:""] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr025 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0640
     * @tc.name     : testSetConfigurationParamErr026
     * @tc.desc     : Negative test: config isSelfPowered is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr026', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr026 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.isSelfPowered = PARAM_NULL;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.isSelfPowered:null] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr026 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0650
     * @tc.name     : testSetConfigurationParamErr027
     * @tc.desc     : Negative test: config isSelfPowered is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr027', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr027 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.isSelfPowered = PARAM_UNDEFINED;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.isSelfPowered:undefined] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr027 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0660
     * @tc.name     : testSetConfigurationParamErr028
     * @tc.desc     : Negative test: config isSelfPowered is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr028', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr028 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.isSelfPowered = PARAM_NULLSTRING;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.isSelfPowered:""] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr028 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0670
     * @tc.name     : testSetConfigurationParamErr029
     * @tc.desc     : Negative test: config interfaces is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr029', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr029 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.interfaces = PARAM_NULL;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.interfaces:null] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr029 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0680
     * @tc.name     : testSetConfigurationParamErr030
     * @tc.desc     : Negative test: config interfaces is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr030', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr030 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.interfaces = PARAM_UNDEFINED;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.interfaces:undefined] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr030 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0690
     * @tc.name     : testSetConfigurationParamErr031
     * @tc.desc     : Negative test: config interfaces is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr031', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr031 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.interfaces = PARAM_NULLSTRING;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.interfaces:""] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr031 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0710
     * @tc.name     : testSetConfigurationParamErr032
     * @tc.desc     : Negative test: config isRemoteWakeup is 123
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr032', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr032 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.isRemoteWakeup = PARAM_NUMBERTYPE;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.isRemoteWakeup:123] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr032 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0720
     * @tc.name     : testSetConfigurationParamErr033
     * @tc.desc     : Negative test: config isSelfPowered is 123
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr033', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr033 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.isSelfPowered = PARAM_NUMBERTYPE;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.isSelfPowered:123] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr033 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0730
     * @tc.name     : testSetConfigurationParamErr034
     * @tc.desc     : Negative test: config interfaces is 123
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetConfigurationParamErr034', 0, function () {
        console.info(TAG, 'usb testSetConfigurationParamErr034 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            gPipe.busNum = devices.busNum;
            gPipe.devAddress = devices.devAddress;
            let tmpConfig = devices.configs[0];
            tmpConfig.interfaces = PARAM_NUMBERTYPE;
            let ret = usbManager.setConfiguration(gPipe, tmpConfig);
            console.info(TAG, 'usb [config.interfaces:123] setConfiguration ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetConfigurationParamErr034 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0740
     * @tc.name     : testSetInterfaceParamErr001
     * @tc.desc     : Negative test: Enter three parameters
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetInterfaceParamErr001', 0, function () {
        console.info(TAG, 'usb testSetInterfaceParamErr001 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        getPipe('testSetInterfaceParamErr001');
        let tmpInterface = devices.configs[0].interfaces[0];
        let isClaim = usbManager.claimInterface(gPipe, tmpInterface, true);
        expect(isClaim).assertEqual(0);
        try {
            let ret = usbManager.setInterface(gPipe, tmpInterface, gPipe);
            console.info(TAG, 'usb [Enter three parameters] setInterface ret : ', ret);
            expect(ret).assertEqual(0);
        } catch (err) {
            console.info(TAG, 'testSetInterfaceParamErr001 catch err code: ', err.code, ', message: ', err.message);
            expect(err !== null).assertFalse();
        }
        toReleaseInterface('testSetInterfaceParamErr001', tmpInterface);
        toClosePipe('testSetInterfaceParamErr001');
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0750
     * @tc.name     : testSetInterfaceParamErr002
     * @tc.desc     : Negative test: Param is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetInterfaceParamErr002', 0, function () {
        console.info(TAG, 'usb testSetInterfaceParamErr002 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.setInterface(PARAM_NULL);
            console.info(TAG, 'usb [param:null] setInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetInterfaceParamErr002 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0760
     * @tc.name     : testSetInterfaceParamErr003
     * @tc.desc     : Negative test: Param is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetInterfaceParamErr003', 0, function () {
        console.info(TAG, 'usb testSetInterfaceParamErr003 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.setInterface(PARAM_UNDEFINED);
            console.info(TAG, 'usb [param:undefined] setInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetInterfaceParamErr003 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0770
     * @tc.name     : testSetInterfaceParamErr004
     * @tc.desc     : Negative test: Param is ""
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetInterfaceParamErr004', 0, function () {
        console.info(TAG, 'usb testSetInterfaceParamErr004 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let ret = usbManager.setInterface(PARAM_NULLSTRING);
            console.info(TAG, 'usb [param:""] setInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetInterfaceParamErr004 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0780
     * @tc.name     : testSetInterfaceParamErr005
     * @tc.desc     : Negative test: pipe is null
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetInterfaceParamErr005', 0, function () {
        console.info(TAG, 'usb testSetInterfaceParamErr005 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let tmpInterface = devices.configs[0].interfaces[0];
            let ret = usbManager.setInterface(PARAM_NULL, tmpInterface);
            console.info(TAG, 'usb [pipe:null] setInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetInterfaceParamErr005 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })

    /**
     * @tc.number   : SUB_USB_HostManager_JS_ParamErr_0790
     * @tc.name     : testSetInterfaceParamErr006
     * @tc.desc     : Negative test: pipe is undefined
     * @tc.size     : MediumTest
     * @tc.type     : Function
     * @tc.level    : Level 3
     */
    it('testSetInterfaceParamErr006', 0, function () {
        console.info(TAG, 'usb testSetInterfaceParamErr006 begin');
        if (!isDeviceConnected) {
            expect(isDeviceConnected).assertFalse();
            return
        }
        try {
            let tmpInterface = devices.configs[0].interfaces[0];
            let ret = usbManager.setInterface(PARAM_UNDEFINED, tmpInterface);
            console.info(TAG, 'usb [pipe:undefined] setInterface ret : ', ret);
            expect(ret !== null).assertFalse();
        } catch (err) {
            console.info(TAG, 'testSetInterfaceParamErr006 catch err code: ', err.code, ', message: ', err.message);
            expect(err.code).assertEqual(PARAM_ERRCODE);
        }
    })
})
}