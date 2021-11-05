/*
 ** add for tinyalsa setting route by Jear.Chen
 */
/**
 * @file config.h
 * @author RkAudio
 * @version 1.0.8
 * @date 2015-08-24
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#define DEVICES_0 0
struct RouteCfgInfo {
    const char *controlName;   // name of control.
    const char *stringVal;  // value of control, which type is stream.
    const int intVal[2];    // left and right value of control, which type are int.
};

struct PathRoute {
    const int sndCard;
    const int devices;
    const struct RouteCfgInfo *controls;
    const unsigned ctlsNums;
};

struct PathRouteCfgTable {
    const struct PathRoute speakNormal; //
    const struct PathRoute headphoneNormal;  //
    const struct PathRoute HdmiNormal;  //
    const struct PathRoute speakerHeadphoneNormal; //

    const struct PathRoute mainMicCapture;  // 
    const struct PathRoute handsFreeMicCapture; // 

    const struct PathRoute playbackOff;  //
    const struct PathRoute captureOff;  // 
};

struct TinyalsaSndCardCfg {
    const char *sndCardName;
    const struct PathRouteCfgTable *pathRouteMap;
};

#endif // _CONFIG_H_
