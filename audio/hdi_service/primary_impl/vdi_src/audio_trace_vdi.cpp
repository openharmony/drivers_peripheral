#include "audio_trace_vdi.h"
#include <hitrace_meter.h>

void HdfAudioStartTrace(const char* value, int valueLen) {
    (void) valueLen;
    StartTrace(HITRACE_TAG_HDF, value);
}

void HdfAudioFinshTrace() {
    FinishTrace(HITRACE_TAG_HDF);
}