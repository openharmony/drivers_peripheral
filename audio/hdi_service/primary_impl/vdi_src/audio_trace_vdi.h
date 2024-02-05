#ifndef AUDIO_TRACE_VDI_H
#define AUDIO_TRACE_VDI_H

#ifdef __cplusplus
extern "C" {
#endif

void HdfAudioStartTrace(const char* value, int valueLen);
void HdfAudioFinshTrace();

#ifdef __cplusplus
}
#endif
#endif /* AUDIO_TRACE_VDI_H */