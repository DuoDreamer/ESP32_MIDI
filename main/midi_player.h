#ifndef MIDI_PLAYER_H
#define MIDI_PLAYER_H

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize UART and timer for MIDI playback */
esp_err_t midi_player_init(void);

/* Load a MIDI file and parse a specific track */
esp_err_t midi_player_load(const char *path, int track_index);

/* Start or resume playback */
esp_err_t midi_player_play(void);

/* Pause playback */
esp_err_t midi_player_pause(void);

/* Stop playback and reset to start */
esp_err_t midi_player_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* MIDI_PLAYER_H */
