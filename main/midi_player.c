#include "midi_player.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIDI_UART_NUM UART_NUM_1
#define MIDI_UART_TX_PIN GPIO_NUM_17

static const char *TAG = "MIDI_PLAYER";

typedef struct {
    uint64_t time_us;            /* absolute time from start */
    uint8_t data[3];             /* MIDI bytes */
    uint8_t len;                 /* number of bytes */
} midi_event_t;

typedef struct {
    midi_event_t *events;
    size_t count;
} midi_track_t;

static midi_track_t s_track = {0};
static size_t s_current = 0;
static bool s_playing = false;
static esp_timer_handle_t s_timer;

static uint32_t read_be32(FILE *f)
{
    uint8_t b[4];
    if (fread(b, 1, 4, f) != 4)
        return 0;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

static uint16_t read_be16(FILE *f)
{
    uint8_t b[2];
    if (fread(b, 1, 2, f) != 2)
        return 0;
    return ((uint16_t)b[0] << 8) | b[1];
}

static uint32_t read_vlq(FILE *f)
{
    uint32_t value = 0;
    int c;
    do {
        c = fgetc(f);
        if (c == EOF)
            return value;
        value = (value << 7) | (c & 0x7F);
    } while (c & 0x80);
    return value;
}

static esp_err_t parse_midi(const char *path, int track_index, midi_track_t *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open %s", path);
        return ESP_FAIL;
    }

    uint8_t chunk_id[4];
    if (fread(chunk_id, 1, 4, f) != 4 || memcmp(chunk_id, "MThd", 4) != 0) {
        ESP_LOGE(TAG, "Invalid MIDI header");
        fclose(f);
        return ESP_FAIL;
    }
    uint32_t hdr_len = read_be32(f);
    uint16_t format = read_be16(f);
    uint16_t ntrks = read_be16(f);
    uint16_t division = read_be16(f);
    if (hdr_len > 6)
        fseek(f, hdr_len - 6, SEEK_CUR);

    if (track_index >= ntrks) {
        ESP_LOGE(TAG, "Track %d out of range", track_index);
        fclose(f);
        return ESP_FAIL;
    }

    /* default tempo 500000 us per quarter note */
    uint32_t tempo = 500000;
    double us_per_tick = (double)tempo / division;

    midi_event_t *events = NULL;
    size_t count = 0;

    for (int t = 0; t < ntrks; t++) {
        if (fread(chunk_id, 1, 4, f) != 4 || memcmp(chunk_id, "MTrk", 4) != 0) {
            ESP_LOGE(TAG, "Missing track chunk");
            free(events);
            fclose(f);
            return ESP_FAIL;
        }
        uint32_t track_len = read_be32(f);
        if (t != track_index) {
            fseek(f, track_len, SEEK_CUR);
            continue;
        }
        long track_end = ftell(f) + track_len;
        uint8_t running = 0;
        uint64_t time_us = 0;
        while (ftell(f) < track_end) {
            uint32_t delta = read_vlq(f);
            time_us += (uint64_t)(delta * us_per_tick);
            int c = fgetc(f);
            if (c == EOF)
                break;
            uint8_t status = (uint8_t)c;
            if (status < 0x80) { /* running status */
                if (!running) {
                    ESP_LOGE(TAG, "Running status without previous status");
                    free(events);
                    fclose(f);
                    return ESP_FAIL;
                }
                ungetc(status, f);
                status = running;
            } else {
                running = status;
            }

            if (status == 0xFF) {
                int type = fgetc(f);
                uint32_t len = read_vlq(f);
                if (type == 0x51 && len == 3) {
                    uint8_t tb[3];
                    fread(tb, 1, 3, f);
                    tempo = (tb[0] << 16) | (tb[1] << 8) | tb[2];
                    us_per_tick = (double)tempo / division;
                } else {
                    fseek(f, len, SEEK_CUR);
                }
                if (type == 0x2F) {
                    break; /* end of track */
                }
                continue; /* meta events not stored */
            } else if (status == 0xF0 || status == 0xF7) {
                uint32_t len = read_vlq(f);
                fseek(f, len, SEEK_CUR); /* skip sysex */
                continue;
            }

            int needed = ((status & 0xF0) == 0xC0 || (status & 0xF0) == 0xD0) ? 1 : 2;
            uint8_t data[2] = {0};
            fread(data, 1, needed, f);
            midi_event_t *tmp = realloc(events, (count + 1) * sizeof(midi_event_t));
            if (!tmp) {
                free(events);
                fclose(f);
                return ESP_ERR_NO_MEM;
            }
            events = tmp;
            events[count].time_us = time_us;
            events[count].data[0] = status;
            events[count].len = needed + 1;
            if (needed >= 1)
                events[count].data[1] = data[0];
            if (needed == 2)
                events[count].data[2] = data[1];
            count++;
        }
    }

    fclose(f);
    out->events = events;
    out->count = count;
    ESP_LOGI(TAG, "Parsed %zu events", count);
    return ESP_OK;
}

static void timer_cb(void *arg)
{
    if (!s_playing || s_current >= s_track.count)
        return;
    midi_event_t *e = &s_track.events[s_current];
    uart_write_bytes(MIDI_UART_NUM, (const char *)e->data, e->len);
    s_current++;
    if (s_current < s_track.count) {
        uint64_t delay = s_track.events[s_current].time_us - e->time_us;
        esp_timer_start_once(s_timer, delay);
    } else {
        s_playing = false;
    }
}

esp_err_t midi_player_init(void)
{
    const uart_config_t cfg = {
        .baud_rate = 31250,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_APB,
    };
    ESP_ERROR_CHECK(uart_param_config(MIDI_UART_NUM, &cfg));
    ESP_ERROR_CHECK(uart_set_pin(MIDI_UART_NUM, MIDI_UART_TX_PIN, UART_PIN_NO_CHANGE,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    ESP_ERROR_CHECK(uart_driver_install(MIDI_UART_NUM, 1024, 0, 0, NULL, 0));

    esp_timer_create_args_t args = {
        .callback = timer_cb,
        .name = "midi"};
    return esp_timer_create(&args, &s_timer);
}

esp_err_t midi_player_load(const char *path, int track_index)
{
    if (s_track.events) {
        free(s_track.events);
        s_track.events = NULL;
        s_track.count = 0;
    }
    s_current = 0;
    return parse_midi(path, track_index, &s_track);
}

esp_err_t midi_player_play(void)
{
    if (!s_track.events || s_track.count == 0)
        return ESP_FAIL;
    if (s_playing)
        return ESP_OK;
    uint64_t delay;
    if (s_current == 0)
        delay = s_track.events[0].time_us;
    else
        delay = s_track.events[s_current].time_us - s_track.events[s_current - 1].time_us;
    s_playing = true;
    return esp_timer_start_once(s_timer, delay);
}

esp_err_t midi_player_pause(void)
{
    if (!s_playing)
        return ESP_OK;
    esp_timer_stop(s_timer);
    s_playing = false;
    return ESP_OK;
}

esp_err_t midi_player_stop(void)
{
    esp_timer_stop(s_timer);
    s_current = 0;
    s_playing = false;
    return ESP_OK;
}

esp_err_t midi_player_send(const uint8_t *data, size_t len)
{
    if (!data || len == 0)
        return ESP_ERR_INVALID_ARG;
    int sent = uart_write_bytes(MIDI_UART_NUM, (const char *)data, len);
    return (sent == (int)len) ? ESP_OK : ESP_FAIL;
}
