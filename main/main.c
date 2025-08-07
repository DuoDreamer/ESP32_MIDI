#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"

#include "esp_https_server.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "esp_spiffs.h"

#include "nvs.h"
#include "nvs_flash.h"
#include "midi_player.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <stdbool.h>
#include <ctype.h>
#include <stdlib.h>

static const char *TAG = "ESP32_MIDI";

#define AUTH_TOKEN "midi123"
#define UPDATE_URL "https://example.com/firmware.bin"
#define OTA_CHECK_INTERVAL_MS (60 * 60 * 1000)
#define CERT_BUF_SIZE 2048

static bool check_token(httpd_req_t *req)
{
    char token[32];
    if (httpd_req_get_hdr_value_str(req, "X-Auth-Token", token, sizeof(token)) == ESP_OK) {
        if (strcmp(token, AUTH_TOKEN) == 0)
            return true;
    }
    return false;
}

static char *memfind(const char *buf, size_t len, const char *pat, size_t pat_len)
{
    if (pat_len == 0)
        return NULL;
    for (size_t i = 0; i + pat_len <= len; i++) {
        if (buf[i] == pat[0] && memcmp(buf + i, pat, pat_len) == 0)
            return (char *)(buf + i);
    }
    return NULL;
}

static esp_err_t midi_post_handler(httpd_req_t *req)
{
    if (!check_token(req))
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");

    char buf[64];
    int received = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (received <= 0)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No data");
    buf[received] = '\0';

    uint8_t midi[3];
    size_t midi_len = 0;
    char *p = buf;
    while (*p && midi_len < sizeof(midi)) {
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')
            p++;
        if (!isxdigit((unsigned char)p[0]) || !isxdigit((unsigned char)p[1]))
            break;
        char byte_str[3] = {p[0], p[1], 0};
        midi[midi_len++] = strtol(byte_str, NULL, 16);
        p += 2;
    }
    if (midi_len == 0)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad data");
    midi_player_send(midi, midi_len);
    return httpd_resp_sendstr(req, "OK");
}

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        if (!check_token(req))
            return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_OK;
    }

    httpd_ws_frame_t ws_pkt;
    uint8_t buf[32];
    memset(&ws_pkt, 0, sizeof(ws_pkt));
    ws_pkt.payload = buf;
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, sizeof(buf));
    if (ret != ESP_OK)
        return ret;
    if (ws_pkt.len > 0)
        midi_player_send(ws_pkt.payload, ws_pkt.len);
    return ESP_OK;
}

static void udp_server_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(5005),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    while (1) {
        uint8_t rx_buffer[64];
        struct sockaddr_in source_addr;
        socklen_t socklen = sizeof(source_addr);
        int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer), 0,
                           (struct sockaddr *)&source_addr, &socklen);
        if (len <= 0)
            continue;
        size_t token_len = strlen(AUTH_TOKEN);
        if (len <= token_len + 1)
            continue;
        if (memcmp(rx_buffer, AUTH_TOKEN, token_len) != 0 || rx_buffer[token_len] != ':')
            continue;
        midi_player_send(rx_buffer + token_len + 1, len - token_len - 1);
    }
    close(sock);
    vTaskDelete(NULL);
}

static StackType_t udp_task_stack[4096];
static StaticTask_t udp_task_tcb;


/* Embedded default certificate and key */
extern const unsigned char certs_server_cert_pem_start[] asm("_binary_certs_server_cert_pem_start");
extern const unsigned char certs_server_cert_pem_end[] asm("_binary_certs_server_cert_pem_end");
extern const unsigned char certs_server_key_pem_start[] asm("_binary_certs_server_key_pem_start");
extern const unsigned char certs_server_key_pem_end[] asm("_binary_certs_server_key_pem_end");

static char loaded_cert[CERT_BUF_SIZE];
static char loaded_key[CERT_BUF_SIZE];
static size_t loaded_cert_len = 0;
static size_t loaded_key_len = 0;

static esp_err_t root_get_handler(httpd_req_t *req)
{
    const char resp[] =
        "<!DOCTYPE html><html><body>"
        "<h1>ESP32 Config</h1>"
        "<form method='POST' action='/config'>"
        "SSID: <input name='ssid'><br>"
        "Password: <input type='password' name='password'><br>"
        "<input type='submit' value='Save'></form>"
        "<h2>Upload File</h2>"
        "<form method='POST' action='/upload' enctype='multipart/form-data'>"
        "<input type='file' name='file'>"
        "<input type='submit' value='Upload'></form>"
        "<h2>Firmware Update</h2>"
        "<form method='POST' action='/ota' enctype='multipart/form-data'>"
        "<input type='file' name='file'>"
        "<input type='submit' value='Update Firmware'></form>"
        "</body></html>";

    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t config_post_handler(httpd_req_t *req)
{
    char buf[128];
    int received = 0;
    while (received < req->content_len) {
        int ret = httpd_req_recv(req, buf + received, sizeof(buf) - received - 1);
        if (ret <= 0) {
            return ESP_FAIL;
        }
        received += ret;
    }
    buf[received] = '\0';

    char ssid[32] = {0};
    char pass[64] = {0};
    httpd_query_key_value(buf, "ssid", ssid, sizeof(ssid));
    httpd_query_key_value(buf, "password", pass, sizeof(pass));

    nvs_handle_t nvs;
    if (nvs_open("wifi", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_set_str(nvs, "ssid", ssid);
        nvs_set_str(nvs, "pass", pass);
        nvs_commit(nvs);
        nvs_close(nvs);
    }

    httpd_resp_sendstr(req, "Saved. Rebooting...");
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

static esp_err_t upload_post_handler(httpd_req_t *req)
{
    char content_type[64];
    if (httpd_req_get_hdr_value_str(req, "Content-Type", content_type, sizeof(content_type)) != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Missing Content-Type");
    char *b_start = strstr(content_type, "boundary=");
    if (!b_start)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No boundary");
    char boundary[70];
    snprintf(boundary, sizeof(boundary), "--%s", b_start + 9);
    size_t b_len = strlen(boundary);

    char header[256];
    size_t header_len = 0;
    bool header_done = false;
    char filename[64] = {0};
    FILE *f = NULL;
    char tail[70];
    size_t tail_len = 0;
    size_t remaining = req->content_len;
    char buf[CONFIG_UPLOAD_BUF_SIZE];

    bool error = false;
    while (remaining > 0 && !error) {
        int to_read = remaining < sizeof(buf) ? remaining : sizeof(buf);
        int r = httpd_req_recv(req, buf, to_read);
        if (r <= 0) {
            error = true;
            break;
        }
        remaining -= r;
        int offset = 0;
        if (!header_done) {
            int copy = r < (int)sizeof(header) - (int)header_len - 1 ? r : (int)sizeof(header) - (int)header_len - 1;
            memcpy(header + header_len, buf, copy);
            header_len += copy;
            header[header_len] = '\0';
            char *p = strstr(header, "\r\n\r\n");
            if (!p)
                continue;
            header_done = true;
            char *filename_pos = strstr(header, "filename=");
            if (!filename_pos) {
                error = true;
                break;
            }
            filename_pos += 9;
            if (*filename_pos == '"')
                filename_pos++;
            char *filename_end = strchr(filename_pos, '"');
            if (!filename_end) {
                error = true;
                break;
            }
            size_t fname_len = filename_end - filename_pos;
            if (fname_len >= sizeof(filename))
                fname_len = sizeof(filename) - 1;
            strncpy(filename, filename_pos, fname_len);
            filename[fname_len] = '\0';
            char path[128];
            snprintf(path, sizeof(path), "/spiffs/%s", filename);
            f = fopen(path, "w");
            if (!f) {
                error = true;
                break;
            }
            offset = (p + 4) - header;
            r -= offset;
        }

        char tmp[CONFIG_UPLOAD_BUF_SIZE + 70];
        memcpy(tmp, tail, tail_len);
        memcpy(tmp + tail_len, buf + offset, r);
        size_t tmp_len = tail_len + r;
        char *bpos = memfind(tmp, tmp_len, boundary, b_len);
        if (bpos) {
            size_t data_len = bpos - tmp;
            if (data_len >= 2)
                data_len -= 2; /* strip CRLF */
            if (data_len > 0 && f)
                fwrite(tmp, 1, data_len, f);
            break;
        } else {
            if (tmp_len > b_len) {
                size_t write_len = tmp_len - b_len + 1;
                if (f)
                    fwrite(tmp, 1, write_len, f);
                tail_len = b_len - 1;
                memcpy(tail, tmp + write_len, tail_len);
            } else {
                tail_len = tmp_len;
                memcpy(tail, tmp, tail_len);
            }
        }
    }

    if (f)
        fclose(f);
    if (error)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Upload failed");
    return httpd_resp_sendstr(req, "File uploaded");
}

static esp_err_t ota_post_handler(httpd_req_t *req)
{
    char content_type[64];
    if (httpd_req_get_hdr_value_str(req, "Content-Type", content_type, sizeof(content_type)) != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Missing Content-Type");
    char *b_start = strstr(content_type, "boundary=");
    if (!b_start)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No boundary");
    char boundary[70];
    snprintf(boundary, sizeof(boundary), "--%s", b_start + 9);
    size_t b_len = strlen(boundary);

    char header[256];
    size_t header_len = 0;
    bool header_done = false;
    char tail[70];
    size_t tail_len = 0;
    size_t remaining = req->content_len;
    char buf[CONFIG_UPLOAD_BUF_SIZE];

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    esp_ota_handle_t update_handle = 0;
    esp_err_t err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &update_handle);
    if (err != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA begin failed");

    while (remaining > 0) {
        int to_read = remaining < sizeof(buf) ? remaining : sizeof(buf);
        int r = httpd_req_recv(req, buf, to_read);
        if (r <= 0) {
            esp_ota_abort(update_handle);
            return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA write failed");
        }
        remaining -= r;
        int offset = 0;
        if (!header_done) {
            int copy = r < (int)sizeof(header) - (int)header_len - 1 ? r : (int)sizeof(header) - (int)header_len - 1;
            memcpy(header + header_len, buf, copy);
            header_len += copy;
            header[header_len] = '\0';
            char *p = strstr(header, "\r\n\r\n");
            if (!p)
                continue;
            header_done = true;
            offset = (p + 4) - header;
            r -= offset;
        }

        char tmp[CONFIG_UPLOAD_BUF_SIZE + 70];
        memcpy(tmp, tail, tail_len);
        memcpy(tmp + tail_len, buf + offset, r);
        size_t tmp_len = tail_len + r;
        char *bpos = memfind(tmp, tmp_len, boundary, b_len);
        if (bpos) {
            size_t data_len = bpos - tmp;
            if (data_len >= 2)
                data_len -= 2;
            if (data_len > 0)
                esp_ota_write(update_handle, tmp, data_len);
            break;
        } else {
            if (tmp_len > b_len) {
                size_t write_len = tmp_len - b_len + 1;
                if (write_len > 0)
                    esp_ota_write(update_handle, tmp, write_len);
                tail_len = b_len - 1;
                memcpy(tail, tmp + write_len, tail_len);
            } else {
                tail_len = tmp_len;
                memcpy(tail, tmp, tail_len);
            }
        }
    }

    err = esp_ota_end(update_handle);
    if (err != ESP_OK) {
        esp_ota_abort(update_handle);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA write failed");
    }
    if (esp_ota_set_boot_partition(update_partition) != ESP_OK) {
        esp_ota_abort(update_handle);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA write failed");
    }
    httpd_resp_sendstr(req, "Update successful. Rebooting...");
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

static esp_err_t track_get_handler(httpd_req_t *req)
{
    char query[128];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No query");
    char file[64] = {0};
    char track_str[8] = {0};
    if (httpd_query_key_value(query, "file", file, sizeof(file)) != ESP_OK ||
        httpd_query_key_value(query, "track", track_str, sizeof(track_str)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad params");
    }
    int track = atoi(track_str);
    char path[128];
    snprintf(path, sizeof(path), "/spiffs/%s", file);
    if (midi_player_load(path, track) != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Load failed");
    return httpd_resp_sendstr(req, "Track loaded");
}

static esp_err_t play_get_handler(httpd_req_t *req)
{
    if (midi_player_play() != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Play failed");
    return httpd_resp_sendstr(req, "Playing");
}

static esp_err_t pause_get_handler(httpd_req_t *req)
{
    midi_player_pause();
    return httpd_resp_sendstr(req, "Paused");
}

static esp_err_t stop_get_handler(httpd_req_t *req)
{
    midi_player_stop();
    return httpd_resp_sendstr(req, "Stopped");
}

static void ota_auto_task(void *arg)
{
    while (1) {
        esp_http_client_config_t config = {
            .url = UPDATE_URL,
            .cert_pem = (const char *)certs_server_cert_pem_start,
        };
        esp_http_client_handle_t client = esp_http_client_init(&config);
        if (client && esp_http_client_open(client, 0) == ESP_OK) {
            const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
            esp_ota_handle_t update_handle = 0;
            esp_err_t err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &update_handle);
            if (err == ESP_OK) {
                bool header_checked = false;
                esp_app_desc_t new_app_info;
                const esp_app_desc_t *running_app_info = esp_app_get_description();
                char buf[1024];
                int data_read;
                while ((data_read = esp_http_client_read(client, buf, sizeof(buf))) > 0) {
                    if (!header_checked) {
                        if (data_read > sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t)) {
                            memcpy(&new_app_info, buf + sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t), sizeof(esp_app_desc_t));
                            if (!memcmp(new_app_info.version, running_app_info->version, sizeof(new_app_info.version))) {
                                ESP_LOGI(TAG, "Firmware up to date");
                                esp_ota_abort(update_handle);
                                break;
                            }
                            header_checked = true;
                        }
                    }
                    err = esp_ota_write(update_handle, buf, data_read);
                    if (err != ESP_OK)
                        break;
                }
                if (header_checked && err == ESP_OK && esp_ota_end(update_handle) == ESP_OK) {
                    if (esp_ota_set_boot_partition(update_partition) == ESP_OK) {
                        ESP_LOGI(TAG, "OTA update applied, rebooting");
                        esp_restart();
                    }
                } else {
                    esp_ota_abort(update_handle);
                    ESP_LOGE(TAG, "OTA update failed");
                    esp_ota_mark_app_invalid_rollback_and_reboot();
                }
            }
        }
        if (client) {
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
        }
        vTaskDelay(pdMS_TO_TICKS(OTA_CHECK_INTERVAL_MS));
    }
}

static StackType_t ota_task_stack[8192];
static StaticTask_t ota_task_tcb;
static httpd_handle_t start_https_server(void)
{
    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();

    struct stat st_cert, st_key;
    if (stat("/spiffs/server_cert.pem", &st_cert) == 0 &&
        stat("/spiffs/server_key.pem", &st_key) == 0 &&
        st_cert.st_size + 1 < CERT_BUF_SIZE && st_key.st_size + 1 < CERT_BUF_SIZE) {
        FILE *f = fopen("/spiffs/server_cert.pem", "r");
        fread(loaded_cert, 1, st_cert.st_size, f);
        loaded_cert[st_cert.st_size] = '\0';
        fclose(f);
        loaded_cert_len = st_cert.st_size + 1;

        f = fopen("/spiffs/server_key.pem", "r");
        fread(loaded_key, 1, st_key.st_size, f);
        loaded_key[st_key.st_size] = '\0';
        fclose(f);
        loaded_key_len = st_key.st_size + 1;

        conf.cacert_pem = (const uint8_t *)loaded_cert;
        conf.cacert_len = loaded_cert_len;
        conf.prvtkey_pem = (const uint8_t *)loaded_key;
        conf.prvtkey_len = loaded_key_len;
    } else {
        conf.cacert_pem = certs_server_cert_pem_start;
        conf.cacert_len = certs_server_cert_pem_end - certs_server_cert_pem_start;
        conf.prvtkey_pem = certs_server_key_pem_start;
        conf.prvtkey_len = certs_server_key_pem_end - certs_server_key_pem_start;
    }

    httpd_handle_t server = NULL;
    if (httpd_ssl_start(&server, &conf) == ESP_OK) {
        httpd_uri_t root = {
            .uri = "/",
            .method = HTTP_GET,
            .handler = root_get_handler,
        };
        httpd_uri_t config_post = {
            .uri = "/config",
            .method = HTTP_POST,
            .handler = config_post_handler,
        };
        httpd_uri_t upload_post = {
            .uri = "/upload",
            .method = HTTP_POST,
            .handler = upload_post_handler,
        };
        httpd_uri_t ota_post = {
            .uri = "/ota",
            .method = HTTP_POST,
            .handler = ota_post_handler,
        };
          httpd_uri_t track_get = {
              .uri = "/track",
              .method = HTTP_GET,
              .handler = track_get_handler,
          };
          httpd_uri_t play_get = {
              .uri = "/play",
              .method = HTTP_GET,
              .handler = play_get_handler,
          };
          httpd_uri_t pause_get = {
              .uri = "/pause",
              .method = HTTP_GET,
              .handler = pause_get_handler,
          };
          httpd_uri_t stop_get = {
              .uri = "/stop",
              .method = HTTP_GET,
              .handler = stop_get_handler,
          };
        httpd_uri_t midi_post = {
            .uri = "/midi",
            .method = HTTP_POST,
            .handler = midi_post_handler,
        };
        httpd_uri_t ws = {
            .uri = "/ws",
            .method = HTTP_GET,
            .handler = ws_handler,
            .is_websocket = true,
        };
        httpd_register_uri_handler(server, &root);
        httpd_register_uri_handler(server, &config_post);
        httpd_register_uri_handler(server, &upload_post);
        httpd_register_uri_handler(server, &ota_post);
          httpd_register_uri_handler(server, &track_get);
          httpd_register_uri_handler(server, &play_get);
          httpd_register_uri_handler(server, &pause_get);
          httpd_register_uri_handler(server, &stop_get);
        httpd_register_uri_handler(server, &midi_post);
        httpd_register_uri_handler(server, &ws);
        ESP_LOGI(TAG, "HTTPS server started");
    } else {
        ESP_LOGE(TAG, "Failed to start HTTPS server");
    }
    return server;
}

static void wifi_init_softap(void)
{
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t wifi_config = {
        .ap = {
            .ssid = "ESP32_MIDI",
            .ssid_len = strlen("ESP32_MIDI"),
            .channel = 1,
            .password = "password",
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK,
        },
    };
    if (strlen((char *)wifi_config.ap.password) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &wifi_config);
    esp_wifi_start();
    ESP_LOGI(TAG, "SoftAP started. Connect to SSID ESP32_MIDI");
}

static void wifi_init_sta(const char *ssid, const char *pass)
{
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t wifi_config = { 0 };
    strncpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
    strncpy((char *)wifi_config.sta.password, pass, sizeof(wifi_config.sta.password));

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_start();
    ESP_LOGI(TAG, "WiFi STA start: %s", ssid);
}

static void init_spiffs(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = "storage",
        .max_files = 5,
        .format_if_mount_failed = true
    };
    ESP_ERROR_CHECK(esp_vfs_spiffs_register(&conf));
}

void app_main(void)
{
    ESP_LOGI(TAG, "ESP32 MIDI project initialized");

    esp_ota_mark_app_valid_cancel_rollback();

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    init_spiffs();
    midi_player_init();

    char ssid[32] = {0};
    char pass[64] = {0};
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("wifi", NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        size_t len = sizeof(ssid);
        err = nvs_get_str(nvs, "ssid", ssid, &len);
        len = sizeof(pass);
        if (err == ESP_OK) {
            err = nvs_get_str(nvs, "pass", pass, &len);
        }
        nvs_close(nvs);
    }

    if (err == ESP_OK && strlen(ssid) > 0) {
        wifi_init_sta(ssid, pass);
    } else {
        wifi_init_softap();
    }

    start_https_server();
    xTaskCreateStatic(udp_server_task, "udp_server", 4096, NULL, 5, udp_task_stack, &udp_task_tcb);
    xTaskCreateStatic(ota_auto_task, "ota_auto", 8192, NULL, 5, ota_task_stack, &ota_task_tcb);
}

