idf_component_register(SRCS "main.c" "midi_player.c" INCLUDE_DIRS "." EMBED_TXTFILES "certs/server_cert.pem" "certs/server_key.pem" REQUIRES esp_http_client)
