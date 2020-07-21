#include <sodium.h>

#include "common-sodium.h"
#include "logging.h"
#include "protocol.h"

void log_bin2hex_sodium(enum log_priority log_prio,
                        char const * const prefix,
                        uint8_t const * const buffer,
                        size_t size)
{
    char hexstr[2 * size + 1];

    if (log_prio >= lower_prio) {
        LOG(log_prio, "%s: %s", prefix, sodium_bin2hex(hexstr, sizeof(hexstr), buffer, size));
        sodium_memzero(hexstr, sizeof(hexstr));
    }
}

struct longterm_keypair * generate_keypair_sodium(void)
{
    struct longterm_keypair * keypair = (struct longterm_keypair *)malloc(sizeof(*keypair));

    if (keypair == NULL) {
        return NULL;
    }

    sodium_memzero(keypair->publickey, crypto_kx_PUBLICKEYBYTES);
    sodium_memzero(keypair->secretkey, crypto_kx_SECRETKEYBYTES);
    crypto_kx_keypair(keypair->publickey, keypair->secretkey);
    sodium_mlock(keypair, sizeof(*keypair));

    return keypair;
}

struct longterm_keypair * generate_keypair_from_secretkey_hexstr_sodium(char const * const secretkey_hexstr,
                                                                        size_t secretkey_hexstr_len)
{
    struct longterm_keypair * keypair = (struct longterm_keypair *)malloc(sizeof(*keypair));

    if (keypair == NULL) {
        return NULL;
    }

    if (sodium_hex2bin(
            keypair->secretkey, sizeof(keypair->secretkey), secretkey_hexstr, secretkey_hexstr_len, NULL, NULL, NULL) !=
        0) {
        LOG(ERROR, "Could not parse private key: %s", secretkey_hexstr);
        goto error;
    }

    if (crypto_scalarmult_base(keypair->publickey, keypair->secretkey) != 0) {
        LOG(ERROR, "Could not extract public key from a secret key");
        goto error;
    }

    sodium_mlock(keypair, sizeof(*keypair));

    return keypair;
error:
    free(keypair);
    return NULL;
}

int generate_session_keypair_sodium(struct connection * const state)
{
    if (state->session_keys != NULL) {
        LOG(ERROR, "Session initialization invoked twice, abort");
        return 1;
    }

    state->session_keys = (struct session_keys *)malloc(sizeof(*(state->session_keys)));
    if (state->session_keys == NULL) {
        return 1;
    }

    if (state->is_server_side != 0 && crypto_kx_server_session_keys(state->session_keys->rx,
                                                                    state->session_keys->tx,
                                                                    state->my_keypair->publickey,
                                                                    state->my_keypair->secretkey,
                                                                    state->peer_publickey) != 0) {
        LOG(ERROR, "Session key creation failed");
        return 1;
    } else if (state->is_server_side == 0 && crypto_kx_client_session_keys(state->session_keys->rx,
                                                                           state->session_keys->tx,
                                                                           state->my_keypair->publickey,
                                                                           state->my_keypair->secretkey,
                                                                           state->peer_publickey) != 0) {
        LOG(ERROR, "Session key creation failed");
        return 1;
    }

    log_bin2hex_sodium(NOTICE, "Generated session rx key", state->session_keys->rx, crypto_kx_SESSIONKEYBYTES);
    log_bin2hex_sodium(NOTICE, "Generated session tx key", state->session_keys->tx, crypto_kx_SESSIONKEYBYTES);

    return 0;
}

int init_crypto_server(struct connection * const state,
                       unsigned char const * const server_rx_header,
                       size_t server_rx_header_size)
{
    if (server_rx_header_size != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        LOG(ERROR,
            "Invalid Sodium RX header size: %zu != %zu",
            server_rx_header_size,
            crypto_secretstream_xchacha20poly1305_HEADERBYTES);
        return 1;
    }
    if (generate_session_keypair_sodium(state) != 0) {
        LOG(ERROR, "Client session keypair generation failed");
        return 1;
    }
    crypto_secretstream_xchacha20poly1305_init_pull(&state->crypto_rx_state, server_rx_header, state->session_keys->rx);

    return 0;
}

int init_crypto_client(struct connection * const state,
                       unsigned char const * const client_rx_header,
                       size_t client_rx_header_size)
{
    if (client_rx_header_size != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        LOG(ERROR,
            "Invalid Sodium RX header size: %zu != %zu",
            client_rx_header_size,
            crypto_secretstream_xchacha20poly1305_HEADERBYTES);
        return 1;
    }
    crypto_secretstream_xchacha20poly1305_init_pull(&state->crypto_rx_state, client_rx_header, state->session_keys->rx);

    return 0;
}
