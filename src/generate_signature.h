#ifndef GENERATE_SIGNATURE_H_
#define GENERATE_SIGNATURE_H_

#include <stddef.h>

typedef struct {
    /* input parameters */

    const char *access_key_id;
    size_t access_key_id_len;

    const char *secret_access_key;
    size_t secret_access_key_len;

    const char *data_iso8601; /* YYYYMMDD */

    const char *region;
    size_t region_len;

    const char *method;
    size_t method_len;

    const char *url_path;
    size_t url_path_len;

    const char *headers;
    size_t headers_len;

    /* output parameters */

    char *auth_buf; /* caller must provide memory. */
    size_t auth_buf_len;

    char *signature; /* points to somewhere in auth_buf. */
    size_t signature_len;

} generate_signature_params_t;

int generate_signature(generate_signature_params_t *param);

#endif /* ifndef GENERATE_SIGNATURE_H_ */