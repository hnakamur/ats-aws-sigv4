#ifndef GENERATE_AWS_SIGV4_H_
#define GENERATE_AWS_SIGV4_H_

#include <stddef.h>

typedef struct {
    /* input parameters */

    const char *access_key_id;
    size_t access_key_id_len;

    const char *secret_access_key;
    size_t secret_access_key_len;

    const char *region;
    size_t region_len;

    const char *date_iso8601; /* YYYYMMDD */

    const char *method;
    size_t method_len;

    const char *url_path;
    size_t url_path_len;

    const char *headers;
    size_t headers_len;

    /* output parameters */

    char *auth_buf; /* caller must provide memory (ex. 2048 bytes). */
    size_t auth_buf_len;

    char *signature; /* points to somewhere in auth_buf. */
    size_t signature_len;

} generate_aws_sigv4_params_t;

int generate_aws_sigv4(generate_aws_sigv4_params_t *param);

#endif /* ifndef GENERATE_AWS_SIGV4_H_ */
