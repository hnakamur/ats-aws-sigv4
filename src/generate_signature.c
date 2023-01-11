#include <assert.h>
#include <openssl/evp.h>

#include "generate_signature.h"
#include "sigv4.h"

/**
 * @brief AWS Service name to send HTTP request using SigV4 library.
 */
#define AWS_S3_SERVICE_NAME "s3"

/**
 * @brief Represents empty payload for HTTP GET request sent to AWS S3.
 */
#define S3_REQUEST_EMPTY_PAYLOAD ""

/**
 * @brief Length in bytes of hex encoded hash digest.
 */
#define HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH ((uint16_t)64)

/**
 * @brief Length in bytes of SHA256 hash digest.
 */
#define SHA256_HASH_DIGEST_LENGTH (HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH / 2)

/**
 * @brief Length of AWS HTTP Authorization header value generated using SigV4
 * library.
 */
#define AWS_HTTP_AUTH_HEADER_VALUE_LEN 2048U

typedef struct {
    EVP_MD_CTX *mdctx;
} sha256_ctx_t;

static int32_t sha256Init(void *hashContext)
{
    sha256_ctx_t *ctx = (sha256_ctx_t *)hashContext;
    ctx->mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    return (int32_t)EVP_DigestInit(ctx->mdctx, md);
}

static int32_t sha256Update(void *hashContext, const uint8_t *pInput,
                            size_t inputLen)
{
    sha256_ctx_t *ctx = (sha256_ctx_t *)hashContext;
    return (int32_t)EVP_DigestUpdate(ctx->mdctx, pInput, inputLen);
}

static int32_t sha256Final(void *hashContext, uint8_t *pOutput,
                           size_t outputLen)
{
    assert(outputLen >= SHA256_HASH_DIGEST_LENGTH);

    (void)outputLen;

    sha256_ctx_t *ctx = (sha256_ctx_t *)hashContext;
    int rc = EVP_DigestFinal_ex(ctx->mdctx, pOutput, NULL);
    EVP_MD_CTX_free(ctx->mdctx);
    return (int32_t)rc;
}

int generate_signature(generate_signature_params_t *param)
{
    SigV4Credentials_t sigvCreds = {
        .pAccessKeyId = param->access_key_id,
        .accessKeyIdLen = param->access_key_id_len,
        .pSecretAccessKey = param->secret_access_key,
        .secretAccessKeyLen = param->secret_access_key_len,
    };

    sha256_ctx_t hashContext;
    SigV4CryptoInterface_t cryptoInterface = {
        .hashInit = sha256Init,
        .hashUpdate = sha256Update,
        .hashFinal = sha256Final,
        .pHashContext = &hashContext,
        .hashBlockLen = HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH,
        .hashDigestLen = SHA256_HASH_DIGEST_LENGTH,
    };

    /* Setup the HTTP parameters. */
    SigV4HttpParameters_t sigv4HttpParams = {
        .pHttpMethod = param->method,
        .httpMethodLen = param->method_len,
        /* None of the requests parameters below are pre-canonicalized */
        .flags = 0,
        .pPath = param->url_path,
        .pathLen = param->url_path_len,
        /* AWS S3 request does not require any Query parameters. */
        .pQuery = NULL,
        .queryLen = 0,
        .pHeaders = param->headers,
        .headersLen = param->headers_len,
        .pPayload = S3_REQUEST_EMPTY_PAYLOAD,
        .payloadLen = sizeof(S3_REQUEST_EMPTY_PAYLOAD) - 1,
    };

    SigV4Parameters_t sigv4Params = {
        .pCredentials = &sigvCreds,
        .pDateIso8601 = param->data_iso8601,
        .pRegion = param->region,
        .regionLen = param->region_len,
        .pService = AWS_S3_SERVICE_NAME,
        .serviceLen = sizeof(AWS_S3_SERVICE_NAME) - 1,
        .pCryptoInterface = &cryptoInterface,
        .pHttpParameters = &sigv4HttpParams,
    };

    SigV4Status_t sigv4Status = SigV4_GenerateHTTPAuthorization(
        &sigv4Params, param->auth_buf, &param->auth_buf_len, &param->signature,
        &param->signature_len);
    return sigv4Status == SigV4Success;
}
