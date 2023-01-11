#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
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

/**
 * @brief Application-defined Hash Initialization function provided
 * to the SigV4 library.
 *
 * @note Refer to SigV4CryptoInterface_t interface documentation for this
 * function.
 */
static int32_t sha256Init(void *hashContext);

/**
 * @brief Application-defined Hash Update function provided to the SigV4
 * library.
 *
 * @note Refer to SigV4CryptoInterface_t interface documentation for this
 * function.
 */
static int32_t sha256Update(void *hashContext, const uint8_t *pInput,
                            size_t inputLen);

/**
 * @brief Application-defined Hash Final function provided to the SigV4 library.
 *
 * @note Refer to SigV4CryptoInterface_t interface documentation for this
 * function.
 */
static int32_t sha256Final(void *hashContext, uint8_t *pOutput,
                           size_t outputLen);

/**
 * @brief Represents Length of Authorization header value generated using SigV4
 * library.
 */
static size_t sigv4AuthLen = AWS_HTTP_AUTH_HEADER_VALUE_LEN;

void f(const char *region, size_t region_len, const char *method,
       size_t method_len, const char *url_path, size_t url_path_len,
       const char *headers, size_t headers_len)
{
    SigV4Status_t sigv4Status = SigV4Success;
    SigV4HttpParameters_t sigv4HttpParams;

    /* Store Signature used in AWS HTTP requests generated using SigV4 library.
     */
    char *signature = NULL;
    size_t signatureLen = 0;

    SigV4Credentials_t sigvCreds = {0};
    char pDateISO8601[SIGV4_ISO_STRING_LEN] = {0};
    char pSigv4Auth[AWS_HTTP_AUTH_HEADER_VALUE_LEN];

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    SigV4CryptoInterface_t cryptoInterface = {
        .hashInit = sha256Init,
        .hashUpdate = sha256Update,
        .hashFinal = sha256Final,
        .pHashContext = mdctx,
        .hashBlockLen = HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH,
        .hashDigestLen = SHA256_HASH_DIGEST_LENGTH,
    };

    SigV4Parameters_t sigv4Params = {.pCredentials = &sigvCreds,
                                     .pDateIso8601 = pDateISO8601,
                                     .pRegion = region,
                                     .regionLen = region_len,
                                     .pService = AWS_S3_SERVICE_NAME,
                                     .serviceLen =
                                         sizeof(AWS_S3_SERVICE_NAME) - 1,
                                     .pCryptoInterface = &cryptoInterface,
                                     .pHttpParameters = NULL};

    /* Setup the HTTP parameters. */
    sigv4HttpParams.pHttpMethod = method;
    sigv4HttpParams.httpMethodLen = method_len;
    /* None of the requests parameters below are pre-canonicalized */
    sigv4HttpParams.flags = 0;
    sigv4HttpParams.pPath = url_path;
    sigv4HttpParams.pathLen = url_path_len;
    /* AWS S3 request does not require any Query parameters. */
    sigv4HttpParams.pQuery = NULL;
    sigv4HttpParams.queryLen = 0;
    sigv4HttpParams.pHeaders = headers;
    sigv4HttpParams.headersLen = headers_len;
    sigv4HttpParams.pPayload = S3_REQUEST_EMPTY_PAYLOAD;
    sigv4HttpParams.payloadLen = strlen(S3_REQUEST_EMPTY_PAYLOAD);

    /* Initializing sigv4Params with Http parameters required for the HTTP
     * request. */
    sigv4Params.pHttpParameters = &sigv4HttpParams;

    /* Generate HTTP Authorization header using SigV4_GenerateHTTPAuthorization
     * API. */
    sigv4Status = SigV4_GenerateHTTPAuthorization(
        &sigv4Params, pSigv4Auth, &sigv4AuthLen, &signature, &signatureLen);

    EVP_MD_CTX_free(mdctx);

    if (sigv4Status != SigV4Success) {
        fprintf(stderr, "Failed to generate HTTP AUTHORIZATION Header.\n");
    }
}

/*-----------------------------------------------------------*/

static int32_t sha256Init(void *hashContext)
{
    EVP_MD_CTX *mdctx = (EVP_MD_CTX *)hashContext;
    const EVP_MD *md = EVP_sha256();
    return (int32_t)EVP_DigestInit(mdctx, md);
}

/*-----------------------------------------------------------*/

static int32_t sha256Update(void *hashContext, const uint8_t *pInput,
                            size_t inputLen)
{
    EVP_MD_CTX *mdctx = (EVP_MD_CTX *)hashContext;
    return (int32_t)EVP_DigestUpdate(mdctx, pInput, inputLen);
}

/*-----------------------------------------------------------*/

static int32_t sha256Final(void *hashContext, uint8_t *pOutput,
                           size_t outputLen)
{
    assert(outputLen >= SHA256_HASH_DIGEST_LENGTH);

    (void)outputLen;

    EVP_MD_CTX *mdctx = (EVP_MD_CTX *)hashContext;
    return (int32_t)EVP_DigestFinal_ex(mdctx, pOutput, NULL);
}
