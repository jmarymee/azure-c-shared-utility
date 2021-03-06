// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include "wolfssl/ssl.h"
#include "wolfssl/error-ssl.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/tlsio_wolfssl.h"
#include "azure_c_shared_utility/socketio.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/shared_util_options.h"


typedef enum TLSIO_STATE_ENUM_TAG
{
    TLSIO_STATE_NOT_OPEN,
    TLSIO_STATE_OPENING_UNDERLYING_IO,
    TLSIO_STATE_IN_HANDSHAKE,
    TLSIO_STATE_OPEN,
    TLSIO_STATE_CLOSING,
    TLSIO_STATE_ERROR
} TLSIO_STATE_ENUM;

typedef struct TLS_IO_INSTANCE_TAG
{
    XIO_HANDLE socket_io;
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_OPEN_COMPLETE on_io_open_complete;
    ON_IO_CLOSE_COMPLETE on_io_close_complete;
    ON_IO_ERROR on_io_error;
    void* on_bytes_received_context;
    void* on_io_open_complete_context;
    void* on_io_close_complete_context;
    void* on_io_error_context;
    WOLFSSL* ssl;
    WOLFSSL_CTX* ssl_context;
    TLSIO_STATE_ENUM tlsio_state;
    unsigned char* socket_io_read_bytes;
    size_t socket_io_read_byte_count;
    ON_SEND_COMPLETE on_send_complete;
    void* on_send_complete_callback_context;
    char* certificate;
    char* x509certificate;
    char* x509privatekey;
    char* hostname;
    int port;
} TLS_IO_INSTANCE;

/*this function will clone an option given by name and value*/
static void* tlsio_wolfssl_CloneOption(const char* name, const void* value)
{
    void* result;
    if ((name == NULL) || (value == NULL))
    {
        LogError("invalid parameter detected: const char* name=%p, const void* value=%p", name, value);
        result = NULL;
    }
    else
    {
        if (strcmp(name, "TrustedCerts") == 0)
        {
            if (mallocAndStrcpy_s((char**)&result, value) != 0)
            {
                LogError("unable to mallocAndStrcpy_s TrustedCerts value");
                result = NULL;
            }
            else
            {
                /*return as is*/
            }
        }
        else if (strcmp(name, SU_OPTION_X509_CERT) == 0)
        {
            if (mallocAndStrcpy_s((char**)&result, value) != 0)
            {
                LogError("unable to mallocAndStrcpy_s x509certificate value");
                result = NULL;
            }
            else
            {
                /*return as is*/
            }
        }
        else if (strcmp(name, SU_OPTION_X509_PRIVATE_KEY) == 0)
        {
            if (mallocAndStrcpy_s((char**)&result, value) != 0)
            {
                LogError("unable to mallocAndStrcpy_s x509privatekey value");
                result = NULL;
            }
            else
            {
                /*return as is*/
            }
        }
        else
        {
            LogError("not handled option : %s", name);
            result = NULL;
        }
    }
    return result;
}

/*this function destroys an option previously created*/
static void tlsio_wolfssl_DestroyOption(const char* name, const void* value)
{
    /*since all options for this layer are actually string copies., disposing of one is just calling free*/
    if ((name == NULL) || (value == NULL))
    {
        LogError("invalid parameter detected: const char* name=%p, const void* value=%p", name, value);
    }
    else
    {
        if ((strcmp(name, "TrustedCerts") == 0) ||
            (strcmp(name, SU_OPTION_X509_CERT) == 0) ||
            (strcmp(name, SU_OPTION_X509_PRIVATE_KEY) == 0))
        {
            free((void*)value);
        }
        else
        {
            LogError("not handled option : %s", name);
        }
    }
}

static OPTIONHANDLER_HANDLE tlsio_wolfssl_retrieveoptions(CONCRETE_IO_HANDLE tls_io)
{
    OPTIONHANDLER_HANDLE result;
    (void)tls_io;

    result = OptionHandler_Create(tlsio_wolfssl_CloneOption, tlsio_wolfssl_DestroyOption, tlsio_wolfssl_setoption);
    if (result == NULL)
    {
        /*return as is*/
    }
    else
    {
        /*insert here work to add the options to "result" handle*/
    }
    return result;
}

static const IO_INTERFACE_DESCRIPTION tlsio_wolfssl_interface_description =
{
    tlsio_wolfssl_retrieveoptions,
    tlsio_wolfssl_create,
    tlsio_wolfssl_destroy,
    tlsio_wolfssl_open,
    tlsio_wolfssl_close,
    tlsio_wolfssl_send,
    tlsio_wolfssl_dowork,
    tlsio_wolfssl_setoption
};

static void indicate_error(TLS_IO_INSTANCE* tls_io_instance)
{
    if (tls_io_instance->on_io_error != NULL)
    {
        tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
    }
}

static void indicate_open_complete(TLS_IO_INSTANCE* tls_io_instance, IO_OPEN_RESULT open_result)
{
    if (tls_io_instance->on_io_open_complete != NULL)
    {
        tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, open_result);
    }
}

static int decode_ssl_received_bytes(TLS_IO_INSTANCE* tls_io_instance)
{
    int result = 0;
    unsigned char buffer[64];

    int rcv_bytes = 1;
    while (rcv_bytes > 0)
    {
        rcv_bytes = wolfSSL_read(tls_io_instance->ssl, buffer, sizeof(buffer));
        if (rcv_bytes > 0)
        {
            if (tls_io_instance->on_bytes_received != NULL)
            {
                tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, buffer, rcv_bytes);
            }
        }
    }

    return result;
}

static void on_underlying_io_open_complete(void* context, IO_OPEN_RESULT open_result)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    if (open_result != IO_OPEN_OK)
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        indicate_open_complete(tls_io_instance, IO_OPEN_ERROR);
    }
    else
    {
        int res;
        tls_io_instance->tlsio_state = TLSIO_STATE_IN_HANDSHAKE;

        res = wolfSSL_connect(tls_io_instance->ssl);
        if (res != SSL_SUCCESS)
        {
            indicate_open_complete(tls_io_instance, IO_OPEN_ERROR);
            tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        }
    }
}

static void on_underlying_io_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    unsigned char* new_socket_io_read_bytes = (unsigned char*)realloc(tls_io_instance->socket_io_read_bytes, tls_io_instance->socket_io_read_byte_count + size);
    if (new_socket_io_read_bytes == NULL)
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        indicate_error(tls_io_instance);
    }
    else
    {
        tls_io_instance->socket_io_read_bytes = new_socket_io_read_bytes;
        (void)memcpy(tls_io_instance->socket_io_read_bytes + tls_io_instance->socket_io_read_byte_count, buffer, size);
        tls_io_instance->socket_io_read_byte_count += size;
    }
}

static void on_underlying_io_error(void* context)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    switch (tls_io_instance->tlsio_state)
    {
    default:
    case TLSIO_STATE_NOT_OPEN:
    case TLSIO_STATE_ERROR:
        break;

    case TLSIO_STATE_OPENING_UNDERLYING_IO:
    case TLSIO_STATE_IN_HANDSHAKE:
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        indicate_open_complete(tls_io_instance, IO_OPEN_ERROR);
        break;

    case TLSIO_STATE_OPEN:
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        indicate_error(tls_io_instance);
        break;
    }
}

static void on_underlying_io_close_complete(void* context)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    if (tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING)
    {
        if (tls_io_instance->on_io_close_complete != NULL)
        {
            tls_io_instance->on_io_close_complete(tls_io_instance->on_io_close_complete_context);
        }
        tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
    }
}

static int on_io_recv(WOLFSSL *ssl, char *buf, int sz, void *context)
{
    int result;
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;
    unsigned char* new_socket_io_read_bytes;

    (void)ssl;
    while (tls_io_instance->socket_io_read_byte_count == 0)
    {
        xio_dowork(tls_io_instance->socket_io);
        if (tls_io_instance->tlsio_state != TLSIO_STATE_IN_HANDSHAKE)
        {
            break;
        }
    }

    result = tls_io_instance->socket_io_read_byte_count;
    if (result > sz)
    {
        result = sz;
    }

    if (result > 0)
    {
        (void)memcpy(buf, tls_io_instance->socket_io_read_bytes, result);
        (void)memmove(tls_io_instance->socket_io_read_bytes, tls_io_instance->socket_io_read_bytes + result, tls_io_instance->socket_io_read_byte_count - result);
        tls_io_instance->socket_io_read_byte_count -= result;
        if (tls_io_instance->socket_io_read_byte_count > 0)
        {
            new_socket_io_read_bytes = (unsigned char*)realloc(tls_io_instance->socket_io_read_bytes, tls_io_instance->socket_io_read_byte_count);
            if (new_socket_io_read_bytes != NULL)
            {
                tls_io_instance->socket_io_read_bytes = new_socket_io_read_bytes;
            }
        }
        else
        {
            free(tls_io_instance->socket_io_read_bytes);
            tls_io_instance->socket_io_read_bytes = NULL;
        }
    }

    if ((result == 0) && (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN))
    {
        result = WOLFSSL_CBIO_ERR_WANT_READ;
    }
    else if ((result == 0) && tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING)
    {
        result = WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

    return result;
}

static int on_io_send(WOLFSSL *ssl, char *buf, int sz, void *context)
{
    int result;
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    (void)ssl;
    if (xio_send(tls_io_instance->socket_io, buf, sz, tls_io_instance->on_send_complete, tls_io_instance->on_send_complete_callback_context) != 0)
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        indicate_error(tls_io_instance);
        result = 0;
    }
    else
    {
        result = sz;
    }

    return result;
}

static int on_handshake_done(WOLFSSL* ssl, void* context)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;
    (void)ssl;
    if (tls_io_instance->tlsio_state == TLSIO_STATE_IN_HANDSHAKE)
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
        indicate_open_complete(tls_io_instance, IO_OPEN_OK);
    }

    return 0;
}

static int add_certificate_to_store(TLS_IO_INSTANCE* tls_io_instance)
{
    int result;
    if (tls_io_instance->certificate != NULL)
    {
        int res = wolfSSL_CTX_load_verify_buffer(tls_io_instance->ssl_context, (const unsigned char*)tls_io_instance->certificate, strlen(tls_io_instance->certificate) + 1, SSL_FILETYPE_PEM);
        if (res != SSL_SUCCESS)
        {
            result = __LINE__;
        }
        else
        {
            result = 0;
        }
    }
    else
    {
        result = 0;
    }
    return result;
}

static int x509_wolfssl_add_credentials(WOLFSSL* ssl, char* x509certificate, char* x509privatekey) {

    int result;

    if (wolfSSL_use_certificate_buffer(ssl, (unsigned char*)x509certificate, strlen(x509certificate) + 1, SSL_FILETYPE_PEM) != SSL_SUCCESS)
    {
        LogError("unable to load x509 client certificate");
        result = __LINE__;
    }
    else if (wolfSSL_use_PrivateKey_buffer(ssl, (unsigned char*)x509privatekey, strlen(x509privatekey) + 1, SSL_FILETYPE_PEM) != SSL_SUCCESS)
    {
        LogError("unable to load x509 client private key");
        result = __LINE__;
    }
#ifdef HAVE_SECURE_RENEGOTIATION
    else if (wolfSSL_UseSecureRenegotiation(ssl) != SSL_SUCCESS) {
        LogError("unable to enable secure renegotiation");
        result = __LINE__;
    }
#endif 
    else
    {
        result = 0;
    }
    return result;
}

static void destroy_wolfssl_instance(TLS_IO_INSTANCE* tls_io_instance)
{
    wolfSSL_free(tls_io_instance->ssl);
}

static int create_wolfssl_instance(TLS_IO_INSTANCE* tls_io_instance)
{
    int result;

    if (add_certificate_to_store(tls_io_instance) != 0)
    {
        wolfSSL_CTX_free(tls_io_instance->ssl_context);
        result = __LINE__;
    }
    else
    {
        tls_io_instance->ssl = wolfSSL_new(tls_io_instance->ssl_context);
        if (tls_io_instance->ssl == NULL)
        {
            wolfSSL_CTX_free(tls_io_instance->ssl_context);
            result = __LINE__;
        }
        /*x509 authentication can only be build before underlying connection is realized*/
        else if ((tls_io_instance->x509certificate != NULL) &&
            (tls_io_instance->x509privatekey != NULL) &&
            (x509_wolfssl_add_credentials(tls_io_instance->ssl, tls_io_instance->x509certificate, tls_io_instance->x509privatekey) != 0))
        {
            destroy_wolfssl_instance(tls_io_instance);
            tls_io_instance->ssl = NULL;
            wolfSSL_CTX_free(tls_io_instance->ssl_context);
            tls_io_instance->ssl_context = NULL;
            LogError("unable to use x509 authentication");
            result = __LINE__;
        }

        else
        {
            tls_io_instance->socket_io_read_bytes = NULL;
            tls_io_instance->socket_io_read_byte_count = 0;
            tls_io_instance->on_send_complete = NULL;
            tls_io_instance->on_send_complete_callback_context = NULL;

            wolfSSL_set_using_nonblock(tls_io_instance->ssl, 1);
            wolfSSL_SetIOSend(tls_io_instance->ssl_context, on_io_send);
            wolfSSL_SetIORecv(tls_io_instance->ssl_context, on_io_recv);
            wolfSSL_SetHsDoneCb(tls_io_instance->ssl, on_handshake_done, tls_io_instance);
            wolfSSL_SetIOWriteCtx(tls_io_instance->ssl, tls_io_instance);
            wolfSSL_SetIOReadCtx(tls_io_instance->ssl, tls_io_instance);

            tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
            result = 0;
        }
    }
    return result;
}

int tlsio_wolfssl_init(void)
{
    (void)wolfSSL_library_init();
    wolfSSL_load_error_strings();

    return 0;
}

void tlsio_wolfssl_deinit(void)
{
}

CONCRETE_IO_HANDLE tlsio_wolfssl_create(void* io_create_parameters)
{
    TLSIO_CONFIG* tls_io_config = io_create_parameters;
    TLS_IO_INSTANCE* result;

    if (tls_io_config == NULL)
    {
        result = NULL;
    }
    else
    {
        result = (TLS_IO_INSTANCE*)malloc(sizeof(TLS_IO_INSTANCE));
        if (result != NULL)
        {
            memset(result, 0, sizeof(TLS_IO_INSTANCE));
            mallocAndStrcpy_s(&result->hostname, tls_io_config->hostname);
            result->port = tls_io_config->port;

            result->socket_io_read_bytes = 0;
            result->socket_io_read_byte_count = 0;
            result->socket_io = NULL;

            result->ssl = NULL;
            result->ssl_context = NULL;
            result->certificate = NULL;
            result->x509certificate = NULL;
            result->x509privatekey = NULL;

            result->on_bytes_received = NULL;
            result->on_bytes_received_context = NULL;

            result->on_io_open_complete = NULL;
            result->on_io_open_complete_context = NULL;

            result->on_io_close_complete = NULL;
            result->on_io_close_complete_context = NULL;

            result->on_io_error = NULL;
            result->on_io_error_context = NULL;

            result->tlsio_state = TLSIO_STATE_NOT_OPEN;

            result->ssl_context = wolfSSL_CTX_new(wolfTLSv1_client_method());
            if (result->ssl_context == NULL)
            {
                free(result);
                result = NULL;
            }
            else
            {
                const IO_INTERFACE_DESCRIPTION* socket_io_interface = socketio_get_interface_description();
                if (socket_io_interface == NULL)
                {
                    wolfSSL_CTX_free(result->ssl_context);
                    free(result);
                    result = NULL;
                }
                else
                {
                    SOCKETIO_CONFIG socketio_config;
                    socketio_config.hostname = result->hostname;
                    socketio_config.port = result->port;
                    socketio_config.accepted_socket = NULL;

                    result->socket_io = xio_create(socket_io_interface, &socketio_config);
                    if (result->socket_io == NULL)
                    {
                        LogError("Failure connecting to underlying socket_io");
                        wolfSSL_CTX_free(result->ssl_context);
                        free(result);
                        result = NULL;
                    }
                }
            }


        }
    }

    return result;
}

void tlsio_wolfssl_destroy(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io != NULL)
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
        if (tls_io_instance->socket_io_read_bytes != NULL)
        {
            free(tls_io_instance->socket_io_read_bytes);
        }

        if (tls_io_instance->certificate != NULL)
        {
            free(tls_io_instance->certificate);
            tls_io_instance->certificate = NULL;
        }
        if (tls_io_instance->x509certificate != NULL)
        {
            free(tls_io_instance->x509certificate);
            tls_io_instance->x509certificate = NULL;
        }
        if (tls_io_instance->x509privatekey != NULL)
        {
            free(tls_io_instance->x509privatekey);
            tls_io_instance->x509privatekey = NULL;
        }
        wolfSSL_CTX_free(tls_io_instance->ssl_context);
        xio_destroy(tls_io_instance->socket_io);
        free(tls_io);
    }
}

int tlsio_wolfssl_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    int result;

    if (tls_io == NULL)
    {
        result = __LINE__;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN)
        {
            LogError("Invalid state encountered.");
            result = __LINE__;
        }
        else
        {
            tls_io_instance->on_bytes_received = on_bytes_received;
            tls_io_instance->on_bytes_received_context = on_bytes_received_context;

            tls_io_instance->on_io_open_complete = on_io_open_complete;
            tls_io_instance->on_io_open_complete_context = on_io_open_complete_context;

            tls_io_instance->on_io_error = on_io_error;
            tls_io_instance->on_io_error_context = on_io_error_context;

            tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_UNDERLYING_IO;

            if (create_wolfssl_instance(tls_io_instance) != 0)
            {
                tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
                result = __LINE__;
            }
            else if (xio_open(tls_io_instance->socket_io, on_underlying_io_open_complete, tls_io_instance, on_underlying_io_bytes_received, tls_io_instance, on_underlying_io_error, tls_io_instance) != 0)
            {
                tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
                result = __LINE__;
            }
            else
            {
                // The state can get changed in the on_underlying_io_open_complete
                if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
                {
                    LogError("Failed to connect to server.  The certificates may not be correct.");
                    result = __LINE__;
                }
                else
                {
                    result = 0;
                }
            }
        }
    }

    return result;
}

int tlsio_wolfssl_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    int result = 0;

    if (tls_io == NULL)
    {
        result = __LINE__;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if ((tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN) ||
            (tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING))
        {
            result = __LINE__;
        }
        else
        {
            tls_io_instance->tlsio_state = TLSIO_STATE_CLOSING;
            tls_io_instance->on_io_close_complete = on_io_close_complete;
            tls_io_instance->on_io_close_complete_context = callback_context;

            if (xio_close(tls_io_instance->socket_io, on_underlying_io_close_complete, tls_io_instance) != 0)
            {
                result = __LINE__;
            }
            else
            {
                destroy_wolfssl_instance(tls_io_instance);
                result = 0;
            }
        }
    }

    return result;
}

int tlsio_wolfssl_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;

    if (tls_io == NULL)
    {
        result = __LINE__;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
        {
            result = __LINE__;
        }
        else
        {
            tls_io_instance->on_send_complete = on_send_complete;
            tls_io_instance->on_send_complete_callback_context = callback_context;

            int res = wolfSSL_write(tls_io_instance->ssl, buffer, size);
            if ((res < 0) || ((size_t)res != size)) // Best way I can think of to safely compare an int to a size_t
            {
                result = __LINE__;
            }
            else
            {
                result = 0;
            }
        }
    }

    return result;
}

void tlsio_wolfssl_dowork(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io != NULL)
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if ((tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN) &&
            (tls_io_instance->tlsio_state != TLSIO_STATE_ERROR))
        {
            decode_ssl_received_bytes(tls_io_instance);
            xio_dowork(tls_io_instance->socket_io);
        }
    }
}

const IO_INTERFACE_DESCRIPTION* tlsio_wolfssl_get_interface_description(void)
{
    return &tlsio_wolfssl_interface_description;
}

static int process_option(char** destination, const char* name, const char* value)
{
    int result;
    if (*destination != NULL)
    {
        free(*destination);
        *destination = NULL;
    }
    if (mallocAndStrcpy_s(destination, value) != 0)
    {
        LogError("unable to process option %s",name);
        result = __LINE__;
    }
    else
    {
        result = 0;
    }
    return result;

}
int tlsio_wolfssl_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
    int result;

    if (tls_io == NULL || optionName == NULL)
    {
        result = __LINE__;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (strcmp("TrustedCerts", optionName) == 0)
        {
            result  = process_option(&tls_io_instance->certificate, optionName, value);
        }
        else if (strcmp(SU_OPTION_X509_CERT, optionName) == 0)
        {
            result = process_option(&tls_io_instance->x509certificate, optionName, value);
        }
        else if (strcmp(SU_OPTION_X509_PRIVATE_KEY, optionName) == 0)
        {
            result = process_option(&tls_io_instance->x509privatekey, optionName, value);
        }
        else
        {
            if (tls_io_instance->socket_io == NULL)
            {
                result = __LINE__;
            }
            else
            {
                result = xio_setoption(tls_io_instance->socket_io, optionName, value);
            }
        }
    }

    return result;
}
