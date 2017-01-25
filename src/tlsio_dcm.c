// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#define SECURITY_WIN32
#ifdef WINCE
#define UNICODE // Only Unicode version of secur32.lib functions supported on Windows CE
#define SCH_USE_STRONG_CRYPTO  0x00400000 // not defined in header file
#endif

#ifdef UNICODE
#define SEC_TCHAR   SEC_WCHAR
#else
#define SEC_TCHAR   SEC_CHAR
#endif

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif


#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/tlsio_dcm.h"
#include "azure_c_shared_utility/socketio.h"
#include "windows.h"
#include "sspi.h"
#include "schannel.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/x509_schannel.h"
#include "azure_c_shared_utility/crt_abstractions.h"

typedef enum TLSIO_STATE_TAG
{
	TLSIO_STATE_NOT_OPEN,
	TLSIO_STATE_OPENING_UNDERLYING_IO,
	TLSIO_STATE_HANDSHAKE_CLIENT_HELLO_SENT,
	TLSIO_STATE_HANDSHAKE_SERVER_HELLO_RECEIVED,
	TLSIO_STATE_OPEN,
	TLSIO_STATE_CLOSING,
	TLSIO_STATE_ERROR
} TLSIO_STATE;

//Used for faux DCM Init
typedef struct DCM_INFO
{
	TLSIO_STATE tlsio_dcm_state;
	const char* initData;
} DCM_INSTANCE;

typedef struct TLS_IO_INSTANCE_TAG
{
	XIO_HANDLE socket_io;
	ON_IO_OPEN_COMPLETE on_io_open_complete;
	ON_IO_CLOSE_COMPLETE on_io_close_complete;
	ON_BYTES_RECEIVED on_bytes_received;
	ON_IO_ERROR on_io_error;
	void* on_io_open_complete_context;
	void* on_io_close_complete_context;
	void* on_bytes_received_context;
	void* on_io_error_context;
	CtxtHandle security_context;
	TLSIO_STATE tlsio_state;
	SEC_TCHAR* host_name;
	CredHandle credential_handle;
	bool credential_handle_allocated;
	unsigned char* received_bytes;
	size_t received_byte_count;
	size_t buffer_size;
	size_t needed_bytes;
	const char* x509certificate;
	const char* x509privatekey;
	X509_SCHANNEL_HANDLE x509_schannel_handle;
} TLS_IO_INSTANCE;

//debug
static int count = 0;

/*this function will clone an option given by name and value*/
static void* tlsio_dcm_CloneOption(const char* name, const void* value)
{
	void* result;
	if (
		(name == NULL) || (value == NULL)
		)
	{
		LogError("invalid parameter detected: const char* name=%p, const void* value=%p", name, value);
		result = NULL;
	}
	else
	{
		if (strcmp(name, "x509certificate") == 0)
		{
			if (mallocAndStrcpy_s((char**)&result, (const char *)value) != 0)
			{
				LogError("unable to mallocAndStrcpy_s x509certificate value");
				result = NULL;
			}
			else
			{
				/*return as is*/
			}
		}
		else if (strcmp(name, "x509privatekey") == 0)
		{
			if (mallocAndStrcpy_s((char**)&result, (const char *)value) != 0)
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
static void tlsio_dcm_DestroyOption(const char* name, const void* value)
{
	/*since all options for this layer are actually string copies., disposing of one is just calling free*/
	if (
		(name == NULL) || (value == NULL)
		)
	{
		LogError("invalid parameter detected: const char* name=%p, const void* value=%p", name, value);
	}
	else
	{
		if (
			(strcmp(name, "x509certificate") == 0) ||
			(strcmp(name, "x509privatekey") == 0)
			)
		{
			free((void*)value);
		}
		else
		{
			LogError("not handled option : %s", name);
		}
	}
}

static OPTIONHANDLER_HANDLE tlsio_dcm_retrieveoptions(CONCRETE_IO_HANDLE handle)
{
	OPTIONHANDLER_HANDLE result;
	if (handle == NULL)
	{
		LogError("invalid parameter detected: CONCRETE_IO_HANDLE handle=%p", handle);
		result = NULL;
	}
	else
	{
		result = OptionHandler_Create(tlsio_dcm_CloneOption, tlsio_dcm_DestroyOption, tlsio_dcm_setoption);
		if (result == NULL)
		{
			LogError("unable to OptionHandler_Create");
			/*return as is*/
		}
		else
		{
			/*this layer cares about the certificates and the x509 credentials*/
			TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)handle;
			if (
				(tls_io_instance->x509certificate != NULL) &&
				(OptionHandler_AddOption(result, "x509certificate", tls_io_instance->x509certificate) != 0)
				)
			{
				LogError("unable to save x509certificate option");
				OptionHandler_Destroy(result);
				result = NULL;
			}
			else if (
				(tls_io_instance->x509privatekey != NULL) &&
				(OptionHandler_AddOption(result, "x509privatekey", tls_io_instance->x509privatekey) != 0)
				)
			{
				LogError("unable to save x509privatekey option");
				OptionHandler_Destroy(result);
				result = NULL;
			}
			else
			{
				/*all is fine, all interesting options have been saved*/
				/*return as is*/
			}
		}
	}
	return result;
}

static const IO_INTERFACE_DESCRIPTION tlsio_dcm_interface_description =
{
	tlsio_dcm_retrieveoptions,
	tlsio_dcm_create,
	tlsio_dcm_destroy,
	tlsio_dcm_open,
	tlsio_dcm_close,
	tlsio_dcm_send,
	tlsio_dcm_dowork,
	tlsio_dcm_setoption
};

static void indicate_error(TLS_IO_INSTANCE* tls_io_instance)
{
	if (tls_io_instance->on_io_error != NULL)
	{
		tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
	}
}

static int resize_receive_buffer(TLS_IO_INSTANCE* tls_io_instance, size_t needed_buffer_size)
{
	int result;

	if (needed_buffer_size > tls_io_instance->buffer_size)
	{
		unsigned char* new_buffer = (unsigned char*)realloc(tls_io_instance->received_bytes, needed_buffer_size);
		if (new_buffer == NULL)
		{
			result = __LINE__;
		}
		else
		{
			tls_io_instance->received_bytes = new_buffer;
			tls_io_instance->buffer_size = needed_buffer_size;
			result = 0;
		}
	}
	else
	{
		result = 0;
	}

	return result;
}

static void on_underlying_io_close_complete(void* context)
{
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;
	if (tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING)
	{
		tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
		if (tls_io_instance->on_io_close_complete != NULL)
		{
			tls_io_instance->on_io_close_complete(tls_io_instance->on_io_close_complete_context);
		}

		/* Free security context resources corresponding to creation with open */
		//DeleteSecurityContext(&tls_io_instance->security_context); //HACK: Removed since we don't have a security context yet (This was for SSL Version)

		if (tls_io_instance->credential_handle_allocated)
		{
			(void)FreeCredentialHandle(&tls_io_instance->credential_handle);
			tls_io_instance->credential_handle_allocated = false;
		}
	}
}



//TODO: Security init should start here. In TLS/SSL this is where the client sends the TLS Hello and then the server respondsd with a server Cert plus auth type list
static void on_underlying_io_open_complete(void* context, IO_OPEN_RESULT io_open_result)
{
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;
	DCM_INSTANCE dcm_info;
	dcm_info.initData = "SEED"; //Test Init data


	if (tls_io_instance->tlsio_state != TLSIO_STATE_OPENING_UNDERLYING_IO)
	{
		tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
		indicate_error(tls_io_instance);
	}
	else
	{
		if (io_open_result != IO_OPEN_OK)
		{
			tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
			if (tls_io_instance->on_io_open_complete != NULL)
			{
				tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, IO_OPEN_ERROR);
			}
		}
		else
		{
			if (xio_send(tls_io_instance->socket_io, dcm_info.initData, (strlen(dcm_info.initData) + 1), NULL, NULL) != 0)
			{
				tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
				indicate_error(tls_io_instance);
			}
			else
			{
				/* set the needed bytes to 1, to get on the next byte how many we actually need */
				tls_io_instance->needed_bytes = 1;
				if (resize_receive_buffer(tls_io_instance, tls_io_instance->needed_bytes + tls_io_instance->received_byte_count) != 0)
				{
					tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
					indicate_error(tls_io_instance);
				}
				else
				{
					tls_io_instance->tlsio_state = TLSIO_STATE_HANDSHAKE_CLIENT_HELLO_SENT;
				}
			}
		}
	}

	//if (io_open_result == IO_OPEN_OK)
	//{
	//}

	//if (tls_io_instance->tlsio_state != TLSIO_STATE_OPENING_UNDERLYING_IO)
	//{
	//	tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
	//	indicate_error(tls_io_instance);
	//}
	//else
	//{
	//	//tls_io_instance->tlsio_state = TLSIO_STATE_HANDSHAKE_CLIENT_HELLO_SENT; //This is a handoff to send a packet to the server to complete the seurity init handshake
	//	// Since we aren't doing that yet, we will just say that everything is open and OK
	//	tls_io_instance->needed_bytes = 1;
	//	tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
	//	if (tls_io_instance->on_io_open_complete != NULL)
	//	{
	//		tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, IO_OPEN_OK);
	//	}
	//}
}

static int set_receive_buffer(TLS_IO_INSTANCE* tls_io_instance, size_t buffer_size)
{
	int result;

	unsigned char* new_buffer = (unsigned char*)realloc(tls_io_instance->received_bytes, buffer_size);
	if (new_buffer == NULL)
	{
		result = __LINE__;
	}
	else
	{
		tls_io_instance->received_bytes = new_buffer;
		tls_io_instance->buffer_size = buffer_size;
		result = 0;
	}

	return result;
}

static void on_underlying_io_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;
	size_t consumed_bytes;

	if (resize_receive_buffer(tls_io_instance, tls_io_instance->received_byte_count + size) == 0)
	{
		memcpy(tls_io_instance->received_bytes + tls_io_instance->received_byte_count, buffer, size);
		tls_io_instance->received_byte_count += size;

		if (size > tls_io_instance->needed_bytes)
		{
			tls_io_instance->needed_bytes = 0;
		}
		else
		{
			tls_io_instance->needed_bytes -= size;
		}
		/* Drain what we received */
		while (tls_io_instance->needed_bytes == 0)
		{
			if (tls_io_instance->tlsio_state == TLSIO_STATE_HANDSHAKE_CLIENT_HELLO_SENT)
			{
				if (tls_io_instance->received_byte_count == 1024)
				{
					//size_t loop = 0;
					//for (loop = 0; loop < tls_io_instance->received_byte_count; loop++)
					//{
					//	printf("%d : %x |",loop, tls_io_instance->received_bytes[loop]);
					//}
					consumed_bytes = tls_io_instance->received_byte_count;
					tls_io_instance->received_byte_count -= consumed_bytes;
					/* if nothing more to consume, set the needed bytes to 1, to get on the next byte how many we actually need */
					tls_io_instance->needed_bytes = tls_io_instance->received_byte_count == 0 ? 1 : 0;


					//Resize the receive buffer for the next set of inbound network data unrelated to this handshake
					if (set_receive_buffer(tls_io_instance, tls_io_instance->needed_bytes + tls_io_instance->received_byte_count) != 0)
					{
						tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
						if (tls_io_instance->on_io_open_complete != NULL)
						{
							tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, IO_OPEN_ERROR);
						}
					}
					else
					{
						//Handshake done; now time for MQTT connect and ACK IF we we are using MQTT. This layer shouldn't care....
						tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
						if (tls_io_instance->on_io_open_complete != NULL)
						{
							tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, IO_OPEN_OK);
						}
					}
				}
				else
				{
					tls_io_instance->needed_bytes = 1024 - tls_io_instance->received_byte_count;
				}
				//tls_io_instance->received_byte_count -= consumed_bytes;

				/* if nothing more to consume, set the needed bytes to 1, to get on the next byte how many we actually need */
				//tls_io_instance->needed_bytes = tls_io_instance->received_byte_count == 0 ? 1 : 0;


			}
			else if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
			{
				consumed_bytes = tls_io_instance->received_byte_count;
				if (tls_io_instance->on_bytes_received != NULL)
				{
					//tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, (const unsigned char *)buffer, size);
					tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, tls_io_instance->received_bytes, tls_io_instance->received_byte_count);
				}

				tls_io_instance->received_byte_count -= consumed_bytes;

				/* if nothing more to consume, set the needed bytes to 1, to get on the next byte how many we actually need */
				tls_io_instance->needed_bytes = tls_io_instance->received_byte_count == 0 ? 1 : 0;

				if (set_receive_buffer(tls_io_instance, tls_io_instance->needed_bytes + tls_io_instance->received_byte_count) != 0)
				{
					tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
					indicate_error(tls_io_instance);
				}
			}
			//else if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
			//{
			//	if (tls_io_instance->on_bytes_received != NULL)
			//	{
			//		tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, (const unsigned char *)buffer, size);
			//	}
			//	consumed_bytes = tls_io_instance->received_byte_count;
			//	tls_io_instance->received_byte_count -= consumed_bytes;

			//	/* if nothing more to consume, set the needed bytes to 1, to get on the next byte how many we actually need */
			//	tls_io_instance->needed_bytes = tls_io_instance->received_byte_count == 0 ? 1 : 0;

			//	if (set_receive_buffer(tls_io_instance, tls_io_instance->needed_bytes + tls_io_instance->received_byte_count) != 0)
			//	{
			//		tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
			//		indicate_error(tls_io_instance);
			//	}
			//}
		}
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
	case TLSIO_STATE_HANDSHAKE_CLIENT_HELLO_SENT:
	case TLSIO_STATE_HANDSHAKE_SERVER_HELLO_RECEIVED:
		tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
		if (tls_io_instance->on_io_open_complete != NULL)
		{
			tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, IO_OPEN_ERROR);
		}
		break;

	case TLSIO_STATE_CLOSING:
		tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
		if (tls_io_instance->on_io_close_complete != NULL)
		{
			tls_io_instance->on_io_close_complete(tls_io_instance->on_io_close_complete_context);
		}
		break;

	case TLSIO_STATE_OPEN:
		tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
		indicate_error(tls_io_instance);
		break;
	}
}

CONCRETE_IO_HANDLE tlsio_dcm_create(void* io_create_parameters)
{
	TLSIO_CONFIG* tls_io_config = (TLSIO_CONFIG *)io_create_parameters;
	TLS_IO_INSTANCE* result;

	if (tls_io_config == NULL)
	{
		result = NULL;
	}
	else
	{
		result = (TLS_IO_INSTANCE *)malloc(sizeof(TLS_IO_INSTANCE));
		if (result != NULL)
		{
			SOCKETIO_CONFIG socketio_config;

			socketio_config.hostname = tls_io_config->hostname;
			socketio_config.port = tls_io_config->port;
			socketio_config.accepted_socket = NULL;

			result->on_bytes_received = NULL;
			result->on_io_open_complete = NULL;
			result->on_io_close_complete = NULL;
			result->on_io_error = NULL;
			result->on_io_open_complete_context = NULL;
			result->on_io_close_complete_context = NULL;
			result->on_bytes_received_context = NULL;
			result->on_io_error_context = NULL;
			result->credential_handle_allocated = false;
			result->x509_schannel_handle = NULL;

			result->host_name = (SEC_TCHAR*)malloc(sizeof(SEC_TCHAR) * (1 + strlen(tls_io_config->hostname)));

			if (result->host_name == NULL)
			{
				free(result);
				result = NULL;
			}
			else
			{
#ifdef WINCE
				(void) mbstowcs(result->host_name, tls_io_config->hostname, strlen(tls_io_config->hostname));
#else
				(void)strcpy(result->host_name, tls_io_config->hostname);
#endif

				const IO_INTERFACE_DESCRIPTION* socket_io_interface = socketio_get_interface_description();
				if (socket_io_interface == NULL)
				{
					free(result->host_name);
					free(result);
					result = NULL;
				}
				else
				{
					result->socket_io = xio_create(socket_io_interface, &socketio_config);
					if (result->socket_io == NULL)
					{
						free(result->host_name);
						free(result);
						result = NULL;
					}
					else
					{
						result->received_bytes = NULL;
						result->received_byte_count = 0;
						result->buffer_size = 0;
						result->tlsio_state = TLSIO_STATE_NOT_OPEN;
						result->x509certificate = NULL;
						result->x509privatekey = NULL;
						result->x509_schannel_handle = NULL;
					}
				}
			}
		}
	}

	return result;
}

void tlsio_dcm_destroy(CONCRETE_IO_HANDLE tls_io)
{
	if (tls_io != NULL)
	{
		TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
		if (tls_io_instance->credential_handle_allocated)
		{
			(void)FreeCredentialHandle(&tls_io_instance->credential_handle);
			tls_io_instance->credential_handle_allocated = false;
		}

		if (tls_io_instance->received_bytes != NULL)
		{
			free(tls_io_instance->received_bytes);
		}

		if (tls_io_instance->x509_schannel_handle != NULL)
		{
			x509_schannel_destroy(tls_io_instance->x509_schannel_handle);
		}

		xio_destroy(tls_io_instance->socket_io);
		free(tls_io_instance->host_name);
		free(tls_io);
	}
}

int tlsio_dcm_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
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
			result = __LINE__;
		}
		else
		{
			tls_io_instance->on_io_open_complete = on_io_open_complete;
			tls_io_instance->on_io_open_complete_context = on_io_open_complete_context;

			tls_io_instance->on_bytes_received = on_bytes_received;
			tls_io_instance->on_bytes_received_context = on_bytes_received_context;

			tls_io_instance->on_io_error = on_io_error;
			tls_io_instance->on_io_error_context = on_io_error_context;

			tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_UNDERLYING_IO;

			if (xio_open(tls_io_instance->socket_io, on_underlying_io_open_complete, tls_io_instance, on_underlying_io_bytes_received, tls_io_instance, on_underlying_io_error, tls_io_instance) != 0)
			{
				result = __LINE__;
				tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
			}
			else
			{
				result = 0;
			}
		}
	}

	return result;
}

int tlsio_dcm_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
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
				result = 0;
			}
		}
	}

	return result;
}

static int send_chunk(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
	int result;

	if ((tls_io == NULL) ||
		(buffer == NULL) ||
		(size == 0))
	{
		/* Invalid arguments */
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
			//SecPkgContext_StreamSizes  sizes;
			//SECURITY_STATUS status = QueryContextAttributes(&tls_io_instance->security_context, SECPKG_ATTR_STREAM_SIZES, &sizes);
			SECURITY_STATUS status = SEC_E_OK;
			if (status != SEC_E_OK)
			{
				result = __LINE__;
			}
			else
			{
				//SecBuffer security_buffers[4];
				//SecBufferDesc security_buffers_desc;
				//size_t needed_buffer = sizes.cbHeader + size + sizes.cbTrailer;
				//unsigned char* out_buffer = (unsigned char*)malloc(needed_buffer);
				//if (out_buffer == NULL)
				//{
				//	result = __LINE__;
				//}
				//else
				//{
				//	memcpy(out_buffer + sizes.cbHeader, buffer, size);

				//	security_buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
				//	security_buffers[0].cbBuffer = sizes.cbHeader;
				//	security_buffers[0].pvBuffer = out_buffer;
				//	security_buffers[1].BufferType = SECBUFFER_DATA;
				//	security_buffers[1].cbBuffer = (unsigned long)size;
				//	security_buffers[1].pvBuffer = out_buffer + sizes.cbHeader;
				//	security_buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
				//	security_buffers[2].cbBuffer = sizes.cbTrailer;
				//	security_buffers[2].pvBuffer = out_buffer + sizes.cbHeader + size;
				//	security_buffers[3].cbBuffer = 0;
				//	security_buffers[3].BufferType = SECBUFFER_EMPTY;
				//	security_buffers[3].pvBuffer = 0;

				//	security_buffers_desc.cBuffers = sizeof(security_buffers) / sizeof(security_buffers[0]);
				//	security_buffers_desc.pBuffers = security_buffers;
				//	security_buffers_desc.ulVersion = SECBUFFER_VERSION;

				//	status = EncryptMessage(&tls_io_instance->security_context, 0, &security_buffers_desc, 0);
				if (FAILED(status))
				{
					result = __LINE__;
				}
				else
				{
					//if (xio_send(tls_io_instance->socket_io, out_buffer, security_buffers[0].cbBuffer + security_buffers[1].cbBuffer + security_buffers[2].cbBuffer, on_send_complete, callback_context) != 0)
					if (xio_send(tls_io_instance->socket_io, buffer, size, on_send_complete, callback_context) != 0)
					{
						result = __LINE__;
					}
					else
					{
						result = 0;
					}
				}

				//free(out_buffer);
			}
		}
	}

	return result;
}

int tlsio_dcm_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
	int result;

	while (size > 0)
	{
		size_t to_send = 16 * 1024;
		if (to_send > size)
		{
			to_send = size;
		}

		if (send_chunk(tls_io, buffer, to_send, (to_send == size) ? on_send_complete : NULL, callback_context) != 0)
		{
			break;
		}

		size -= to_send;
		buffer = ((const unsigned char*)buffer) + to_send;
	}

	if (size > 0)
	{
		result = __LINE__;
	}
	else
	{
		result = 0;
	}

	return result;
}

void tlsio_dcm_dowork(CONCRETE_IO_HANDLE tls_io)
{
	if (tls_io != NULL)
	{
		TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
		xio_dowork(tls_io_instance->socket_io);
	}
}

int tlsio_dcm_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
	int result;

	if (tls_io == NULL || optionName == NULL)
	{
		result = __LINE__;
	}
	else
	{
		TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
		/*x509certificate and x509privatekey are "referenced" by this layer*/
		if (strcmp("x509certificate", optionName) == 0)
		{
			if (tls_io_instance->x509certificate != NULL)
			{
				LogError("unable to set x509 options more than once");
				result = __LINE__;
			}
			else
			{
				tls_io_instance->x509certificate = (const char *)tlsio_dcm_CloneOption("x509certificate", value);
				if (tls_io_instance->x509privatekey != NULL)
				{
					tls_io_instance->x509_schannel_handle = x509_schannel_create(tls_io_instance->x509certificate, tls_io_instance->x509privatekey);
					if (tls_io_instance->x509_schannel_handle == NULL)
					{
						LogError("x509_schannel_create failed");
						result = __LINE__;
					}
					else
					{
						/*all is fine, the x509 shall be used later*/
						result = 0;
					}
				}
				else
				{
					result = 0; /*all is fine, maybe x509 privatekey will come and then x509 is set*/
				}
			}
		}
		else if (strcmp("x509privatekey", optionName) == 0)
		{
			if (tls_io_instance->x509privatekey != NULL)
			{
				LogError("unable to set more than once x509 options");
				result = __LINE__;
			}
			else
			{
				tls_io_instance->x509privatekey = (const char *)tlsio_dcm_CloneOption("x509privatekey", value);
				if (tls_io_instance->x509certificate != NULL)
				{
					tls_io_instance->x509_schannel_handle = x509_schannel_create(tls_io_instance->x509certificate, tls_io_instance->x509privatekey);
					if (tls_io_instance->x509_schannel_handle == NULL)
					{
						LogError("x509_schannel_create failed");
						result = __LINE__;
					}
					else
					{
						/*all is fine, the x509 shall be used later*/
						result = 0;
					}
				}
				else
				{
					result = 0; /*all is fine, maybe x509 privatekey will come and then x509 is set*/
				}
			}
		}
		else if (tls_io_instance->socket_io == NULL)
		{
			result = __LINE__;
		}
		else
		{
			result = xio_setoption(tls_io_instance->socket_io, optionName, value);
		}
	}

	return result;
}

const IO_INTERFACE_DESCRIPTION* tlsio_dcm_get_interface_description(void)
{
	return &tlsio_dcm_interface_description;
}
