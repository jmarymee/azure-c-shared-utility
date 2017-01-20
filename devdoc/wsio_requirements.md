# wsio requirements
 
## Overview

`wsio` is module that implements a concrete IO that implements the WebSockets protocol by using the uws library.

## References

RFC6455 - The WebSocket Protocol.

## Exposed API

```c
typedef struct WSIO_CONFIG_TAG
{
    const char* hostname;
    int port;
    const char* resource_name;
    const char* protocol;
    bool use_ssl;
} WSIO_CONFIG;

extern const IO_INTERFACE_DESCRIPTION* wsio_get_interface_description(void);
```

### wsio_create

```c
extern CONCRETE_IO_HANDLE wsio_create(void* io_create_parameters);
```

XX**SRS_WSIO_01_001: [**`wsio_create` shall create an instance of wsio and return a non-NULL handle to it.**]**
XX**SRS_WSIO_01_065: [** If the argument `io_create_parameters` is NULL then `wsio_create` shall return NULL. **]**
XX**SRS_WSIO_01_066: [** `io_create_parameters` shall be used as a `WSIO_CONFIG*` . **]**
XX**SRS_WSIO_01_067: [** If any of the members `hostname`, `resource_name` or `protocol` is NULL in `WSIO_CONFIG` then `wsio_create` shall return NULL. **]**
XX**SRS_WSIO_01_068: [** If allocating memory for the new wsio instance fails then `wsio_create` shall return NULL. **]**
XX**SRS_WSIO_01_070: [** The underlying uws instance shall be created by calling `uws_client_create`. **]**
XX**SRS_WSIO_01_071: [** The arguments for `uws_client_create` shall be: **]**
XX**SRS_WSIO_01_072: [** - `hostname` set to the `hostname` field in the `io_create_parameters` passed to `wsio_create`. **]**
XX**SRS_WSIO_01_130: [** - `port` set to the `port` field in the `io_create_parameters` passed to `wsio_create`. **]**
XX**SRS_WSIO_01_128: [** - `resource_name` set to the `resource_name` field in the `io_create_parameters` passed to `wsio_create`. **]**
XX**SRS_WSIO_01_129: [** - `protocols` shall be filled with only one structure, that shall have the `protocol` set to the value of the `protocol` field in the `io_create_parameters` passed to `wsio_create`. **]**
XX**SRS_WSIO_01_075: [** If `uws_client_create` fails, then `wsio_create` shall fail and return NULL. **]**
XX**SRS_WSIO_01_076: [** `wsio_create` shall create a pending send IO list that is to be used to queue send packets by calling `singlylinkedlist_create`. **]**
XX**SRS_WSIO_01_077: [** If `singlylinkedlist_create` fails then `wsio_create` shall fail and return NULL. **]**

### wsio_destroy

```c
extern void wsio_destroy(CONCRETE_IO_HANDLE ws_io);
```

XX**SRS_WSIO_01_078: [** `wsio_destroy` shall free all resources associated with the wsio instance. **]**
XX**SRS_WSIO_01_079: [** If `ws_io` is NULL, `wsio_destroy` shall do nothing.  **]**
XX**SRS_WSIO_01_080: [** `wsio_destroy` shall destroy the uws instance created in `wsio_create` by calling `uws_client_destroy`. **]**
XX**SRS_WSIO_01_081: [** `wsio_destroy` shall free the list used to track the pending send IOs by calling `singlylinkedlist_destroy`. **]**

### wsio_open

```c
extern int wsio_open(CONCRETE_IO_HANDLE ws_io, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context);
```

XX**SRS_WSIO_01_082: [** `wsio_open` shall open the underlying uws instance by calling `uws_client_open` and providing the uws handle created in `wsio_create` as argument. **]**
XX**SRS_WSIO_01_083: [** On success, `wsio_open` shall return 0. **]**
XX**SRS_WSIO_01_084: [** If opening the underlying uws instance fails then `wsio_open` shall fail and return a non-zero value. **]**
XX**SRS_WSIO_01_131: [** `wsio_open` when already OPEN or OPENING shall fail and return a non-zero value. **]**
XX**SRS_WSIO_01_132: [** If any of the arguments `ws_io`, `on_io_open_complete`, `on_bytes_received`, `on_io_error` is NULL, `wsio_open` shall fail and return a non-zero value. **]**
XX**SRS_WSIO_01_165: [** `wsio_open` when CLOSING shall fail and return a non-zero value. **]**

### wsio_close

```c
extern int wsio_close(CONCRETE_IO_HANDLE ws_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context);
```

XX**SRS_WSIO_01_085: [** `wsio_close` shall close the websockets IO if an open action is either pending or has completed successfully (if the IO is open).  **]**
XX**SRS_WSIO_01_133: [** On success `wsio_close` shall return 0. **]**
XX**SRS_WSIO_01_086: [** if `ws_io` is NULL, `wsio_close` shall return a non-zero value.  **]**
XX**SRS_WSIO_01_087: [** `wsio_close` shall call `uws_client_close` while passing as argument the IO handle created in `wsio_create`.  **]**
XX**SRS_WSIO_01_164: [** When `uws_client_close` fails, `wsio_close` shall fail and return a non-zero value. **]**
XX**SRS_WSIO_01_088: [** `wsio_close` when no open action has been issued shall fail and return a non-zero value. **]**
XX**SRS_WSIO_01_089: [** `wsio_close` after a `wsio_close` shall fail and return a non-zero value.  **]**
XX**SRS_WSIO_01_090: [** The argument `on_io_close_complete` shall be optional, if NULL is passed by the caller then no close complete callback shall be triggered.  **]**
XX**SRS_WSIO_01_091: [** `wsio_close` shall obtain all the pending IO items by repetitively querying for the head of the pending IO list and freeing that head item. **]**
XX**SRS_WSIO_01_092: [** Obtaining the head of the pending IO list shall be done by calling `singlylinkedlist_get_head_item`. **]**
XX**SRS_WSIO_01_093: [** For each pending item the send complete callback shall be called with `IO_SEND_CANCELLED`.**\]**

### wsio_send

```c
extern int wsio_send(CONCRETE_IO_HANDLE ws_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context);
```

XX**SRS_WSIO_01_095: [** `wsio_send` shall call `uws_client_send_frame`, passing the `buffer` and `size` arguments as they are: **]**
XX**SRS_WSIO_01_096: [** The frame type used shall be `WS_FRAME_TYPE_BINARY`. **]**
XX**SRS_WSIO_01_097: [** The `is_final` argument shall be set to true. **]**
XX**SRS_WSIO_01_098: [** On success, `wsio_send` shall return 0. **]**
XX**SRS_WSIO_01_099: [** If the wsio is not OPEN (open has not been called or is still in progress) then `wsio_send` shall fail and return a non-zero value. **]**
XX**SRS_WSIO_01_100: [** If any of the arguments `ws_io` or `buffer` are NULL, `wsio_send` shall fail and return a non-zero value. **]**
XX**SRS_WSIO_01_101: [** If `size` is zero then `wsio_send` shall fail and return a non-zero value. **]**
XX**SRS_WSIO_01_102: [** An entry shall be queued in the singly linked list by calling `singlylinkedlist_add`. **]**
XX**SRS_WSIO_01_103: [** The entry shall contain the `on_send_complete` callback and its context. **]**
XX**SRS_WSIO_01_134: [** If allocating memory for the pending IO data fails, `wsio_send` shall fail and return a non-zero value. **]**
XX**SRS_WSIO_01_104: [** If `singlylinkedlist_add` fails, `wsio_send` shall fail and return a non-zero value. **]**
XX**SRS_WSIO_01_105: [** The argument `on_send_complete` shall be optional, if NULL is passed by the caller then no send complete callback shall be triggered. **]**

### wsio_dowork

```c
extern void wsio_dowork(CONCRETE_IO_HANDLE ws_io);
```

XX**SRS_WSIO_01_106: [** `wsio_dowork` shall call `uws_client_dowork` with the uws handle created in `wsio_create`. **]**
XX**SRS_WSIO_01_107: [** If the `ws_io` argument is NULL, `wsio_dowork` shall do nothing. **]**
XX**SRS_WSIO_01_108: [** If the IO is not yet open, `wsio_dowork` shall do nothing. **]**

### wsio_setoption

```c
extern int wsio_setoption(CONCRETE_IO_HANDLE ws_io, const char* option_name, const void* value);
```

XX**SRS_WSIO_01_109: [** If any of the arguments `ws_io` or `option_name` is NULL `wsio_setoption` shall return a non-zero value. **]**
XX**SRS_WSIO_01_156: [** All options shall be passed as they are to uws by calling `uws_client_set_option`. **]**
XX**SRS_WSIO_01_158: [** On success, `wsio_setoption` shall return 0. **]**
XX**SRS_WSIO_01_157: [** If `uws_client_set_option` fails, `wsio_setoption` shall fail and return a non-zero value. **]**

### wsio_retrieveoptions

```c
OPTIONHANDLER_HANDLE wsio_retrieveoptions(CONCRETE_IO_HANDLE handle)
```

XX**SRS_WSIO_01_118: [** If parameter `handle` is `NULL` then `wsio_retrieveoptions` shall fail and return NULL. **]**
XX**SRS_WSIO_01_119: [** `wsio_retrieveoptions` shall call `uws_client_retrieve_options` to produce an `OPTIONHANDLER_HANDLE` and on success return the new `OPTIONHANDLER_HANDLE` handle. **]**
XX**SRS_WSIO_01_120: [** If `uws_client_retrieve_options` fails then `wsio_retrieveoptions` shall fail and return NULL.  **]**

### wsio_get_interface_description

```c
extern const IO_INTERFACE_DESCRIPTION* wsio_get_interface_description(void);
```

**SRS_WSIO_01_064: [**wsio_get_interface_description shall return a pointer to an IO_INTERFACE_DESCRIPTION structure that contains pointers to the functions: wsio_retrieveoptions, wsio_create, wsio_destroy, wsio_open, wsio_close, wsio_send and wsio_dowork.**]** 

### on_underlying_ws_error

XX**SRS_WSIO_01_121: [** When `on_underlying_ws_error` is called while the IO is OPEN the wsio instance shall be set to ERROR and an error shall be indicated via the `on_io_error` callback passed to `wsio_open`. **]**
XX**SRS_WSIO_01_123: [** When calling `on_io_error`, the `on_io_error_context` argument given in `wsio_open` shall be passed to the callback `on_io_error`. **]**
XX**SRS_WSIO_01_122: [** When `on_underlying_ws_error` is called while the IO is OPENING, the `on_io_open_complete` callback passed to `wsio_open` shall be called with `IO_OPEN_ERROR`. **]**
XX**SRS_WSIO_01_135: [** When `on_underlying_ws_error` is called with a NULL context, it shall do nothing. **]**

### on_underlying_ws_frame_received

XX**SRS_WSIO_01_124: [** When `on_underlying_ws_frame_received` is called the bytes in the frame shall be indicated by calling the `on_bytes_received` callback passed to `wsio_open`. **]**
XX**SRS_WSIO_01_125: [** When calling `on_bytes_received`, the `on_bytes_received_context` argument given in `wsio_open` shall be passed to the callback `on_bytes_received`. **]**
XX**SRS_WSIO_01_126: [** If `on_underlying_ws_frame_received` is called while the IO is in any state other than OPEN, it shall do nothing. **]**
XX**SRS_WSIO_01_150: [** If `on_underlying_ws_frame_received` is called with NULL context it shall do nothing. **]**
XX**SRS_WSIO_01_151: [** If the WebSocket frame type is not binary then an error shall be indicated by calling the `on_io_error` callback passed to `wsio_open`. **]**
XX**SRS_WSIO_01_153: [** When `on_underlying_ws_frame_received` is called with zero `size`, no bytes shall be indicated up as received. **]**
XX**SRS_WSIO_01_154: [** When `on_underlying_ws_frame_received` is called with a positive `size` and a NULL `buffer`, an error shall be indicated by calling the `on_io_error` callback passed to `wsio_open`. **]**
XX**SRS_WSIO_01_152: [** When calling `on_io_error`, the `on_io_error_context` argument given in `wsio_open` shall be passed to the callback `on_io_error`. **]**

### on_underlying_ws_open_complete

XX**SRS_WSIO_01_136: [** When `on_underlying_ws_open_complete` is called with `WS_OPEN_OK` while the IO is opening, the callback `on_io_open_complete` shall be called with `IO_OPEN_OK`. **]**
XX**SRS_WSIO_01_149: [** When `on_underlying_ws_open_complete` is called with `WS_OPEN_CANCELLED` while the IO is opening, the callback `on_io_open_complete` shall be called with `IO_OPEN_CANCELLED`. **]**
XX**SRS_WSIO_01_137: [** When `on_underlying_ws_open_complete` is called with any other error code while the IO is opening, the callback `on_io_open_complete` shall be called with `IO_OPEN_ERROR`. **]**
XX**SRS_WSIO_01_138: [** When `on_underlying_ws_open_complete` is called with a NULL context, it shall do nothing. **]**
XX**SRS_WSIO_01_139: [** When `on_underlying_ws_open_complete` is called while in OPEN state it shall indicate an error by calling the `on_io_error` callback passed to `wsio_open` and switch to the ERROR state. **]**
XX**SRS_WSIO_01_141: [** When `on_underlying_ws_open_complete` is called while in the ERROR state it shall indicate an error by calling the `on_io_error` callback passed to `wsio_open`. **]**
XX**SRS_WSIO_01_140: [** When calling `on_io_error`, the `on_io_error_context` argument given in `wsio_open` shall be passed to the callback `on_io_error`. **]**
XX**SRS_WSIO_01_142: [** When `on_underlying_ws_open_complete` is called while in the CLOSING state an error shall be indicated by calling the `on_io_error` callback passed to `wsio_open`. **]**

### on_underlying_ws_send_frame_complete

XX**SRS_WSIO_01_143: [** When `on_underlying_ws_send_frame_complete` is called after sending a WebSocket frame, the pending IO shall be removed from the list. **]**
XX**SRS_WSIO_01_145: [** Removing it from the list shall be done by calling `singlylinkedlist_remove`. **]**
XX**SRS_WSIO_01_144: [** Also the pending IO data shall be freed. **]**
XX**SRS_WSIO_01_146: [** When `on_underlying_ws_send_frame_complete` is called with `WS_SEND_OK`, the callback `on_send_complete` shall be called with `IO_SEND_OK`. **]**
XX**SRS_WSIO_01_147: [** When `on_underlying_ws_send_frame_complete` is called with `WS_SEND_CANCELLED`, the callback `on_send_complete` shall be called with `IO_SEND_CANCELLED`. **]**
XX**SRS_WSIO_01_148: [** When `on_underlying_ws_send_frame_complete` is called with any other error code, the callback `on_send_complete` shall be called with `IO_SEND_ERROR`. **]**
XX**SRS_WSIO_01_155: [** When `on_underlying_ws_send_frame_complete` is called with a NULL context it shall do nothing. **]**

### on_underlying_ws_close_complete

XX**SRS_WSIO_01_159: [** When `on_underlying_ws_close_complete` while the IO is closing (after `wsio_close`), the close shall be indicated up by calling the `on_io_close_complete` callback passed to `wsio_close`. **]**
XX**SRS_WSIO_01_163: [** When `on_io_close_complete` is called, the context passed to `wsio_close` shall be passed as argument to `on_io_close_complete`. **]**
XX**SRS_WSIO_01_160: [** If NULL was passed to `wsio_close` no callback shall be called. **]**
XX**SRS_WSIO_01_161: [** If the context passed to `on_underlying_ws_close_complete` is NULL, `on_underlying_ws_close_complete` shall do nothing. **]**

### on_underlying_ws_peer_closed

XX**SRS_WSIO_01_166: [** When `on_underlying_ws_peer_closed` and the state of the IO is OPEN an error shall be indicated by calling the `on_io_error` callback passed to `wsio_open`. **]**
XX**SRS_WSIO_01_169: [** When `on_underlying_ws_peer_closed` and the state of the IO is CLOSING an error shall be indicated by calling the `on_io_error` callback passed to `wsio_open`. **]**
XX**SRS_WSIO_01_170: [** When `on_underlying_ws_peer_closed` and the state of the IO is OPENING an error shall be indicated by calling the `on_io_open_complete` callback passed to `wsio_open` with the error code `IO_OPEN_ERROR`. **]**
XX**SRS_WSIO_01_168: [** The `close_code`, `extra_data` and `extra_data_length` arguments shall be ignored. **]**
XX**SRS_WSIO_01_167: [** If `on_underlying_ws_peer_closed` is called with a NULL context it shall do nothing. **]**
