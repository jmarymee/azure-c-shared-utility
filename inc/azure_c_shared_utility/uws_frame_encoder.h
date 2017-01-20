// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef UWS_FRAME_ENCODER_H
#define UWS_FRAME_ENCODER_H

#ifdef __cplusplus
#include <cstdbool>
#include <cstddef>
extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#endif

#include "azure_c_shared_utility/buffer_.h"
#include "azure_c_shared_utility/umock_c_prod.h"

#define RESERVED_1  0x04
#define RESERVED_2  0x02
#define RESERVED_3  0x01

#define WS_FRAME_TYPE_VALUES \
    WS_CONTINUATION_FRAME = 0x00, \
    WS_TEXT_FRAME = 0x01, \
    WS_BINARY_FRAME = 0x02, \
    WS_RESERVED_NON_CONTROL_FRAME_3 = 0x03, \
    WS_RESERVED_NON_CONTROL_FRAME_4 = 0x04, \
    WS_RESERVED_NON_CONTROL_FRAME_5 = 0x05, \
    WS_RESERVED_NON_CONTROL_FRAME_6 = 0x06, \
    WS_RESERVED_NON_CONTROL_FRAME_7 = 0x07, \
    WS_CLOSE_FRAME = 0x08, \
    WS_PING_FRAME = 0x09, \
    WS_PONG_FRAME = 0x0A, \
    WS_RESERVED_CONTROL_FRAME_B = 0x0B, \
    WS_RESERVED_CONTROL_FRAME_C = 0x0C, \
    WS_RESERVED_CONTROL_FRAME_D = 0x0D, \
    WS_RESERVED_CONTROL_FRAME_E = 0x0E, \
    WS_RESERVED_CONTROL_FRAME_F = 0x0F

DEFINE_ENUM(WS_FRAME_TYPE, WS_FRAME_TYPE_VALUES);

MOCKABLE_FUNCTION(, int, uws_frame_encoder_encode, BUFFER_HANDLE, encode_buffer, unsigned char, opcode, const void*, payload, size_t, length, bool, is_masked, bool, is_final, unsigned char, reserved);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UWS_FRAME_ENCODER_H */
