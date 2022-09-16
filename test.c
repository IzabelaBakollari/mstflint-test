/*
 * Copyright (c) 2013-2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include "string.h"
#include <stdlib.h>
#include <errno.h>

/* #include "calc_hw_crc.h" */

u_int16_t crc16table2[256] = {
    0x0000, 0x1BA1, 0x3742, 0x2CE3, 0x6E84, 0x7525, 0x59C6, 0x4267,
    0xDD08, 0xC6A9, 0xEA4A, 0xF1EB, 0xB38C, 0xA82D, 0x84CE, 0x9F6F,
    0x1A01, 0x01A0, 0x2D43, 0x36E2, 0x7485, 0x6F24, 0x43C7, 0x5866,
    0xC709, 0xDCA8, 0xF04B, 0xEBEA, 0xA98D, 0xB22C, 0x9ECF, 0x856E,
    0x3402, 0x2FA3, 0x0340, 0x18E1, 0x5A86, 0x4127, 0x6DC4, 0x7665,
    0xE90A, 0xF2AB, 0xDE48, 0xC5E9, 0x878E, 0x9C2F, 0xB0CC, 0xAB6D,
    0x2E03, 0x35A2, 0x1941, 0x02E0, 0x4087, 0x5B26, 0x77C5, 0x6C64,
    0xF30B, 0xE8AA, 0xC449, 0xDFE8, 0x9D8F, 0x862E, 0xAACD, 0xB16C,
    0x6804, 0x73A5, 0x5F46, 0x44E7, 0x0680, 0x1D21, 0x31C2, 0x2A63,
    0xB50C, 0xAEAD, 0x824E, 0x99EF, 0xDB88, 0xC029, 0xECCA, 0xF76B,
    0x7205, 0x69A4, 0x4547, 0x5EE6, 0x1C81, 0x0720, 0x2BC3, 0x3062,
    0xAF0D, 0xB4AC, 0x984F, 0x83EE, 0xC189, 0xDA28, 0xF6CB, 0xED6A,
    0x5C06, 0x47A7, 0x6B44, 0x70E5, 0x3282, 0x2923, 0x05C0, 0x1E61,
    0x810E, 0x9AAF, 0xB64C, 0xADED, 0xEF8A, 0xF42B, 0xD8C8, 0xC369,
    0x4607, 0x5DA6, 0x7145, 0x6AE4, 0x2883, 0x3322, 0x1FC1, 0x0460,
    0x9B0F, 0x80AE, 0xAC4D, 0xB7EC, 0xF58B, 0xEE2A, 0xC2C9, 0xD968,
    0xD008, 0xCBA9, 0xE74A, 0xFCEB, 0xBE8C, 0xA52D, 0x89CE, 0x926F,
    0x0D00, 0x16A1, 0x3A42, 0x21E3, 0x6384, 0x7825, 0x54C6, 0x4F67,
    0xCA09, 0xD1A8, 0xFD4B, 0xE6EA, 0xA48D, 0xBF2C, 0x93CF, 0x886E,
    0x1701, 0x0CA0, 0x2043, 0x3BE2, 0x7985, 0x6224, 0x4EC7, 0x5566,
    0xE40A, 0xFFAB, 0xD348, 0xC8E9, 0x8A8E, 0x912F, 0xBDCC, 0xA66D,
    0x3902, 0x22A3, 0x0E40, 0x15E1, 0x5786, 0x4C27, 0x60C4, 0x7B65,
    0xFE0B, 0xE5AA, 0xC949, 0xD2E8, 0x908F, 0x8B2E, 0xA7CD, 0xBC6C,
    0x2303, 0x38A2, 0x1441, 0x0FE0, 0x4D87, 0x5626, 0x7AC5, 0x6164,
    0xB80C, 0xA3AD, 0x8F4E, 0x94EF, 0xD688, 0xCD29, 0xE1CA, 0xFA6B,
    0x6504, 0x7EA5, 0x5246, 0x49E7, 0x0B80, 0x1021, 0x3CC2, 0x2763,
    0xA20D, 0xB9AC, 0x954F, 0x8EEE, 0xCC89, 0xD728, 0xFBCB, 0xE06A,
    0x7F05, 0x64A4, 0x4847, 0x53E6, 0x1181, 0x0A20, 0x26C3, 0x3D62,
    0x8C0E, 0x97AF, 0xBB4C, 0xA0ED, 0xE28A, 0xF92B, 0xD5C8, 0xCE69,
    0x5106, 0x4AA7, 0x6644, 0x7DE5, 0x3F82, 0x2423, 0x08C0, 0x1361,
    0x960F, 0x8DAE, 0xA14D, 0xBAEC, 0xF88B, 0xE32A, 0xCFC9, 0xD468,
    0x4B07, 0x50A6, 0x7C45, 0x67E4, 0x2583, 0x3E22, 0x12C1, 0x0960
};

u_int16_t calc_hw_crc(u_int8_t *d, int size)
{
    int i;
    int table_index;

    //u_int8_t data[size];

    unsigned crc = 0xffff;
    for (i = 0; i < size; i++)
    {   
        //data[i] = d[i];
        if (i == 0 || i == 1) {
            d[i] = ~d[i];    
        }
        table_index = ((crc ^ d[i]) & 0xff);
        crc = ((crc >> 8) ^ crc16table2[table_index]);
    }
    crc = ((crc << 8) & 0xff00) | ((crc >> 8) & 0xff);

    return crc;
}

int main() {

    u_int8_t *table = (u_int8_t *) crc16table2;
    u_int8_t string[] = "Hello World";
    int crc = calc_hw_crc(table, sizeof(crc16table2));

    printf("return_1 is %d\n", crc);

    crc = calc_hw_crc(string, sizeof(string)-1);
    printf("return_2 is %d\n", crc);
    printf("string is %s\n", string);

    return 0;
}