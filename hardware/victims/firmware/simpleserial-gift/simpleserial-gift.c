/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

//#include "aes-independant.h"
#include "gift/crypto.h"
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
//#include <stdbool.h>

#define false 0
#define true  1

void gift_key(uint8_t *k);
void gift_mode(uint8_t* text);
void gift_encrypt(uint8_t* text);
void rotate_doubleword(uint8_t *t);


uint8_t get_mode(uint8_t* m)
{
    gift_mode(m);
    return 0x00;
}

uint8_t get_key(uint8_t* k)
{
    gift_key(k);
    return 0x00;
}

uint8_t get_pt(uint8_t* pt)
{
    // Rotate double-words (Do this before the trigger so that we are primarily
    // playing with clean data)
    rotate_doubleword(pt);

    /* Trigger calls have been moved to bracket the exact encryption calls */
    //trigger_high();

    #ifdef ADD_JITTER
    for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);
    #endif

    gift_encrypt(pt); /* encrypting the data block */

    //trigger_low();

    rotate_doubleword(pt);
    simpleserial_put('r', 16, pt);
    return 0x00;
}

uint8_t reset(uint8_t* x)
{
    // Reset key here if needed
    return 0x00;
}

int main(void)
{
    uint8_t tmp[KEY_LENGTH] = DEFAULT_KEY;

    platform_init();
    init_uart();
    trigger_setup();

    //aes_indep_init();
    //aes_indep_key(tmp);
    gift_key(tmp);

    /* Uncomment this to get a HELLO message for debug */

    putch('h');
    putch('e');
    putch('l');
    putch('l');
    putch('o');
    putch('\n');

    simpleserial_init();
    simpleserial_addcmd('k', 16,  get_key);
    simpleserial_addcmd('p', 16,   get_pt);
    simpleserial_addcmd('x',  0,    reset);
    simpleserial_addcmd('m',  2, get_mode);
    while(1)
        simpleserial_get();
}

// Some gift-specific functions that need to get moved to the gift crypto code
// at some point or some other location
// TODO

uint64_t *subkeys      = NULL;
_Bool     largeblocks  = false;  // false for 64-bit blocksize,
                                 // true for 128-bit blocks

/**
 * Sets the key for the gift encryption. Note that this uses 29/41 rounds to
 * match the default setting of the command-line tool
 */
void gift_key(uint8_t* k){

    // Rotate double-words to transform the input into the format the gift code
    // is expecting
    rotate_doubleword(k);

    //Cast to get in proper datatype
    uint64_t key_h = *((uint64_t *)k);
    uint64_t key_l = *((uint64_t *)(k + 8));

    if (largeblocks) {
        // 128-bit cypher mode
        subkeys = key_schedule128(key_h, key_l, 41, false);
    } else {
        // 64-bit cypher mode
        subkeys = key_schedule(key_h, key_l, 29, false, false);
    }
}

/**
 * Sets the cypher block size. *m should be falsy to set a 64-bit size, and
 * truthy for a 128-bit block size.
 */
void gift_mode(uint8_t *m){
    largeblocks = !!(*m);
}

/**
 * Wrapper function to perform the gift encryption. This allows for (reasonably)
 * transparent cryto size switches, if we choose to do this. Note that this uses
 * 29/41 rounds to match the default setting of the command-line tool
 *
 * Returns the result of the encryption in the text pointer.
 */
void gift_encrypt(uint8_t* t){
    uint64_t text[2] = {0};

    text[0] = *((uint64_t *)t);
    text[1] = *((uint64_t *)(t + 8));

    if (largeblocks) {
        // 128-bit cypher mode
        uint64_t *res = 0;

        trigger_high();
        res = encrypt128(text[0], text[1], subkeys, 41, false);
        trigger_low();

        *(uint64_t *)t       = res[0];
        *(uint64_t *)(t + 8) = res[1];
        free(res);  //Ouch, don't really want to malloc/free on ucontrollers :(

    } else {
        // 64-bit cypher mode
        trigger_high();
        *(uint64_t *)t       = encrypt(text[0], subkeys, 29, false);
        *(uint64_t *)(t + 8) = encrypt(text[1], subkeys, 29, false);
        trigger_low();
    }
}

/**
 * Takes an array of 16 bytes, and swaps the endianness of the two double-words
 * (uint64_t) that make up the array. It returns the result in the same array.
 */

void rotate_doubleword(uint8_t *t) {
    // Both the STM32 and the AVR XMEGA are little-endian devices, so the
    // big-endian byte transmission means that a simple cast will not translate
    // the array of bytes into the proper result. Thus, we preprocess first to
    // translate the byte array into the 64-bit datatypes the crypto code
    // expects, despite neither of the targets having 64-bit datapaths :P

    for (uint8_t i = 0; i < 4; i++) {
        uint8_t tmp;
        uint8_t inv = 7 - i;
        tmp         = t[i];
        t[i]        = t[inv];
        t[inv]      = tmp;

        tmp        = t[i + 8];
        t[i + 8]   = t[inv + 8];
        t[inv + 8] = tmp;
    }
}
