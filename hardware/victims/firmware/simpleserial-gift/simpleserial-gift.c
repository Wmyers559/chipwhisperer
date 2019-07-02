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

#define GIFT64
//#define GIFT128

void gift_key(uint8_t *k);
void gift_encrypt(uint8_t* text);

/**
 * TODO:
 * Implement switchable cypher modes using the get_mode command, maybe reuse the
 * get_mask command to change the number of rounds?
 */

uint8_t get_mask(uint8_t* m)
{
    //aes_indep_mask(m);
    return 0x00;
}

uint8_t get_key(uint8_t* k)
{
    gift_key(k);
    return 0x00;
}

uint8_t get_pt(uint8_t* pt)
{
    trigger_high();

    #ifdef ADD_JITTER
    for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);
    #endif
    //uint8_t tmp[16] = {0xba,0xdc,0x0f,0xfe,0xeb,0xad,0xf0,0x0d,0xba,0xdc,0x0f,0xfe,0xeb,0xad,0xf0,0x0d};

    //simpleserial_put('r', 16, pt);
    gift_encrypt(pt); /* encrypting the data block */

    trigger_low();
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
    simpleserial_addcmd('k', 16, get_key);
    simpleserial_addcmd('p', 16,  get_pt);
    simpleserial_addcmd('x',  0,   reset);
    simpleserial_addcmd('m', 18, get_mask);
    while(1)
        simpleserial_get();
}

// Some gift-specific functions that need to get moved to the gift crypto code
// at some point
// TODO

uint64_t *subkeys = NULL;

/**
 * Sets the key for the gift encryption
 */
void gift_key(uint8_t* k){

    // Rotate double-words to transform the input into the format the gift code
    // is expecting
    for (uint8_t i = 0; i < 4; i++) {
        uint8_t tmp;
        uint8_t inv = 7 - i;
        tmp         = k[i];
        k[i]        = k[inv];
        k[inv]      = tmp;

        tmp        = k[i + 8];
        k[i + 8]   = k[inv + 8];
        k[inv + 8] = tmp;
    }

    //Cast to get in proper datatype
    uint64_t key_h = *((uint64_t *)k);
    uint64_t key_l = *((uint64_t *)(k + 8));

#ifdef GIFT128
    subkeys = key_schedule128(key_h, key_l, 41, false);
#else
    subkeys = key_schedule(key_h, key_l, 29, false, false);
#endif
}


/**
 * Wrapper function to perform the gift encryption. This allows for (reasonably)
 * transparent cryto size switches, if we choose to do this.
 *
 * Returns the result of the encryption in the text pointer.
 */
void gift_encrypt(uint8_t* t){
    // Both the STM32 and the AVR XMEGA are little-endian devices, so the
    // big-endian byte transmission means that a simple cast will not translate
    // the array of bytes into the proper result. Thus, we preprocess first to
    // translate the byte array into the 64-bit datatypes the crypto code
    // expects, despite neither of the targets having 64-bit datapaths :P
    uint64_t text[2] = {0};

    //Compiler bug?! ugh, it thinks it's ub, so..... :( (This is for
    // `arm-none-eabi`)
    //text_h = (t[7] << 56) | (t[6] << 48) | (t[5] << 40) | (t[4] << 32) | (t[3] << 24) | (t[2] << 16) | (t[1] << 8) | t[0];

    // This works, for ARM, but avr-gcc complains mightily
    /*
    //uint32_t tt[4];
    tt[1] = (t[0]  << 24) | (t[1]  << 16) | (t[2]  << 8) | t[3];
    tt[0] = (t[4]  << 24) | (t[5]  << 16) | (t[6]  << 8) | t[7];
    tt[3] = (t[8]  << 24) | (t[9]  << 16) | (t[10] << 8) | t[11];
    tt[2] = (t[12] << 24) | (t[13] << 16) | (t[14] << 8) | t[15];

    text[0] = *((uint64_t *)tt);
    text[1] = *((uint64_t *)(tt + 2));
    */

    // Rotate double-words
    ///*
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

    text[0] = *((uint64_t *)t);
    text[1] = *((uint64_t *)(t + 8));


#ifdef GIFT128
    uint64_t *res = 0;
    res = encrypt128(text[0], text[1], subkeys, 41, false);

    *(uint64_t *)t       = res[0];
    *(uint64_t *)(t + 8) = res[1];
    free(res);  //Ouch, don't really want to malloc/free on ucontrollers :(

#else
     *(uint64_t *)t       = encrypt(text[0], subkeys, 28, false);
     *(uint64_t *)(t + 8) = encrypt(text[1], subkeys, 28, false);
#endif

    // And now the other way, to make the other end happy
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
