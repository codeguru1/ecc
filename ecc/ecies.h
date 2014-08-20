/**
 *
 * Suraj Neupane <neupanesuraj@gmail.com>, port to Contiki
 */

#ifndef _ecies_h
#define _ecies_h

#include "nn.h"
#include "ecc.h"
int ecc_encrypt ( uint8_t *cipher, uint16_t cipher_len, uint8_t *message, uint16_t message_len, point_t *publiccKey );
void KDF ( uint8_t *k, int k_len, uint8_t *z );
int ecc_decrypt(uint8_t *message, int message_len, uint8_t *cipher, int cipher_len, NN_DIGIT *d);

#endif
