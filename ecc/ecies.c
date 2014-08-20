/**
 *
 * Suraj Neupane <neupanesuraj@gmail.com>, port to Contiki
 */

#include "ecc.h"
#include "ecies.h"
#include "ecc_sha1.h"

#include <stdlib.h>
#include <string.h>

point_t baseArray[NUM_POINTS];
#define TEST_VECTOR 1
void hmac_sha1 ( uint8_t *text, int text_len, uint8_t *key, int key_len, uint8_t *digest )
{
        SHA1Context context;
        uint8_t k_ipad[65];    /* inner padding -
			    * key XORd with ipad
			    */
        uint8_t k_opad[65];    /* outer padding -
			    * key XORd with opad
			    */
        uint8_t tk[20];
        int i;
        /* if key is longer than 64 bytes reset it to key=MD5(key) */
        if ( key_len > 64 ) {

                SHA1Context tctx;

                sha1_reset ( &tctx );
                sha1_update ( &tctx, key, key_len );
                sha1_digest ( &tctx, tk );

                key = tk;
                key_len = 20;
        }
        /*
             * the HMAC_SHA1 transform looks like:
             *
             * SHA1(K XOR opad, SHA1(K XOR ipad, text))
             *
             * where K is an n byte key
             * ipad is the byte 0x36 repeated 64 times

             * opad is the byte 0x5c repeated 64 times
             * and text is the data being protected
             */

        /* start out by storing key in pads */
        memcpy ( k_ipad, key, key_len );
        memset ( k_ipad + key_len, 0, 65 - key_len );
        memcpy ( k_opad, key, key_len );
        memset ( k_opad + key_len, 0, 65 - key_len );

        /* XOR key with ipad and opad values */
        for ( i=0; i<64; i++ ) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner SHA1
         */
        sha1_reset ( &context );                /* init context for 1st pass */
        sha1_update ( &context, k_ipad, 64 );   /* start with inner pad */
        sha1_update ( &context, text, text_len ); /* then text of datagram */
        sha1_digest ( &context, digest );       /* finish up 1st pass */
        /*
         * perform outer SHA1
         */
        sha1_reset ( &context );                /* init context for 2nd pass */
        sha1_update ( &context, k_opad, 64 );  /* start with outer pad */
        sha1_update ( &context, digest, 20 );
        sha1_digest ( &context, digest );      /* then results of 1st hash */

}

int ecc_encrypt ( uint8_t *Ce, uint16_t C_len, uint8_t *Me, uint16_t M_len, point_t *publicKey )
{
        NN_DIGIT k[NUMWORDS];
        uint8_t z[KEYDIGITS*NN_DIGIT_LEN];
        point_t R, P;
        uint16_t octet_len;
        uint8_t K[41 + SHA1HashSize];
        uint16_t i;
#ifdef POINT_COMPRESS
        if ( C_len < KEYDIGITS*NN_DIGIT_LEN+1+SHA1HashSize )
                return -1;
#else
        if ( C_len < 2*KEYDIGITS*NN_DIGIT_LEN+1+SHA1HashSize )
                return -1;
#endif

#ifdef TEST_VECTOR
#ifdef EIGHT_BIT_PROCESSOR
        k[20] = 0x0;
        k[19] = 0x7b;
        k[18] = 0x01;
        k[17] = 0x2d;
        k[16] = 0xb7;
        k[15] = 0x68;
        k[14] = 0x1a;
        k[13] = 0x3f;
        k[12] = 0x28;
        k[11] = 0xb9;
        k[10] = 0x18;
        k[9] = 0x5c;
        k[8] = 0x8b;
        k[7] = 0x2a;
        k[6] = 0xc5;
        k[5] = 0xd5;
        k[4] = 0x28;
        k[3] = 0xde;
        k[2] = 0xcd;
        k[1] = 0x52;
        k[0] = 0xda;
#elif defined(SIXTEEN_BIT_PROCESSOR)
        k[10] = 0x0;
        k[9] = 0x7b01;
        k[8] = 0x2db7;
        k[7] = 0x681a;
        k[6] = 0x3f28;
        k[5] = 0xb918;
        k[4] = 0x5c8b;
        k[3] = 0x2ac5;
        k[2] = 0xd528;
        k[1] = 0xdecd;
        k[0] = 0x52da;
#elif defined(THIRTYTWO_BIT_PROCESSOR)
        k[5] = 0x0;
        k[4] = 0x7b012db7;
        k[3] = 0x681a3f28;
        k[2] = 0xb9185c8b;
        k[1] = 0x2ac5d528;
        k[0] = 0xdecd52da;
#endif
#else
        ecc_gen_private_key ( k );
#endif
        ecc_gen_public_key ( &R, k );

#ifdef POINT_COMPRESS
        octet_len = ecc_point2octet ( Ce, C_len, &R );
#else  //no point compression
        octet_len = ecc_point2octet ( Ce, C_len, &R );
#endif
        //3. derive shared secret z=P.x
#ifdef SLIDING_WIN
        ecc_win_precompute ( publicKey, baseArray );
        ecc_win_mul ( &P, k, baseArray );
#else  //SLIDING_WIN
        ecc_mul ( &P, publicKey, k );
#endif  //SLIDING_WIN

        if ( p_iszero ( &P ) )
                return -1;

        //4. convert z to octet string Z
        NN_Encode ( z, KEYDIGITS*NN_DIGIT_LEN, P.x, NUMWORDS );

        //5. use KDF to generate K of length enckeylen + mackeylen octets from Z
        //enckeylen = M_len, mackeylen = 20
        KDF ( K, M_len+SHA1HashSize, z );

        //6. the left most enckeylen octets of K is EK, right most mackeylen octets is MK

        //7. encrypt EM
        for ( i=0; i<M_len; i++ ) {
                Ce[octet_len+i] = Me[i] ^ K[i];
        }

        //8. generate mac D
        hmac_sha1 ( Ce + octet_len, M_len, K + M_len, SHA1HashSize, Ce + octet_len + M_len );

        //9. output C = R||EM||D
        return ( octet_len + M_len + SHA1HashSize );
}

void KDF(uint8_t *Kee, int K_len, uint8_t *Zee)
{
        int len, i;
        uint8_t z[KEYDIGITS*NN_DIGIT_LEN+4];
        SHA1Context ctx;
        uint8_t sha1sum[20];

        memcpy ( z, Zee, KEYDIGITS*NN_DIGIT_LEN );
        memset ( z + KEYDIGITS*NN_DIGIT_LEN, 0, 3 );

        len = K_len;
        i = 1;
        while ( len > 0 ) {
                z[KEYDIGITS*NN_DIGIT_LEN + 3] = i;
                sha1_reset ( &ctx );
                sha1_update ( &ctx, z, KEYDIGITS*NN_DIGIT_LEN+4 );
                sha1_digest ( &ctx, sha1sum );
                if ( len >= 20 ) {
                        memcpy ( Kee+ ( i-1 ) *20, sha1sum, 20 );
                } else {
                        memcpy ( Kee+ ( i-1 ) *20, sha1sum, len );
                }
                i++;
                len = len - 20;
        }
}

int ecc_decrypt ( uint8_t *Me, int M_len, uint8_t *Ce, int C_len, NN_DIGIT *d )
{
        uint8_t z[KEYDIGITS*NN_DIGIT_LEN];
        point_t R, P;
        int octet_len;
        uint8_t K[41 + SHA1HashSize];
        int i;
        uint8_t hmac_tmp[SHA1HashSize];

        octet_len = ecc_octet2point ( &R, Ce, C_len );

        if ( ecc_check_point ( &R ) != 1 ) {
                return -1;
        }

        //4. use private key to generate shared secret z
#ifdef SLIDING_WIN
        ecc_win_precompute ( &R, baseArray );
        ecc_win_mul ( &P, d, baseArray );
#else  //SLIDING_WIN
        ecc_mul ( &P, &R, d );
#endif  //SLIDING_WIN

        if ( p_iszero ( &P ) ) {
                return -1;
        }

        //5. convert z to octet string Z
        NN_Encode ( z, KEYDIGITS*NN_DIGIT_LEN, P.x, NUMWORDS );

        //6. use KDF to derive EK and MK
        KDF ( K, C_len - octet_len, z );

        //7. check D first
        if ( M_len < C_len - SHA1HashSize - octet_len )
                return -1;
        M_len = C_len - SHA1HashSize - octet_len;
        hmac_sha1 ( Ce + octet_len, M_len, K + M_len, SHA1HashSize, hmac_tmp );

        for ( i=0; i<SHA1HashSize; i++ ) {
                if ( hmac_tmp[i] != Ce[octet_len + M_len + i] ) {
                        return -2;
                }
        }

        //8. decrypt
        for ( i=0; i<M_len; i++ ) {
                Me[i] = Ce[octet_len+i] ^ K[i];
        }
        return M_len;
}
