#include "ecc.h"
#include "ecdsa.h"
#include "contiki.h"
#include "lib/random.h"
#include "net/rime.h"
#include "dev/button-sensor.h"
#include "dev/leds.h"

#include "messages.h"

#include <stdio.h> /* For printf() */
#include <string.h>
/*---------------------------------------------------------------------------*/
PROCESS ( bob_process, "Bob process" );
PROCESS ( startup_process, "Statup Process" );
AUTOSTART_PROCESSES ( &startup_process );
/*---------------------------------------------------------------------------*/

point_t pbkey_alice;
NN_DIGIT prKey_alice[NUMWORDS];

static struct energy_time last;
static struct energy_time diff;

static void abc_recv ( struct abc_conn *c );
static const struct abc_callbacks abc_call = {abc_recv};
static struct abc_conn abc;
/*---------------------------------------------------------------------------*/
static void
abc_recv ( struct abc_conn *c )
{
        msg_header_t * header;
        uint8_t *data;
        uint16_t data_len;
        char i;

        header = ( msg_header_t * ) ( packetbuf_dataptr() );
        data_len = ntoh_uint16 ( &header->data_len );

        data = ( uint8_t * ) ( header + 1 );

	printf("\nmessage received\n");
	for(i = 0; i < data_len; i++)
	{
		printf ( "%u:", data[i]);
	}
        printf ( "\n");

        ENERGEST_OFF ( ENERGEST_TYPE_CPU );
        ENERGEST_OFF ( ENERGEST_TYPE_LPM );
        ENERGEST_OFF ( ENERGEST_TYPE_TRANSMIT );
        ENERGEST_OFF ( ENERGEST_TYPE_LISTEN );
        ENERGEST_ON ( ENERGEST_TYPE_CPU );
        ENERGEST_ON ( ENERGEST_TYPE_LPM );
        ENERGEST_ON ( ENERGEST_TYPE_TRANSMIT );
        ENERGEST_ON ( ENERGEST_TYPE_LISTEN );
        last.cpu = energest_type_time ( ENERGEST_TYPE_CPU );
        last.lpm = energest_type_time ( ENERGEST_TYPE_LPM );
        last.transmit = energest_type_time ( ENERGEST_TYPE_TRANSMIT );
        last.listen = energest_type_time ( ENERGEST_TYPE_LISTEN );

        i = ecdsa_verify ( data, data_len, header->r, header->s, &pbkey_alice );

        diff.cpu = energest_type_time ( ENERGEST_TYPE_CPU ) - last.cpu;
        diff.lpm = energest_type_time ( ENERGEST_TYPE_LPM ) - last.lpm;
        diff.transmit = energest_type_time ( ENERGEST_TYPE_TRANSMIT ) - last.transmit;
        diff.listen = energest_type_time ( ENERGEST_TYPE_LISTEN ) - last.listen;

        if ( i==1 ) 
	{
                printf ( "Clock ticks recorded by\nCPU = %ld \nLPM = %ld \nTRANSMITTER = %ld\nRECEIVER = %ld\n",diff.cpu, diff.lpm, diff.transmit, diff.listen );
                leds_toggle ( LEDS_GREEN );
        } 
        else 
	{
                printf ( "unverified\n" );
                leds_toggle ( LEDS_RED );
        }
}

point_t gen_pubkey( NN_DIGIT *myPrvKey )
{
        point_t pubKey;

        ecc_gen_public_key ( &pubKey, myPrvKey );
	return pubKey;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD ( startup_process, ev, data )
{
        PROCESS_BEGIN();

        memset ( prKey_alice, 0, NUMWORDS*NN_DIGIT_LEN );
        prKey_alice[9] = 0x7b01;
        prKey_alice[8] = 0x2db7;
        prKey_alice[7] = 0x681a;
        prKey_alice[6] = 0x3f28;
        prKey_alice[5] = 0xb918;
        prKey_alice[4] = 0x5c8b;
        prKey_alice[3] = 0x2ac5;
        prKey_alice[2] = 0xd528;
        prKey_alice[1] = 0xdecd;
        prKey_alice[0] = 0x52da;

        ecc_init();
	pbkey_alice = gen_pubkey(prKey_alice);

        ecdsa_init ( &pbkey_alice );

        process_start ( &bob_process, NULL );

        printf ( "signature size %d\n", 2* ( NUMWORDS * NN_DIGIT_LEN ) );

        PROCESS_END();
}
/*---------------------------------------------------------------------------*/

PROCESS_THREAD ( bob_process, ev, data )
{
        PROCESS_EXITHANDLER ( abc_close ( &abc ); )
        PROCESS_BEGIN();

        abc_open ( &abc, 128, &abc_call );
        SENSORS_ACTIVATE ( button_sensor );
        while ( 1 ) 
	{
                PROCESS_WAIT_EVENT_UNTIL ( ev == sensors_event && data == &button_sensor );
        }


        PROCESS_END();
}
/*---------------------------------------------------------------------------*/
