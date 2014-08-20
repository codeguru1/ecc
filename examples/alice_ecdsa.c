#include "ecc.h"
#include "ecdsa.h"
#include "contiki.h"
#include "messages.h"
#include "lib/random.h"
#include "net/rime.h"
#include "dev/button-sensor.h"
#include "dev/leds.h"

#include <stdio.h> /* For printf() */
#include <string.h>
/*---------------------------------------------------------------------------*/
PROCESS ( alice_ecdsa_process, "Alice Ecdsa process" );
PROCESS ( startup_process, "Statup Process" );
AUTOSTART_PROCESSES ( &startup_process );
/*---------------------------------------------------------------------------*/

point_t pbkey_alice;
NN_DIGIT prKey_alice[NUMWORDS];

static struct energy_time last;
static struct energy_time diff;

static void abc_recv ( struct abc_conn* c );
static const struct abc_callbacks abc_call = {abc_recv};
static struct abc_conn abc;

static void abc_recv ( struct abc_conn* c )
{
;
}

point_t gen_pubkey( NN_DIGIT *myPrvKey )
{
        point_t pubKey;

        ecc_gen_public_key ( &pubKey, myPrvKey );
	return pubKey;
}

/*---------------------------------------------------------------------------*/
static void random_data ( void* ptr, uint16_t len )
{
        uint16_t i;

        for ( i=0; i<len; i++ ) 
	{
                ( ( uint8_t* ) ( ptr ) ) [i] = random_rand() % 100;
        }

}
/*---------------------------------------------------------------------------*/

static void bacast_signed_message()
{
        msg_header_t* header;
        uint8_t* data;
        packetbuf_clear();
        header = ( msg_header_t* ) ( packetbuf_dataptr() );
        data = ( uint8_t* ) ( header + 1 );

        random_data ( data, MSG_LEN );

        hton_uint16 ( &header->data_len, MSG_LEN );

	static struct etimer nrg;
	energest_flush();
        ENERGEST_ON ( ENERGEST_TYPE_LPM );
        ENERGEST_ON ( ENERGEST_TYPE_TRANSMIT );
        ENERGEST_ON ( ENERGEST_TYPE_LISTEN );
        ENERGEST_ON ( ENERGEST_TYPE_CPU );
        last.cpu = energest_type_time ( ENERGEST_TYPE_CPU )/RTIMER_SECOND;
        ENERGEST_OFF ( ENERGEST_TYPE_CPU );
        last.lpm = energest_type_time ( ENERGEST_TYPE_LPM );
        last.transmit = energest_type_time ( ENERGEST_TYPE_TRANSMIT );
        last.listen = energest_type_time ( ENERGEST_TYPE_LISTEN );
        ENERGEST_ON ( ENERGEST_TYPE_CPU );

        ecdsa_sign ( data, MSG_LEN, header->r, header->s, prKey_alice );

        diff.cpu = energest_type_time ( ENERGEST_TYPE_CPU ) - last.cpu;
        diff.lpm = energest_type_time ( ENERGEST_TYPE_LPM ) - last.lpm;
        diff.transmit = energest_type_time ( ENERGEST_TYPE_TRANSMIT ) - last.transmit;
        diff.listen = energest_type_time ( ENERGEST_TYPE_LISTEN ) - last.listen;

        ENERGEST_OFF ( ENERGEST_TYPE_CPU );
        ENERGEST_OFF ( ENERGEST_TYPE_LPM );
        ENERGEST_OFF ( ENERGEST_TYPE_TRANSMIT );
        ENERGEST_OFF ( ENERGEST_TYPE_LISTEN );

        packetbuf_set_datalen ( sizeof ( msg_header_t ) + MSG_LEN );
        abc_send ( &abc );
	printf ( "Clock ticks recorded by\nCPU = %ld \nLPM = %ld \nTRANSMITTER = %ld\nRECEIVER = %ld\n",diff.cpu, diff.lpm, diff.transmit, diff.listen );
}

PROCESS_THREAD ( alice_ecdsa_process, ev, data )
{
        PROCESS_EXITHANDLER ( abc_close ( &abc ); )
        PROCESS_BEGIN();
        abc_open ( &abc, 128, &abc_call );
        SENSORS_ACTIVATE ( button_sensor );

        while ( 1 ) 
	{
                PROCESS_WAIT_EVENT_UNTIL ( ( ev==sensors_event ) && ( data == &button_sensor ) );
                bacast_signed_message();
        }

        PROCESS_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD ( startup_process, ev, data )
{
        PROCESS_BEGIN();

        memset ( prKey_alice, 0, NUMWORDS*NN_DIGIT_LEN );
        memset ( pbkey_alice.x, 0, NUMWORDS*NN_DIGIT_LEN );
        memset ( pbkey_alice.y, 0, NUMWORDS*NN_DIGIT_LEN );

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
        process_start ( &alice_ecdsa_process, NULL );
        PROCESS_END();
}
