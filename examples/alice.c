#include "ecc.h"
#include "ecies.h"
#include "contiki.h"
#include "messages.h"
#include "lib/random.h"
#include "net/rime.h"
#include "dev/button-sensor.h"
#include "dev/leds.h"

#include <stdio.h> /* For printf() */
#include <string.h>

/*
#define RX 21.8
#define TX 19.5
#define CPU 1.8
#define IDLE  0.0545
#define TICKS 8192
#define VOLT 3
*/
/*---------------------------------------------------------------------------*/
PROCESS ( alice_process, "Alice process" );
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

}

point_t public_key_gen( NN_DIGIT *myPrvKey )
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
	//private key here is used to generate public key only. for encrypting public key is used
	//in practice public key must be readily available to alice.
	pbkey_alice = public_key_gen(prKey_alice);
        process_start ( &alice_process, NULL );
        PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static void
random_data ( void* ptr, uint16_t len )
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
	mst_t send_msg;
	int i;
        uint8_t data[MSG_LEN];
	uint8_t cipher[64];
	int size;
        packetbuf_clear();
	printf("message \n");
        random_data ( data, MSG_LEN );
	for(i = 0; i < MSG_LEN; i++)
	{
		printf("%u:", data[i]);
	}
	printf("\ncipher message \n");
	
        ENERGEST_OFF ( ENERGEST_TYPE_CPU );
        ENERGEST_OFF ( ENERGEST_TYPE_LPM );
        ENERGEST_OFF ( ENERGEST_TYPE_TRANSMIT );
        ENERGEST_OFF ( ENERGEST_TYPE_LISTEN );
        ENERGEST_ON ( ENERGEST_TYPE_CPU );
        ENERGEST_ON ( ENERGEST_TYPE_LPM );
        ENERGEST_ON ( ENERGEST_TYPE_TRANSMIT );
        ENERGEST_ON ( ENERGEST_TYPE_LISTEN );

        last.lpm = energest_type_time ( ENERGEST_TYPE_LPM );
        last.transmit = energest_type_time ( ENERGEST_TYPE_TRANSMIT );
        last.listen = energest_type_time ( ENERGEST_TYPE_LISTEN );
	last.cpu = energest_type_time ( ENERGEST_TYPE_CPU );

	size = ecc_encrypt( cipher, 66, data, MSG_LEN, &pbkey_alice);

        diff.cpu = energest_type_time ( ENERGEST_TYPE_CPU ) - last.cpu;
        diff.lpm = energest_type_time ( ENERGEST_TYPE_LPM ) - last.lpm;
        diff.transmit = energest_type_time ( ENERGEST_TYPE_TRANSMIT ) - last.transmit;
        diff.listen = energest_type_time ( ENERGEST_TYPE_LISTEN ) - last.listen;
	
	for(i = 0; i < size; i++)
	{
		printf("%u:", cipher[i]);
		send_msg.dat[i] = cipher[i];
		send_msg.len = size;
	}
	printf("done\n");
	packetbuf_copyfrom ( &send_msg, sizeof(send_msg) );
        abc_send ( &abc );

        printf ( "Clock ticks recorded by\nCPU = %ld \nLPM = %ld \nTRANSMITTER = %ld\nRECEIVER = %ld\n",diff.cpu, diff.lpm, diff.transmit, diff.listen );
}

/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
PROCESS_THREAD ( alice_process, ev, data )
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
