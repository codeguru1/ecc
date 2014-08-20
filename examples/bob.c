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
PROCESS ( bob_process, "Bob process" );
PROCESS ( startup_process, "Statup Process" );
AUTOSTART_PROCESSES ( &startup_process );
/*---------------------------------------------------------------------------*/

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
	mst_t *rcv_msg;
	uint8_t decrypted[MSG_LEN];
	int j, i;
        rcv_msg = packetbuf_dataptr();
	printf("\nmessage received\n");
	for(i = 0; i < rcv_msg->len; i++)
	{
		printf ( "%u:", rcv_msg->dat[i]);
	}
	printf("\n");
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
	
	j = ecc_decrypt(decrypted, MSG_LEN, rcv_msg->dat, rcv_msg->len, prKey_alice);
	
        diff.cpu = energest_type_time ( ENERGEST_TYPE_CPU ) - last.cpu;
        diff.lpm = energest_type_time ( ENERGEST_TYPE_LPM ) - last.lpm;
        diff.transmit = energest_type_time ( ENERGEST_TYPE_TRANSMIT ) - last.transmit;
        diff.listen = energest_type_time ( ENERGEST_TYPE_LISTEN ) - last.listen;
        if ( j > 0 ) {
                printf ( "\nDecrypted data\n" );
                for ( i =0; i < MSG_LEN; i++ ) {
                        printf ( "%u:", decrypted[i] );
                }
                printf ( "\n" );

                printf ( "Clock ticks recorded by\nCPU = %ld \nLPM = %ld \nTRANSMITTER = %ld\nRECEIVER = %ld\n",diff.cpu, diff.lpm, diff.transmit, diff.listen );
        }
        else
	{
		printf("couldn't decrypt\n");
	}
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

        process_start ( &bob_process, NULL );
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
