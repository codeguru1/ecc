#ifndef __MESSAGES_H__
#define __MESSAGES_H__

#include "nn.h"

#define MSG_LEN 8

typedef struct {
 unsigned char data[2]; 
} nw_uint16_t;

typedef struct msg_header 
{
  NN_DIGIT r[NUMWORDS];
  NN_DIGIT s[NUMWORDS];
  nw_uint16_t data_len; 
} msg_header_t;

struct energy_time {
	unsigned short source;
	long cpu;
	long lpm;
	long transmit;
	long listen;
};

typedef struct message
{
	uint8_t dat[64];
	uint16_t len;
} mst_t;


inline uint16_t hton_uint16(void * target, uint16_t value);

inline uint16_t ntoh_uint16(void * source);


#endif /* __MESSAGES_H__ */
