#ifndef __SUPERFLOW_H__
#define __SUPERFLOW_H__

#define SUPERFLOW_NUM_NESSAGES 8
#define SUPERFLOW_TIMEOUT 200
#define SUPERFLOW_MAX_LENGTH 2048

#define SUPERFLOW_MESSAGE_FLAG_OVERLENGTH 	0x01
#define SUPERFLOW_MESSAGE_FLAG_TOSERVER 	0x04
#define SUPERFLOW_MESSAGE_FLAG_TOCLIENT		0x08

typedef struct SuperflowData_ {
	uint8_t		*buffer;
	uint32_t 	capacity;
	uint32_t 	size;
	uint32_t 	posRead;
} SuperflowData;

typedef struct SuperflowMessage_ {
	uint8_t		*buffer;
	uint32_t	capacity;
	uint32_t	size;
	uint8_t		flags;
	struct timeval	last_update;
	struct timeval	first_update;
} SuperflowMessage;

typedef struct SuperflowMessages_ {
	SuperflowMessage msgs[SUPERFLOW_NUM_NESSAGES];
	uint8_t	size;
} SuperflowMessages;

typedef struct SuperflowState_ {
	uint32_t 	flow_flags;
	uint32_t 	tcpstream_flags;
	SuperflowData buffer_to_client;
	SuperflowData buffer_to_server;
	SuperflowMessages messages;
} SuperflowState;

#endif //__SUPERFLOW_H__
