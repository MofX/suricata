#ifndef __SUPERFLOW_H__
#define __SUPERFLOW_H__

#define SUPERFLOW_MESSAGE_MAX_MESSAGES 8
#define SUPERFLOW_TIMEOUT 200
#define SUPERFLOW_MAX_LENGTH 2048

#define SUPERFLOW_MESSAGE_FLAG_OVERLENGTH 		1 << 0
#define SUPERFLOW_MESSAGE_FLAG_INUSE			1 << 1
#define SUPERFLOW_MESSAGE_FLAG_TOSERVER 		1 << 2
#define SUPERFLOW_MESSAGE_FLAG_TOCLIENT			1 << 3

#define SUPERFLOW_FLAG_MESSAGE_OVERFLOW			0x01

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
	SuperflowMessage msgs[SUPERFLOW_MESSAGE_MAX_MESSAGES];
	uint8_t	size;
} SuperflowMessages;

typedef struct SuperflowState_ {
	uint32_t	flags;
	uint32_t 	flow_flags;
	uint32_t 	tcpstream_flags;
	SuperflowData buffer_to_client;
	SuperflowData buffer_to_server;
	SuperflowMessages messages;
} SuperflowState;

struct Flow_; 

void SuperflowInitFlow(struct Flow_* flow);
void SuperflowFreeFlow(struct Flow_* flow);
void SuperflowRecycleFlow(struct Flow_* flow);

void SuperflowRegisterTests();

#endif //__SUPERFLOW_H__
