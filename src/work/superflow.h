#ifndef __SUPERFLOW_H__
#define __SUPERFLOW_H__

#include "superflow-hash.h"

#define FLOW_MESSAGE_MAX_MESSAGES 10
#define SUPERFLOW_TIMEOUT 200
#define SUPERFLOW_MAX_LENGTH 2048

#define SUPERFLOW_MESSAGE_COUNT 8
#define SUPERFLOW_MEMORY 1024 * 1024 * 1

#define SUPERFLOW_MESSAGE_FLAG_OVERLENGTH 		1 << 0
#define SUPERFLOW_MESSAGE_FLAG_INUSE			1 << 1
#define SUPERFLOW_MESSAGE_FLAG_TOSERVER 		1 << 2
#define SUPERFLOW_MESSAGE_FLAG_TOCLIENT			1 << 3

#define SUPERFLOW_FLAG_MESSAGE_OVERFLOW			0x01

#define SUPERFLOW_COUNT ((int)(SUPERFLOW_MEMORY / sizeof(Superflow)))
#define SUPERFLOW_MEMORY_REAL SUPERFLOW_COUNT * sizeof(Superflow)

typedef struct SuperflowMessage_ {
	int time;
	unsigned char length[2];
	unsigned char entropy[2];
} SuperflowMessage;

union SuperflowKey_ {
	struct {
		uint32_t srvr;
		uint32_t clnt;
	};
	uint64_t key;
};

typedef struct Superflow_ {
	union SuperflowKey_ addrs;

	uint16_t refCount;			// The reference count
	uint16_t messageCount;		// The number of messages recorded already (may be a uint8_t)

	struct SuperflowMessage_ msgs[SUPERFLOW_MESSAGE_COUNT];

	struct UT_hash_handle_ hh;
} Superflow;

typedef struct FlowBuffer_ {
	uint8_t		*buffer;
	uint32_t 	capacity;
	uint32_t 	size;
	uint32_t 	posRead;
} FlowBuffer;

typedef struct FlowMessage_ {
	uint8_t		*buffer;
	uint32_t	capacity;
	uint32_t	size;
	uint8_t		flags;
	struct timeval	last_update;
	struct timeval	first_update;
} FlowMessage;

typedef struct FlowMessages_ {
	FlowMessage msgs[FLOW_MESSAGE_MAX_MESSAGES];
	uint8_t	size;
} FlowMessages;

typedef struct SuperflowState_ {
	uint32_t	flags;
	uint32_t 	flow_flags;
	uint32_t 	tcpstream_flags;
	FlowBuffer buffer_to_client;
	FlowBuffer buffer_to_server;
	FlowMessages messages;
	struct Superflow_ *superflow;
} SuperflowState;

extern Superflow *g_superflows;
extern uint32_t g_superflow_used_count;
extern struct UT_hash_table_ *g_superflow_hashtable;

struct Flow_;
struct Packet_;

void SuperflowInit(char silent);
void SuperflowFree();

void SuperflowHandlePacket(struct Packet_* p);

void SuperflowInitFlow(struct Flow_* flow);
void SuperflowFreeFlow(struct Flow_* flow);
void SuperflowRecycleFlow(struct Flow_* flow);

void SuperflowRegisterTests();

#endif //__SUPERFLOW_H__
