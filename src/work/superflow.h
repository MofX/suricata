/**
 * \file
 * \author Jörg Vehlow <fh@jv-coder.de>
 *
 *
 */
#ifndef __SUPERFLOW_H__
#define __SUPERFLOW_H__

#include "superflow-hash.h"

// The Maximum number of messages in superflow and flow
#define SUPERFLOW_MESSAGE_COUNT 8

#define SUPERFLOW_MESSAGE_FLAG_OVERLENGTH 		1 << 0		// Length is greater than g_superflow_message_max_length
#define SUPERFLOW_MESSAGE_FLAG_INUSE			1 << 1		// Message is used
#define SUPERFLOW_MESSAGE_FLAG_TOSERVER 		1 << 2		// Message is to server
#define SUPERFLOW_MESSAGE_FLAG_TOCLIENT			1 << 3		// Message is from server
#define SUPERFLOW_MESSAGE_FLAG_FINALIZED		1 << 4		// Message is finalized

#define SUPERFLOW_FLAG_MESSAGE_OVERFLOW			0x01

// Timeout of messages in ms
extern uint32_t g_superflow_message_timeout;
// Maximum length of messages
extern uint32_t g_superflow_message_max_length;

// The number of reserved superflows
extern uint32_t g_superflow_count;
// The memory used for reserved superflows
extern uint32_t s_superflow_memory_real;
// The maximum memory allowed for reserved superflows
extern uint32_t g_superflow_memory;

/**
 * One message in the superflow
 */
typedef struct SuperflowMessage_ {
	uint32_t time;		// The time the first packet of the message arrived
	uint16_t length;	// The length of the message (capped to g_superflow_message_max_length)
	uint8_t flags;		// Flags of the message (SUPERFLOW_MESSAGE_FLAG_*)
	uint8_t entropy;	// The normalized entropy(0 - 1) of the message multiplied by 255 (not 256 -> (char)1 * 256 == 0)
} SuperflowMessage;

/**
 * Struct defining the key for use in the hash
 */
union SuperflowKey_ {
	struct {
		uint32_t srvr;
		uint32_t clnt;
	};
	uint64_t key;
};

/**
 * Superflow
 */
typedef struct Superflow_ {
	union SuperflowKey_ addrs;	// The key (the source and destination addresses)

	uint16_t refCount;			// The reference count
	uint16_t messageCount;		// The number of messages recorded already (may be a uint8_t)

	struct SuperflowMessage_ msgs[SUPERFLOW_MESSAGE_COUNT];  // The messages of the superflow

	struct UT_hash_handle_ hh;	// The handled used for the hashmap
} Superflow;

/**
 * Buffer used in the applayer wrapper to buffer the incoming data
 */
typedef struct FlowBuffer_ {
	uint8_t		*buffer;
	uint32_t 	capacity;
	uint32_t 	size;
	uint32_t 	posRead;
} FlowBuffer;

/**
 * One message stored in the flow
 */
typedef struct FlowMessage_ {
	uint8_t		*buffer;				// The data of the message
	uint32_t	capacity;				// The current capacity of the buffer
	uint16_t	size;					// The size of the data
	uint8_t		flags;					// Flags SUPERFLOW_MESSAGE_FLAG_*
	SuperflowMessage *sflow_message;	// The associated superflow message
	struct timeval	last_update;		// The time of the first packet
	struct timeval	first_update;		// The time of the las packet
} FlowMessage;

/**
 * Struct holding the messages stored in the flow
 */
typedef struct FlowMessages_ {
	FlowMessage msgs[SUPERFLOW_MESSAGE_COUNT];	// The messages
	uint8_t	size;								// The number of used messages
} FlowMessages;

/**
 * The superflow helper structure stored in all flows.
 */
typedef struct SuperflowState_ {
	uint8_t	flags;						// Flags:SUPERFLOW_FLAG_MESSAGE_*

	// Used by the applayer wrapper
	uint16_t 	tcpstream_flags;		// Backuped tcpstream flags
	uint32_t 	flow_flags;				// Backuped flow flags
	FlowBuffer buffer_to_client;		// Buffer for data to client
	FlowBuffer buffer_to_server;		// Buffer for data to server

	FlowMessages messages;				// The flow messages struct
	struct Superflow_ *superflow;		// The associated superflow
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
float SuperflowGetEntropy(struct SuperflowMessage_ *sfm);

void SuperflowRegisterTests();

SuperflowMessage * SuperflowGetNextMessage(SuperflowState * sfs);

#endif //__SUPERFLOW_H__
