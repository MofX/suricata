/**
 * \file
 * \author Jörg Vehlow <fh@jv-coder.de>
 *
 *This file contains all functions regarding superflow message parsing.
 */

#include "suricata-common.h"

#include <math.h>

#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-private.h"
#include "flow.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-print.h"
#include "util-profiling.h"
#include "util-validate.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "work/superflow.h"
#include "work/message.h"

/**
 * Returns the current message.
 * Returns NULL if no more messages are available.
 */
FlowMessage* MessageGetCurrent(FlowMessages *sms) {
	if (sms->size == 0 || sms->size == SUPERFLOW_MESSAGE_COUNT + 1) {
		return NULL;
	} else {
		FlowMessage *cur = &sms->msgs[sms->size - 1];
		cur->flags |= SUPERFLOW_MESSAGE_FLAG_INUSE;
		return cur;
	}
}

/**
 * Returns the next message and increments the message counter.
 * Returns NULL if no more messages are available.
 */
FlowMessage* MessageGetNext(SuperflowState *sst) {
	FlowMessages *sms = &sst->messages;
	if (sms->size == SUPERFLOW_MESSAGE_COUNT + 1) {
		return NULL;
	} else {
		sms->size++;
		FlowMessage *sm = MessageGetCurrent(sms);
		if (sm) {
			sm->sflow_message = SuperflowGetNextMessage(sst);
		}
		return sm;
	}
}

/**
 * Finalizes a message. This is done, when a new message is created or the stream is closed.
 * If a superflows message is assoziated with this message, the entropy gets ccalculated and
 * all data in the superflow message get set.
 */
void MessageFinalize(FlowMessages *sms, FlowMessage *sm) {
	if (sm->sflow_message) {
		float entropy = 0;
		uint32_t entropy_counter[256];

		memset(entropy_counter, 0, 256 * sizeof(uint32_t));
		for (uint32_t i = 0; i < sm->size; ++i) {
			entropy_counter[sm->buffer[i]]++;
		}

		for (uint32_t i = 0; i < 256; ++i) {
			if (entropy_counter[i] == 0) continue;
			float f = ((float)entropy_counter[i]) / sm->size;
			entropy += f * log2(f);
		}
		entropy = -entropy / log2(256);


		// Add to superflow

		sm->sflow_message->entropy = entropy * 255;
		sm->sflow_message->length = sm->size;
		sm->sflow_message->time = sm->first_update.tv_sec * 1000 + sm->first_update.tv_usec / 1000;
		sm->sflow_message->flags = sm->flags;
	}

	sm->flags |= SUPERFLOW_MESSAGE_FLAG_FINALIZED;
	/*free(sm->buffer);
	sm->buffer = NULL;
	sm->capacity = 0;
	sm->size = 0;*/
}

/**
 * Adds some content to the current message.
 * If the direction changed or a timeout occured, a new message is created and the
 * current one is finalized.
 */
void MessageAdd(Packet *p, uint8_t * data, uint32_t data_len, uint8_t flags) {
	SuperflowState *sst = &p->flow->superflow_state;
	FlowMessages *sms = &sst->messages;
	FlowMessage *sm = MessageGetCurrent(sms);
	// If no current message: This is the first message
	if (!sm) {
		sm = MessageGetNext(sst);
	}
	// If no current message: No more free messages available
	if (!sm) {
		sst->flags |= SUPERFLOW_FLAG_MESSAGE_OVERFLOW;
		return;
	}

	struct timeval diff;
	timersub(&p->ts, &sm->last_update, &diff);
	uint32_t diff_ms = diff.tv_usec / 1000 + diff.tv_sec * 1000;
	const uint8_t dirflags = SUPERFLOW_MESSAGE_FLAG_TOCLIENT | SUPERFLOW_MESSAGE_FLAG_TOSERVER;
	//printf("dirflags: %u, diff_ms: %u\n", (sm->flags & dirflags), diff_ms);

	// Check if direction flag is set (no new message) and if direction differs from current direction
	// or if message timed out.
	if ((sm->flags & dirflags) && (((sm->flags & dirflags) != (flags & dirflags))
			|| (diff_ms > g_superflow_message_timeout) || (flags & STREAM_EOF))) {
		// Finalize and get next message
		MessageFinalize(sms, sm);
		sm = MessageGetNext(sst);
	}

	// If no current message: No more free messages available
	if (!sm) {
		sst->flags |= SUPERFLOW_FLAG_MESSAGE_OVERFLOW;
		return;
	}

	// If no direction flag is set, this is a new message
	if (!(sm->flags & dirflags)) {
		sm->flags |= flags & dirflags;
		sm->first_update = p->ts;
	}
	if (!data_len) return;

	sm->last_update = p->ts;

	uint32_t bytes_to_write = data_len;
	// Resize the buffer to fit the new data
	if (sm->capacity - sm->size < bytes_to_write) {
		uint32_t size = sm->size + bytes_to_write;
		if (size > g_superflow_message_max_length) {
			size = g_superflow_message_max_length;
			bytes_to_write = size - sm->size;
			sm->flags |= SUPERFLOW_MESSAGE_FLAG_OVERLENGTH;
		}

		if (size > sm->capacity) {
			//printf("Reallocating message buffer from %u to %u\n", sm->capacity, size);
			sm->buffer = realloc(sm->buffer, size);
			if (!sm->buffer) {
				printf("Realloc failed\n");
				exit(-1);
			}
			sm->capacity = size;
		}
	}

	if (!bytes_to_write) return;

	memcpy(sm->buffer + sm->size, data, bytes_to_write);
	sm->size += bytes_to_write;
}

/**
 * This function gets called when a flow gets freed by suricata.
 * It finalizes all messages
 */
void MessageSuperflowFinalize(SuperflowState *sfs) {
	if (!sfs->superflow) return;

	for (uint32_t i = 0; i < sfs->messages.size; ++i) {
		if ((sfs->messages.msgs[i].flags & (SUPERFLOW_MESSAGE_FLAG_TOCLIENT | SUPERFLOW_MESSAGE_FLAG_TOSERVER)) && !(sfs->messages.msgs[i].flags & SUPERFLOW_MESSAGE_FLAG_FINALIZED)) {
			MessageFinalize(&sfs->messages, &sfs->messages.msgs[i]);
		}
	}
}

/**
 * Called when a stream ends. It just finalizes the current message
 */
void MessageOnStreamEnd(Packet *p) {
	if (!p->flow) return;
	SuperflowState *sfs = &p->flow->superflow_state;

	FlowMessage *msg = MessageGetCurrent(&sfs->messages);
	if (msg && msg->size && ! (msg->flags & SUPERFLOW_MESSAGE_FLAG_FINALIZED)) {
		MessageFinalize(&sfs->messages, msg);
	}
}

/**
 * Test basic AddMessage
 */
int MessageTest01() {
	FlowInitConfig(1);
	SuperflowInit(1);
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	memset(&p, 0, sizeof(p));

	FLOW_INITIALIZE(&f);
	char buffer[256];

	p.flow = &f;

	MessageAdd(&p, (uint8_t*)"a", 1, STREAM_TOSERVER);
	MessageAdd(&p, (uint8_t*)"b", 1, STREAM_TOSERVER);
	MessageAdd(&p, (uint8_t*)"c", 1, STREAM_TOSERVER);
	MessageAdd(&p, (uint8_t*)"defghi", 6, STREAM_TOSERVER);

	p.ts.tv_usec = 1000 * (g_superflow_message_timeout + 5);
	MessageAdd(&p, (uint8_t*)"jkl", 3, STREAM_TOSERVER);
	MessageAdd(&p, (uint8_t*)"a", 1, STREAM_TOSERVER);

	MessageAdd(&p, (uint8_t*)"a", 1, STREAM_TOCLIENT);
	MessageAdd(&p, (uint8_t*)"bcde", 4, STREAM_TOCLIENT);

	if (msgs->msgs[0].size != 9 || strncmp((char*)msgs->msgs[0].buffer, "abcdefghi", 9) != 0) {
		memset(buffer, 0, 256);
		memcpy(buffer, msgs->msgs[0].buffer, msgs->msgs[0].size);
		printf("Message one != \"abcdefghi\", is: \"%s\"(%u bytes)\n", buffer, msgs->msgs[0].size);
		goto error;
	}

	if (!(msgs->msgs[0].flags & SUPERFLOW_MESSAGE_FLAG_TOSERVER) || (msgs->msgs[0].flags & SUPERFLOW_MESSAGE_FLAG_TOCLIENT)) {
		printf("Message one is not to server!\n");
		goto error;
	}

	if (msgs->msgs[1].size != 4 || strncmp((char*)msgs->msgs[1].buffer, "jkla", 4) != 0) {
		memset(buffer, 0, 256);
		memcpy(buffer, msgs->msgs[1].buffer, msgs->msgs[1].size);
		printf("Message two != \"jkla\", is: \"%s\"(%u bytes)\n", buffer, msgs->msgs[1].size);
		goto error;
	}

	if (!(msgs->msgs[1].flags & SUPERFLOW_MESSAGE_FLAG_TOSERVER) || (msgs->msgs[1].flags & SUPERFLOW_MESSAGE_FLAG_TOCLIENT)) {
		printf("Message two is not to server!\n");
		goto error;

	}

	if (msgs->msgs[2].size != 5 || strncmp((char*)msgs->msgs[2].buffer, "abcde", 5) != 0) {
		memset(buffer, 0, 256);
		memcpy(buffer, msgs->msgs[2].buffer, msgs->msgs[2].size);
		printf("Message three != \"abcde\", is: \"%s\"(%u bytes)\n", buffer, msgs->msgs[2].size);
		goto error;
	}
	if (!(msgs->msgs[2].flags & SUPERFLOW_MESSAGE_FLAG_TOCLIENT) || (msgs->msgs[2].flags & SUPERFLOW_MESSAGE_FLAG_TOSERVER)) {
		printf("Message three is not to client!\n");
		goto error;
	}

	if (f.superflow_state.flags & SUPERFLOW_FLAG_MESSAGE_OVERFLOW) {
		printf("Message overflow set!\n");
		goto error;
	}


	int r = 0;
	goto end;
error:
	r = -1;
end:
	SuperflowFree();
	FlowShutdown();
	return r;
}

/**
 * test overlength flag
 */
int MessageTest02() {
	FlowInitConfig(1);
	SuperflowInit(1);
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	memset(&p, 0, sizeof(p));

	FLOW_INITIALIZE(&f);
	uint8_t buffer[g_superflow_message_max_length + 1];

	p.flow = &f;

	MessageAdd(&p, buffer, g_superflow_message_max_length, STREAM_TOSERVER);
	MessageAdd(&p, buffer, g_superflow_message_max_length + 1, STREAM_TOCLIENT);

	if (msgs->msgs[0].size != g_superflow_message_max_length || (msgs->msgs[0].flags & SUPERFLOW_MESSAGE_FLAG_OVERLENGTH)) {
		printf("Message one has wrong length or overlength flag set\n");
		goto error;
	}

	if (msgs->msgs[1].size != g_superflow_message_max_length || !(msgs->msgs[1].flags & SUPERFLOW_MESSAGE_FLAG_OVERLENGTH)) {
		printf("Message two has wrong length or overlength flag not set\n");
		goto error;
	}

	if (f.superflow_state.flags & SUPERFLOW_FLAG_MESSAGE_OVERFLOW) {
		printf("Message overflow set!\n");
		goto error;
	}

	int r = 0;
	goto end;
error:
	r = -1;
end:
	SuperflowFree();
	FlowShutdown();
	return r;
}

/**
 * Test overflow flag
 */
int MessageTest03() {
	FlowInitConfig(1);
	SuperflowInit(1);
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	memset(&p, 0, sizeof(p));

	FLOW_INITIALIZE(&f);

	p.flow = &f;

	for (uint8_t i = 0; i < SUPERFLOW_MESSAGE_COUNT + 1; ++i) {
		uint8_t buffer[20];
		sprintf((char*)buffer, "%u", i);
		MessageAdd(&p, buffer, 1, i % 2 ? STREAM_TOSERVER : STREAM_TOCLIENT);
	}

	for (uint8_t i = 0; i < SUPERFLOW_MESSAGE_COUNT; ++i) {
		char buffer[10];
		sprintf(buffer, "%u", i);

		if (msgs->msgs[i].size != 1 || strncmp((char*)msgs->msgs[i].buffer, buffer, 1) != 0) {
			printf("Message %u has wrong size or buffer\n", i);
			goto error;
		}
	}

	if (!(f.superflow_state.flags & SUPERFLOW_FLAG_MESSAGE_OVERFLOW)) {
		printf("Message overflow not set!\n");
		goto error;
	}

	int r = 0;
	goto end;
error:
	r = -1;
end:
	FLOW_DESTROY(&f);
	FlowShutdown();
	SuperflowFree();
	return r;
}

/**
 * Test timeout
 */
int MessageTest04() {
	FlowInitConfig(1);
	SuperflowInit(1);
	Packet p;
	Flow f;
	memset(&p, 0, sizeof(Packet));
	memset(&f, 0, sizeof(Flow));
	FLOW_INITIALIZE(&f);

	p.flow = &f;

	MessageAdd(&p, (uint8_t*)"1", 1, STREAM_TOSERVER);

	p.ts.tv_usec += 1000 * (g_superflow_message_timeout - 1);

	MessageAdd(&p, (uint8_t*)"2", 1, STREAM_TOSERVER);

	p.ts.tv_usec += 1000 * (g_superflow_message_timeout - 1);

	MessageAdd(&p, (uint8_t*)"3", 1, STREAM_TOSERVER);

	p.ts.tv_usec += 1000 * (g_superflow_message_timeout);

	MessageAdd(&p, (uint8_t*)"4", 1, STREAM_TOSERVER);

	if (strncmp((char*)f.superflow_state.messages.msgs[0].buffer, "1234", 4) != 0) {
		printf("Buffer is not \"1234\"\n");
		goto error;
	}

	int r = 0;
	goto end;
error:
	r = -1;
end:
	r = 0;
	FLOW_DESTROY(&f);
	FlowShutdown();
	SuperflowFree();
	return r;
}

void MessageRegisterTests() {
	UtRegisterTest("MessageTest1", MessageTest01, 0);
	UtRegisterTest("MessageTest2", MessageTest02, 0);
	UtRegisterTest("MessageTest3", MessageTest03, 0);
	UtRegisterTest("MessageTest4", MessageTest04, 0);
}
