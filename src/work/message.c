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

FlowMessage* MessageGetCurrent(FlowMessages *sms) {
	if (sms->size == 0 || sms->size == FLOW_MESSAGE_MAX_MESSAGES + 1) {
		return NULL;
	} else {
		FlowMessage *cur = &sms->msgs[sms->size - 1];
		cur->flags |= SUPERFLOW_MESSAGE_FLAG_INUSE;
		return cur;
	}
}

FlowMessage* MessageGetNext(SuperflowState *sst) {
	FlowMessages *sms = &sst->messages;
	if (sms->size == FLOW_MESSAGE_MAX_MESSAGES + 1) {
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
			entropy += f * log(f);
		}
		entropy = -entropy / log(256);


		// Add to superflow

		sm->sflow_message->entropy = entropy * 200;
		sm->sflow_message->length = sm->size;
		sm->sflow_message->time = sm->first_update.tv_sec * 1000 + sm->first_update.tv_usec / 1000;
		sm->sflow_message->flags = sm->flags;
	}

	sm->flags |= SUPERFLOW_MESSAGE_FLAG_FINISHED;
	/*free(sm->buffer);
	sm->buffer = NULL;
	sm->capacity = 0;
	sm->size = 0;*/
}

void MessageAdd(Packet *p, uint8_t * data, uint32_t data_len, uint8_t flags) {
	SuperflowState *sst = &p->flow->superflow_state;
	FlowMessages *sms = &sst->messages;
	FlowMessage *sm = MessageGetCurrent(sms);
	if (!sm) {
		sm = MessageGetNext(sst);
	}
	if (!sm) {
		sst->flags |= SUPERFLOW_FLAG_MESSAGE_OVERFLOW;
		return;
	}

	struct timeval diff;
	timersub(&p->ts, &sm->last_update, &diff);
	uint32_t diff_ms = diff.tv_usec / 1000 + diff.tv_sec * 1000;

	const uint8_t dirflags = SUPERFLOW_MESSAGE_FLAG_TOCLIENT | SUPERFLOW_MESSAGE_FLAG_TOSERVER;
	//printf("dirflags: %u, diff_ms: %u\n", (sm->flags & dirflags), diff_ms);
	if ((sm->flags & dirflags) && (((sm->flags & dirflags) != (flags & dirflags))
			|| (diff_ms > SUPERFLOW_MESSAGE_TIMEOUT) || (flags & STREAM_EOF))) {
		//printf("New message\n");
		MessageFinalize(sms, sm);
		sm = MessageGetNext(sst);
	}
	if (!sm) {
		sst->flags |= SUPERFLOW_FLAG_MESSAGE_OVERFLOW;
		return;
	}

	if (!(sm->flags & dirflags)) {
		sm->flags |= flags & dirflags;
		sm->first_update = p->ts;
	}
	if (!data_len) return;

	sm->last_update= p->ts;

	if (sm->capacity - sm->size < data_len) {
		uint32_t size = sm->size + data_len;
		if (size > SUPERFLOW_MESSAGE_MAX_LENGTH) {
			size = SUPERFLOW_MESSAGE_MAX_LENGTH;
			data_len = size - sm->size;
			sm->flags |= SUPERFLOW_MESSAGE_FLAG_OVERLENGTH;
		}

		if (size > sm->capacity) {
			//printf("Reallocating message buffer from %u to %u\n", sm->capacity, size);
			sm->buffer = realloc(sm->buffer, size);
			sm->capacity = size;
		}
	}
	if (!data_len) return;

	memcpy(sm->buffer + sm->size, data, data_len);
	sm->size += data_len;
}

int MessageTest01() {
	FlowInitConfig(1);
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	memset(&p, 0, sizeof(p));

	FLOW_INITIALIZE(&f);
	char buffer[256];

	p.flow = &f;

	MessageAdd(&p, "a", 1, STREAM_TOSERVER);
	MessageAdd(&p, "b", 1, STREAM_TOSERVER);
	MessageAdd(&p, "c", 1, STREAM_TOSERVER);
	MessageAdd(&p, "defghi", 6, STREAM_TOSERVER);

	p.ts.tv_usec = 1000 * (SUPERFLOW_MESSAGE_TIMEOUT + 5);
	MessageAdd(&p, "jkl", 3, STREAM_TOSERVER);
	MessageAdd(&p, "a", 1, STREAM_TOSERVER);

	MessageAdd(&p, "a", 1, STREAM_TOCLIENT);
	MessageAdd(&p, "bcde", 4, STREAM_TOCLIENT);

	if (msgs->msgs[0].size != 9 || strncmp(msgs->msgs[0].buffer, "abcdefghi", 9) != 0) {
		memset(buffer, 0, 256);
		memcpy(buffer, msgs->msgs[0].buffer, msgs->msgs[0].size);
		printf("Message one != \"abcdefghi\", is: \"%s\"(%u bytes)\n", buffer, msgs->msgs[0].size);
		goto error;
	}

	if (!(msgs->msgs[0].flags & SUPERFLOW_MESSAGE_FLAG_TOSERVER) || (msgs->msgs[0].flags & SUPERFLOW_MESSAGE_FLAG_TOCLIENT)) {
		printf("Message one is not to server!\n");
		goto error;
	}

	if (msgs->msgs[1].size != 4 || strncmp(msgs->msgs[1].buffer, "jkla", 4) != 0) {
		memset(buffer, 0, 256);
		memcpy(buffer, msgs->msgs[1].buffer, msgs->msgs[1].size);
		printf("Message two != \"jkla\", is: \"%s\"(%u bytes)\n", buffer, msgs->msgs[1].size);
		goto error;
	}

	if (!(msgs->msgs[1].flags & SUPERFLOW_MESSAGE_FLAG_TOSERVER) || (msgs->msgs[1].flags & SUPERFLOW_MESSAGE_FLAG_TOCLIENT)) {
		printf("Message two is not to server!\n");
		goto error;

	}

	if (msgs->msgs[2].size != 5 || strncmp(msgs->msgs[2].buffer, "abcde", 5) != 0) {
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
	return r;
}

int MessageTest02() {
	FlowInitConfig(1);
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	memset(&p, 0, sizeof(p));

	FLOW_INITIALIZE(&f);
	char buffer[SUPERFLOW_MESSAGE_MAX_LENGTH + 1];

	p.flow = &f;

	MessageAdd(&p, buffer, SUPERFLOW_MESSAGE_MAX_LENGTH, STREAM_TOSERVER);
	MessageAdd(&p, buffer, SUPERFLOW_MESSAGE_MAX_LENGTH + 1, STREAM_TOCLIENT);

	if (msgs->msgs[0].size != SUPERFLOW_MESSAGE_MAX_LENGTH || (msgs->msgs[0].flags & SUPERFLOW_MESSAGE_FLAG_OVERLENGTH)) {
		printf("Message one has wrong length or overlength flag set\n");
		goto error;
	}

	if (msgs->msgs[1].size != SUPERFLOW_MESSAGE_MAX_LENGTH || !(msgs->msgs[1].flags & SUPERFLOW_MESSAGE_FLAG_OVERLENGTH)) {
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
	return r;
}

int MessageTest03() {
	FlowInitConfig(1);
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	memset(&p, 0, sizeof(p));

	FLOW_INITIALIZE(&f);

	p.flow = &f;

	for (uint8_t i = 0; i < FLOW_MESSAGE_MAX_MESSAGES + 1; ++i) {
		char buffer[20];
		sprintf(buffer, "%u", i);
		MessageAdd(&p, buffer, 1, i % 2 ? STREAM_TOSERVER : STREAM_TOCLIENT);
	}

	for (uint8_t i = 0; i < FLOW_MESSAGE_MAX_MESSAGES; ++i) {
		char buffer[10];
		sprintf(buffer, "%u", i);

		if (msgs->msgs[i].size != 1 || strncmp(msgs->msgs[i].buffer, buffer, 1) != 0) {
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
	return r;
}

int MessageTest04() {
	uint32_t x[1024];
	FlowInitConfig(1);
	Packet p;
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
	memset(&p, 0, sizeof(Packet));
	memset(&f, 0, sizeof(Flow));
	FLOW_INITIALIZE(&f);

	p.flow = &f;

	MessageAdd(&p, "1", 1, STREAM_TOSERVER);

	p.ts.tv_usec += 1000 * (SUPERFLOW_MESSAGE_TIMEOUT - 1);

	MessageAdd(&p, "2", 1, STREAM_TOSERVER);

	p.ts.tv_usec += 1000 * (SUPERFLOW_MESSAGE_TIMEOUT - 1);

	MessageAdd(&p, "3", 1, STREAM_TOSERVER);

	p.ts.tv_usec += 1000 * (SUPERFLOW_MESSAGE_TIMEOUT);

	MessageAdd(&p, "4", 1, STREAM_TOSERVER);

	if (strncmp(f.superflow_state.messages.msgs[0].buffer, "1234", 4) != 0) {
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
	return r;
}

void MessageRegisterTests() {
	UtRegisterTest("MessageTest1", MessageTest01, 0);
	UtRegisterTest("MessageTest2", MessageTest02, 0);
	UtRegisterTest("MessageTest3", MessageTest03, 0);
	UtRegisterTest("MessageTest4", MessageTest04, 0);
}
