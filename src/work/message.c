#include "suricata-common.h"

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

SuperflowMessage* MessageGetCurrent(SuperflowMessages *sms) {
	if (sms->size == SUPERFLOW_NUM_NESSAGES) {
		return NULL;
	} else {
		return &(sms->msgs[sms->size]);
	}

}

void MessageFinalize(SuperflowMessages *sms, SuperflowMessage *sm) {
	// Calculate stuff
	// Add to superflow
	// Free memory?
	++sms->size;
}

void MessageAdd(Packet *p, uint8_t * data, uint32_t data_len, uint8_t flags) {
	SuperflowState *sst = &p->flow->superflow_state;
	SuperflowMessages *sms = &sst->messages;
	SuperflowMessage *sm = MessageGetCurrent(sms);
	if (!sm) return;

	struct timeval diff;
	timersub(&p->ts, &sm->last_update, &diff);
	uint32_t diff_ms = diff.tv_usec / 1000 + diff.tv_sec * 1000;

	const uint8_t dirflags = SUPERFLOW_MESSAGE_FLAG_TOCLIENT | SUPERFLOW_MESSAGE_FLAG_TOSERVER;
	//printf("dirflags: %u, diff_ms: %u\n", (sm->flags & dirflags), diff_ms);
	if ((sm->flags & dirflags) && (((sm->flags & dirflags) != (flags & dirflags))
			|| (diff_ms > SUPERFLOW_TIMEOUT) || (flags & STREAM_EOF))) {
		//printf("New message\n");
		MessageFinalize(sms, sm);
		sm = MessageGetCurrent(sms);
		if (!sm) return;
	}
	if (!(sm->flags & dirflags)) {
		sm->flags |= flags & dirflags;
		sm->first_update = p->ts;
	}
	if (!data_len) return;

	sm->last_update= p->ts;

	if (sm->capacity - sm->size < data_len) {
		uint32_t size = sm->size + data_len;
		printf("Reallocating buffer: %u\n", size);
		if (size > SUPERFLOW_MAX_LENGTH) {
			size = SUPERFLOW_MAX_LENGTH;
			data_len = size - sm->size;
			sm->flags |= SUPERFLOW_MESSAGE_FLAG_OVERLENGTH;
		}

		sm->buffer = realloc(sm->buffer, size);
		sm->capacity = size;
	}
	if (!data_len) return;

	memcpy(sm->buffer + sm->size, data, data_len);
	sm->size += data_len;
}

int MessageTest01() {
	FlowInitConfig(1);
	Flow *f = FlowAlloc();
	SuperflowMessages *msgs = &f->superflow_state.messages;
	Packet p;

	char buffer[256];

	p.ts.tv_usec = 0;
	p.flow = f;

	MessageAdd(&p, "a", 1, STREAM_TOSERVER);
	MessageAdd(&p, "b", 1, STREAM_TOSERVER);
	MessageAdd(&p, "c", 1, STREAM_TOSERVER);
	MessageAdd(&p, "defghi", 6, STREAM_TOSERVER);

	p.ts.tv_usec = 1000 * (SUPERFLOW_TIMEOUT + 5);
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


	int r = 0;
	goto end;
error:
	r = -1;
	FlowFree(f);
end:
	return r;
}

int MessageTest02() {
	FlowInitConfig(1);
	Flow *f = FlowAlloc();
	SuperflowMessages *msgs = &f->superflow_state.messages;
	Packet p;

	char buffer[SUPERFLOW_MAX_LENGTH + 1];

	p.ts.tv_usec = 0;
	p.flow = f;

	MessageAdd(&p, buffer, SUPERFLOW_MAX_LENGTH, STREAM_TOSERVER);
	MessageAdd(&p, buffer, SUPERFLOW_MAX_LENGTH + 1, STREAM_TOCLIENT);

	if (msgs->msgs[0].size != SUPERFLOW_MAX_LENGTH || (msgs->msgs[0].flags & SUPERFLOW_MESSAGE_FLAG_OVERLENGTH)) {
		printf("Message one has wrong length or overlength flag set\n");
		goto error;
	}

	if (msgs->msgs[1].size != SUPERFLOW_MAX_LENGTH || !(msgs->msgs[1].flags & SUPERFLOW_MESSAGE_FLAG_OVERLENGTH)) {
		printf("Message two has wrong length or overlength flag not set\n");
		goto error;
	}

	int r = 0;
	goto end;
error:
	r = -1;
	FlowFree(f);
end:
	return r;
}

int MessageTest03() {
	FlowInitConfig(1);
	Flow *f = FlowAlloc();
	SuperflowMessages *msgs = &f->superflow_state.messages;
	Packet p;

	p.ts.tv_usec = 0;
	p.flow = f;

	for (uint8_t i = 0; i < SUPERFLOW_NUM_NESSAGES + 1; ++i) {
		char buffer[2];
		sprintf(buffer, "%u", i);
		MessageAdd(&p, buffer, 1, i % 2 ? STREAM_TOSERVER : STREAM_TOCLIENT);
	}

	for (uint8_t i = 0; i < SUPERFLOW_NUM_NESSAGES; ++i) {
		char buffer[2];
		sprintf(buffer, "%u", i);

		if (msgs->msgs[i].size != 1 || strncmp(msgs->msgs[i].buffer, buffer, 1) != 0) {
			printf("Message %u has wrong size or buffer\n", i);
			goto error;
		}
	}

	int r = 0;
	goto end;
error:
	r = -1;
	FlowFree(f);
end:
	return r;
}

void MessageRegisterTests() {
	UtRegisterTest("MessageTest1", MessageTest01, 0);
	UtRegisterTest("MessageTest2", MessageTest02, 0);
	UtRegisterTest("MessageTest3", MessageTest03, 0);
}
