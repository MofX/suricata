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
#include "work/superflow-applayer-wrapper.h"
#include "work/message.h"

void SuperflowInitFlow(Flow* flow) {
	memset(&flow->superflow_state, 0, sizeof(SuperflowState));
	//printf("Init flow: %llx\n", flow);
}

void SuperflowFreeFlow(Flow* flow) {
	//printf("Free flow: %llx\n", flow);
	free(flow->superflow_state.buffer_to_client.buffer);
	free(flow->superflow_state.buffer_to_server.buffer);
	for (uint8_t i = 0; i < SUPERFLOW_MESSAGE_MAX_MESSAGES; ++i) {
		free(flow->superflow_state.messages.msgs[i].buffer);
	}
}

void SuperflowRecycleFlow(Flow* flow) {
	SuperflowFreeFlow(flow);
	SuperflowInitFlow(flow);
}

int SuperflowTest01() {
	FlowInitConfig(1);
	Flow f;
	SuperflowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	AlpProtoDetectThreadCtx dp_ctx;
	TcpSession ssn;

	FLOW_INITIALIZE(&f);

	p.flow = &f;

	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, "a", 1, STREAM_START | STREAM_TOSERVER);

	if (msgs->size != 1) {
		printf("Expected one message in use\n");
		goto error;
	}

	int r = 0;
	goto end;
error:
	r = -1;
end:
	return r;
}

int SuperflowTest02() {
	FlowInitConfig(1);
	Flow f;
	SuperflowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	AlpProtoDetectThreadCtx dp_ctx;
	TcpSession ssn;

	FLOW_INITIALIZE(&f);

	uint8_t *buffer_to_server = "GET / HTTP/1.0\nContent-length: -1\n\n";

	f.flags |= FLOW_IPV4;

	p.src.address.address_un_data32[0] = 0x12345678;
	p.dst.address.address_un_data32[0] = 0x87654321;
	p.flow = &f;
	f.protoctx = &ssn;

	AlpProtoFinalize2Thread(&dp_ctx);

	for (uint32_t i = 0; i < SUPERFLOW_MESSAGE_MAX_MESSAGES; ++i) {
		uint8_t buffer[256];
		sprintf(buffer, "%u", i);
		uint8_t flags = 0;
		uint8_t * b = buffer;
		uint32_t len = strlen(buffer);

		if (i == 0) {
			flags |= STREAM_START;
			b = buffer_to_server;
			len = strlen(buffer_to_server);
		}

		flags |= (i % 2) ? STREAM_TOCLIENT : STREAM_TOSERVER;
		SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, b, len, flags);
	}

	if (msgs->size != SUPERFLOW_MESSAGE_MAX_MESSAGES) {
		printf("Expected %u message in use, but was: %u\n", SUPERFLOW_MESSAGE_MAX_MESSAGES, msgs->size);
		goto error;
	}

	if (f.flags & FLOW_NO_APPLAYER_INSPECTION) {
		printf("FLOW_NO_APPLAYER_INSPECTION shouldn't be set\n");
		goto error;
	}

	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, "x", 1, (SUPERFLOW_MESSAGE_MAX_MESSAGES % 2) ? STREAM_TOCLIENT : STREAM_TOSERVER);

	if (!(f.flags & FLOW_NO_APPLAYER_INSPECTION)) {
		printf("FLOW_NO_APPLAYER_INSPECTION should be set\n");
		goto error;
	}

	int r = 0;
	goto end;
error:
	r = -1;
end:
	AlpProtoDeFinalize2Thread(&dp_ctx);
	return r;
}

int SuperflowTest03() {
	FlowInitConfig(1);
	Flow f;
	SuperflowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	AlpProtoDetectThreadCtx dp_ctx;
	TcpSession ssn;

	FLOW_INITIALIZE(&f);

	uint8_t *buffer_to_server = "GET / HTTP/1.0\nContent-length: -1\n\n";

	f.flags |= FLOW_IPV4;

	p.src.address.address_un_data32[0] = 0x12345678;
	p.dst.address.address_un_data32[0] = 0x87654321;
	p.flow = &f;
	f.protoctx = &ssn;

	AlpProtoFinalize2Thread(&dp_ctx);

	char buffer[4096];


	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, 2048, STREAM_START | STREAM_TOSERVER);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, 2048, STREAM_TOSERVER);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, 2048, STREAM_TOSERVER);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, 2048, STREAM_TOSERVER);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, 4096, STREAM_TOCLIENT);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, 2048, STREAM_TOCLIENT);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, 2048, STREAM_TOCLIENT);

	int r = 0;
	goto end;
error:
	r = -1;
end:
	AlpProtoDeFinalize2Thread(&dp_ctx);
	return r;
}

void SuperflowRegisterTests() {
	UtRegisterTest("SuperflowTest1", SuperflowTest01, 0);
	UtRegisterTest("SuperflowTest2", SuperflowTest02, 0);
	UtRegisterTest("SuperflowTest3", SuperflowTest03, 0);
}
