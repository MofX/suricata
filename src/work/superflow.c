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

Superflow *g_superflows = NULL;
struct UT_hash_table_ *g_superflow_hashtable = NULL;;
uint32_t g_superflow_used_count = 0;

Superflow* SuperflowFromHeap();
Superflow* SuperflowFromHash();
void SuperflowAttachToFlow(Packet* packet);
void SuperflowTouch(Superflow* sflow);

void SuperflowHandlePacket(Packet* p) {
	if (!g_superflow_hashtable) return;
	if (!p->flow) return;

	if (!FLOW_IS_IPV4(p->flow)) return;


	if (!p->flow->superflow_state.superflow) {
		SuperflowAttachToFlow(p);
	} else {
		SuperflowTouch(p->flow->superflow_state.superflow);
	}
}

void SuperflowTouch(Superflow* sflow) {
	superflow_hash_touch(g_superflow_hashtable, sflow);
}

void SuperflowAttachToFlow(Packet* packet) {
	Flow * flow = packet->flow;
	union SuperflowKey_ key;

	key.srvr = flow->dst.address.address_un_data32[0];
	key.clnt = flow->src.address.address_un_data32[0];

	Superflow* sflow = NULL;

	sflow = superflow_hash_find_by_key(g_superflow_hashtable, &key);

	if (sflow == NULL) {
		sflow = SuperflowFromHeap();

		if (sflow == NULL) {
			sflow = SuperflowFromHash();
		}

		if (sflow == NULL) {
			printf("Error: Can't get free Superflow\n");
			return;
		}

		memset(sflow, 0, sizeof(Superflow));
//		sflow->messageCount = 0;
//		memset(&sflow->msgs, 0, 8 * sizeof(SuperflowMessage));
//		sflow->refCount = 0;
		sflow->addrs.key = key.key;
		superflow_hash_add(g_superflow_hashtable, sflow);
	} else {
		SuperflowTouch(sflow);
	}

	++sflow->refCount;
	flow->superflow_state.superflow = sflow;
}

void SuperflowInit(char silent) {
	if (g_superflows) {
		printf("Superflows is not NULL, SuperflowInit called twice?\n");
		exit(-1);
	}
	if (!silent) {
		printf("Allocating %u bytes of memory for %u superflows\n", SUPERFLOW_MEMORY_REAL, SUPERFLOW_COUNT);
	}
	g_superflows = malloc(SUPERFLOW_MEMORY_REAL);
	if (!g_superflows) {
		printf("Allocating superflows failed\n");
		exit(-1);
	}

	g_superflow_hashtable = superflow_hash_new(g_superflows);
}

void SuperflowFree() {
	Superflow *sflow = NULL;

	while ((sflow = superflow_hash_get_head(g_superflow_hashtable))) {
		superflow_hash_del(g_superflow_hashtable, sflow);
	}

	superflow_hash_free(g_superflow_hashtable);

	free(g_superflows);

	g_superflows = NULL;
	g_superflow_hashtable = NULL;
	g_superflow_used_count = 0;
}

void SuperflowInitFlow(Flow* flow) {
	memset(&flow->superflow_state, 0, sizeof(SuperflowState));
	//printf("Init flow: %llx\n", flow);
}

void SuperflowFreeFlow(Flow* flow) {
	//printf("Free flow: %llx\n", flow);
	free(flow->superflow_state.buffer_to_client.buffer);
	free(flow->superflow_state.buffer_to_server.buffer);
	for (uint8_t i = 0; i < FLOW_MESSAGE_MAX_MESSAGES; ++i) {
		free(flow->superflow_state.messages.msgs[i].buffer);
	}

	if (flow->superflow_state.superflow) {
		--flow->superflow_state.superflow->refCount;
	}
}

void SuperflowRecycleFlow(Flow* flow) {
	SuperflowFreeFlow(flow);
	SuperflowInitFlow(flow);
}

Superflow* SuperflowFromHeap() {
	if (g_superflow_used_count == SUPERFLOW_COUNT) return NULL;
	return &g_superflows[g_superflow_used_count++];
}

Superflow* SuperflowFromHash() {
	Superflow* sflow = superflow_hash_get_head(g_superflow_hashtable);
	if (!sflow) return NULL;

	while (sflow != NULL && sflow->refCount > 0) {
		sflow = superflow_hash_next(g_superflow_hashtable, sflow);
	}

	if (sflow) {
		superflow_hash_del(g_superflow_hashtable, sflow);
	}

	return sflow;
}

int SuperflowTest01() {
	FlowInitConfig(1);
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	AlpProtoDetectThreadCtx dp_ctx;
	TcpSession ssn;

	FLOW_INITIALIZE(&f);

	p.flow = &f;

	SuperflowInit(1);

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
	SuperflowFree();
	return r;
}

int SuperflowTest02() {
	FlowInitConfig(1);
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
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

	SuperflowInit(1);
	AlpProtoFinalize2Thread(&dp_ctx);

	for (uint32_t i = 0; i < FLOW_MESSAGE_MAX_MESSAGES; ++i) {
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

	if (msgs->size != FLOW_MESSAGE_MAX_MESSAGES) {
		printf("Expected %u message in use, but was: %u\n", FLOW_MESSAGE_MAX_MESSAGES, msgs->size);
		goto error;
	}

	if (f.flags & FLOW_NO_APPLAYER_INSPECTION) {
		printf("FLOW_NO_APPLAYER_INSPECTION shouldn't be set\n");
		goto error;
	}

	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, "x", 1, (FLOW_MESSAGE_MAX_MESSAGES % 2) ? STREAM_TOCLIENT : STREAM_TOSERVER);

	if (!(f.flags & FLOW_NO_APPLAYER_INSPECTION)) {
		printf("FLOW_NO_APPLAYER_INSPECTION should be set\n");
		goto error;
	}

	int r = 0;
	goto end;
error:
	r = -1;
end:
	FlowShutdown();
	SuperflowFree();
	AlpProtoDeFinalize2Thread(&dp_ctx);
	return r;
}

int SuperflowTest03() {
	FlowInitConfig(1);
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
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

	SuperflowInit(1);
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
	FlowShutdown();
	SuperflowFree();
	AlpProtoDeFinalize2Thread(&dp_ctx);
	return r;
}

int SuperflowTest04() {
	FlowInitConfig(1);
	Packet p;
	memset(&p, 0, sizeof(Packet));
	AlpProtoDetectThreadCtx dp_ctx;
	TcpSession ssn;
	IPV4Hdr ip4hdr;
	TCPHdr tcphdr;
	p.ip4h = &ip4hdr;
	p.tcph = &tcphdr;

	ip4hdr.ip4_hdrun1.ip4_un1.ip_src.s_addr = p.src.address.address_un_data32[0] = 0x12345678;
	ip4hdr.ip4_hdrun1.ip4_un1.ip_dst.s_addr = p.dst.address.address_un_data32[0] = 0x87654321;
	p.dp = 123;
	p.sp = 456;

	SuperflowInit(1);
	AlpProtoFinalize2Thread(&dp_ctx);

	ThreadVars tv;

	FlowHandlePacket(&tv, &p);
	Flow * f = p.flow;

	if (!f->superflow_state.superflow) {
		printf("No superflow was associated with flow\n");
		goto error;
	}

	if (f->superflow_state.superflow->refCount != 1) {
		printf("Superflow refcount must be 1\n");
		goto error;
	}

	ip4hdr.ip4_hdrun1.ip4_un1.ip_src.s_addr = p.src.address.address_un_data32[0] = 0x87654321;
	ip4hdr.ip4_hdrun1.ip4_un1.ip_dst.s_addr = p.dst.address.address_un_data32[0] = 0x12345678;
	p.dp = 456;
	p.sp = 123;

	FlowHandlePacket(&tv, &p);
	Flow * f2 = p.flow;


	if (f->superflow_state.superflow == f2->superflow_state.superflow) {
		printf("Superflows identic\n");
		goto error;
	}

	ip4hdr.ip4_hdrun1.ip4_un1.ip_src.s_addr = p.src.address.address_un_data32[0] = 0x12345678;
	ip4hdr.ip4_hdrun1.ip4_un1.ip_dst.s_addr = p.dst.address.address_un_data32[0] = 0x87654321;
	p.dp = 123;
	p.sp = 789;

	FlowHandlePacket(&tv, &p);
	Flow * f3 = p.flow;

	if (f->superflow_state.superflow != f3->superflow_state.superflow) {
		printf("Superflows identic\n");
		goto error;
	}

	Superflow *sflow = superflow_hash_get_head(g_superflow_hashtable);
	if (sflow->refCount != 1) {
		printf("Refcount of first superflow is not 1, %u\n", sflow->refCount);
		goto error;
	}

	sflow = superflow_hash_next(g_superflow_hashtable, sflow);
	if (sflow->refCount != 2) {
		printf("Refcount of second superflow is not 1\n");
		goto error;
	}

	sflow = superflow_hash_next(g_superflow_hashtable, sflow);
	if (sflow != NULL) {
		printf("More than two superflows exist");
		goto error;
	}

	int r = 0;
	goto end;
error:
	r = -1;
end:
	FlowShutdown();
	SuperflowFree();
	AlpProtoDeFinalize2Thread(&dp_ctx);
	return r;
}

Superflow* emmitPacket(uint64_t i) {
	union SuperflowKey_ key;
	key.key = i;

	Packet p;
	memset(&p, 0, sizeof(Packet));
	IPV4Hdr ip4hdr;
	TCPHdr tcphdr;
	p.ip4h = &ip4hdr;
	p.tcph = &tcphdr;

	ip4hdr.ip4_hdrun1.ip4_un1.ip_src.s_addr = p.src.address.address_un_data32[0] = key.srvr;
	ip4hdr.ip4_hdrun1.ip4_un1.ip_dst.s_addr = p.dst.address.address_un_data32[0] = key.clnt;
	p.dp = (i * 25) % 65536;
	p.sp = (i * 12) % 65536;

	FlowHandlePacket(NULL, &p);

	Superflow* sflow = p.flow->superflow_state.superflow;

	FLOW_DESTROY(p.flow);

	return sflow;
}

int SuperflowTest05() {
	FlowInitConfig(1);
	AlpProtoDetectThreadCtx dp_ctx;
	AlpProtoFinalize2Thread(&dp_ctx);
	SuperflowInit(1);
	uint64_t i;

	for (i = 0; i < SUPERFLOW_COUNT; ++i) {
		emmitPacket(i);
	}

	if (superflow_hash_count(g_superflow_hashtable) != SUPERFLOW_COUNT) {
		printf("Superflow count is not SUPERFLOW_COUNT\n");
		goto error;
	}

	Superflow *sflow = superflow_hash_get_head(g_superflow_hashtable);
	uint64_t count = 1;
	while ((sflow = superflow_hash_next(g_superflow_hashtable, sflow))) {
		++count;
	}

	if (count != SUPERFLOW_COUNT) {
		printf("count is not SUPERFLOW_COUNT\n");
		goto error;
	}

	Superflow* sflow_head = superflow_hash_get_head(g_superflow_hashtable);
	sflow = emmitPacket(i++);

	if (sflow != sflow_head) {
		printf("New superflow is not sflow_head, %x\n", sflow);
		goto error;
	}

	sflow_head = superflow_hash_get_head(g_superflow_hashtable);
	++sflow_head->refCount;
	sflow_head = superflow_hash_next(g_superflow_hashtable, sflow_head);
	sflow = emmitPacket(i++);

	if (sflow != sflow_head) {
		printf("New superflow is not sflow_head, %x, %x\n", sflow, sflow_head);
		goto error;
	}

	sflow = superflow_hash_get_head(g_superflow_hashtable);
	sflow->refCount++;
	while ((sflow = superflow_hash_next(g_superflow_hashtable, sflow))) {
		sflow->refCount++;
	}

	sflow = emmitPacket(i++);

	if (sflow != NULL) {
		printf("Sflow should have been NULL\n");
		goto error;
	}

	int r = 0;
	goto end;
error:
	r = -1;
end:
	FlowShutdown();
	SuperflowFree();
	AlpProtoDeFinalize2Thread(&dp_ctx);
	return r;
}

void SuperflowRegisterTests() {
	UtRegisterTest("SuperflowTest1", SuperflowTest01, 0);
	UtRegisterTest("SuperflowTest2", SuperflowTest02, 0);
	UtRegisterTest("SuperflowTest3", SuperflowTest03, 0);
	UtRegisterTest("SuperflowTest4", SuperflowTest04, 0);
	UtRegisterTest("SuperflowTest5", SuperflowTest05, 0);
}
