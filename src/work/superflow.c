/**
 * \file
 * \author Jörg Vehlow <fh@jv-coder.de>
 */

#include "suricata-common.h"

#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-private.h"
#include "flow.h"
#include "flow-util.h"
#include "threads.h"

#include "counters.h"
#include "conf.h"

#include "util-debug.h"
#include "util-print.h"
#include "util-profiling.h"
#include "util-validate.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "work/superflow.h"
#include "work/superflow-applayer-wrapper.h"
#include "work/message.h"

#include <pcap.h>

#define SUPERFLOW_NUM_HASHMAPS 4

typedef struct SuperflowHashMap_ {
	struct UT_hash_table_ *htbl;
	SCMutex mutex;
	uint32_t perfId_count;
} SuperflowHashMap;

SuperflowHashMap g_superflow_maps[SUPERFLOW_NUM_HASHMAPS];

Superflow *g_superflows = NULL;
uint32_t g_superflow_used_count = 0;

Superflow* SuperflowFromHeap();
Superflow* SuperflowFromHash(SuperflowHashMap *map);
void SuperflowAttachToFlow(SuperflowHashMap *map, Packet* packet);
void SuperflowTouch(SuperflowHashMap *map, Superflow* sflow);

SCPerfContext g_perfContext;
SCPerfCounterArray *g_perfCounterArray;
uint32_t g_perfId_superflow_drop = 0, g_perfId_superflow_count = 0, g_perfId_superflow_reuse_count = 0;
uint32_t g_perfId_superflow_use_count = 0;
uint32_t g_perfId_superflow_free_count = 0;

uint64_t g_superflow_memory;
uint32_t g_superflow_count;
uint64_t s_superflow_memory_real;

uint32_t g_superflow_message_timeout;
uint32_t g_superflow_message_max_length;

SCMutex g_superflow_mutex;

SuperflowHashMap* SuperflowGetMap(uint32_t src, uint32_t dst) {
	return &g_superflow_maps[(src + dst) % SUPERFLOW_NUM_HASHMAPS];
}

/**
 * Called by FlowHandlePacekt in flow.c
 * This function associates a superflow with a flow or
 * if there is one associated, it just touches it (see SuperflowTouch).
 */
void SuperflowHandlePacket(Packet* p) {
	//SCMutexLock(&g_superflow_mutex);
	//if (!g_superflow_hashtable) goto end;
	if (!p->flow) goto end;
	if (!FLOW_IS_IPV4(p->flow)) goto end;
	if (!PKT_IS_TCP(p) && !PKT_IS_UDP(p)) goto end;

	SuperflowHashMap *map = SuperflowGetMap(p->src.address.address_un_data32[0], p->dst.address.address_un_data32[0]);
	if (!map->htbl) goto end;
	SCMutexLock(&map->mutex);


	if (!p->flow->superflow_state.superflow) {
		SuperflowAttachToFlow(map, p);
	} else {
		SuperflowTouch(map, p->flow->superflow_state.superflow);
	}

	if (PKT_IS_UDP(p) && p->flow) {
		MessageAdd(p, p->payload, p->payload_len,
				(PKT_IS_TOSERVER(p) ? STREAM_TOSERVER : STREAM_TOCLIENT));
	}

	SCMutexUnlock(&map->mutex);

end:
	return;
	//SCMutexUnlock(&g_superflow_mutex);
}

/**
 * Touches a superflow in the hash.
 * I.e. moving the superflow to the end of the linked list.
 */
void SuperflowTouch(SuperflowHashMap *map, Superflow* sflow) {
	superflow_hash_touch(map->htbl, sflow);
}

/**
 * Associates the flow of the given packet to an existing superflow, a new one or to a recycled one.
 * There is a possbility, that no flow is attached afterwards, because there is no matching flow and
 * all superflows have a refcount > 0.
 */
void SuperflowAttachToFlow(SuperflowHashMap *map, Packet* packet) {
	Flow * flow = packet->flow;
	union SuperflowKey_ key;

	// The key is build from the source and destination address
	key.srvr = flow->dst.address.address_un_data32[0];
	key.clnt = flow->src.address.address_un_data32[0];
	key.type = PKT_IS_TCP(packet) ? SUPERFLOW_FLAG_UDP : SUPERFLOW_FLAG_TCP;

	Superflow* sflow = NULL;

	// Look for a matching superflow in the hashmap
	sflow = superflow_hash_find_by_key(map->htbl, &key);

	if (sflow == NULL) {
		// Take the superflow from the heap (the not used superflows)
		sflow = SuperflowFromHeap();

		if (sflow) {
			SCPerfCounterIncr(map->perfId_count, g_perfCounterArray);
			SCPerfUpdateCounterArray(g_perfCounterArray, &g_perfContext, 0);
		}

		if (sflow == NULL) {
			// Take the oldest superflow from the hashmap
			sflow = SuperflowFromHash(map);
			if (sflow) {
				SCPerfCounterIncr(g_perfId_superflow_reuse_count, g_perfCounterArray);
				SCPerfUpdateCounterArray(g_perfCounterArray, &g_perfContext, 0);
			}
		}

		if (sflow == NULL) {
			// No free superflow
			SCPerfCounterIncr(g_perfId_superflow_drop, g_perfCounterArray);
			SCPerfUpdateCounterArray(g_perfCounterArray, &g_perfContext, 0);
			//printf("Warning: No free Superflow. Can't associate superflow to flow. : %u, %x\n", g_perfId_superflow_drop, g_perfCounterArray);
			return;
		}

		// Reset superflow
		memset(sflow, 0, sizeof(Superflow));
		sflow->addrs = key;
		// Add it to the hashtable
		superflow_hash_add(map->htbl, sflow);
	} else {
		// Touch the superflow if a matching superflow was found in the hashmap
		SuperflowTouch(map, sflow);
	}

	// The superflow is now in use so increment the refcount
	SC_ATOMIC_ADD(sflow->refCount, 1);
	if (SC_ATOMIC_GET(sflow->refCount) == 1) {
		SCPerfCounterIncr(g_perfId_superflow_use_count, g_perfCounterArray);
		SCPerfUpdateCounterArray(g_perfCounterArray, &g_perfContext, 0);
	}

	// Assign the superflow to the superflow_state struct
	flow->superflow_state.superflow = sflow;
}

/**
 * Returns the entropy of a superflow message
 */
float SuperflowGetEntropy(struct SuperflowMessage_ *sfm) {
	return sfm->entropy / 255.;
}

/**
 * Initializes the superflow parser.
 */
void SuperflowInit(char silent) {
#ifdef SUPERFLOW_DEACTIVATE
	return;
#endif

	if (g_superflows) {
		printf("Superflows is not NULL, SuperflowInit called twice?\n");
		exit(-1);
	}
	// Default values (used in unittests as well)
	g_superflow_memory = 1024;
	g_superflow_message_timeout = 200;
	g_superflow_message_max_length = 2048;
	SCMutexInit(&g_superflow_mutex, NULL);

	ConfNode *node = ConfGetRootNode();
	node = ConfNodeLookupChild(node, "superflow");
	if (node) {
		char * buffer;
		ConfGetChildValue(node, "memory", &buffer);
		printf("memory: %s\n", buffer);
		g_superflow_memory = strtoull(buffer, 0, 10);

		//intmax_t i = g_superflow_memory;
		//ConfGetChildValueInt(node, "memory", &i);
		//g_superflow_memory = i;
		intmax_t i = g_superflow_message_timeout;
		ConfGetChildValueInt(node, "message-timeout", &i);
		g_superflow_message_timeout = i;
		i = g_superflow_message_max_length;
		ConfGetChildValueInt(node, "message-max-length", &i);
		g_superflow_message_max_length = i;
	}

	// Calculate the number of superflows and their actual memory requirement
	g_superflow_count = g_superflow_memory / sizeof(Superflow);
	s_superflow_memory_real = g_superflow_count * sizeof(Superflow);


	if (!silent) {
		printf("Allocating %llu bytes of memory for %u superflows\n", s_superflow_memory_real, g_superflow_count);
	}
	// Allocate the superflows
	g_superflows = malloc(s_superflow_memory_real);
	if (!g_superflows) {
		printf("Allocating superflows failed\n");
		exit(-1);
	}

	// Create the performance counters
	memset(&g_perfContext, 0, sizeof(SCPerfContext));

	g_perfId_superflow_drop = SCPerfRegisterCounter("superflow.droped_sflows", "Superflow", SC_PERF_TYPE_UINT64, "Number of dropped superflows", &g_perfContext);
	g_perfId_superflow_count = SCPerfRegisterCounter("superflow.num_sflows", "Superflow", SC_PERF_TYPE_UINT64, "Number of superflows", &g_perfContext);
	g_perfId_superflow_reuse_count = SCPerfRegisterCounter("superflow.reuse_count", "Superflow", SC_PERF_TYPE_UINT64, "The number of reused superflows", &g_perfContext);
	g_perfId_superflow_use_count = SCPerfRegisterCounter("superflow.use_count", "Superflow", SC_PERF_TYPE_UINT64, "Number of acquired superflows", &g_perfContext);
	g_perfId_superflow_free_count = SCPerfRegisterCounter("superflow.free_count", "Superflow", SC_PERF_TYPE_UINT64, "Number of freed superflows", &g_perfContext);

	SCPerfCounterDisplay(g_perfId_superflow_drop, &g_perfContext, 1);
	SCPerfCounterDisplay(g_perfId_superflow_count, &g_perfContext, 1);
	SCPerfCounterDisplay(g_perfId_superflow_use_count, &g_perfContext, 1);
	SCPerfCounterDisplay(g_perfId_superflow_free_count, &g_perfContext, 1);
	SCPerfCounterDisplay(g_perfId_superflow_reuse_count, &g_perfContext, 1);


	// Initialize the superflow hashtable
	//g_superflow_hashtable = superflow_hash_new(g_superflows);
	for (uint32_t i = 0; i < SUPERFLOW_NUM_HASHMAPS; ++i) {
		g_superflow_maps[i].htbl = superflow_hash_new(g_superflows);
		SCMutexInit(&g_superflow_maps[i].mutex, NULL);

		char name[1024];
		char desc[1024];
		sprintf(name, "superflow.hash_map%u_count", i);
		sprintf(desc, "Number of superflows in hashmap %u", i);
		g_superflow_maps[i].perfId_count = SCPerfRegisterCounter(name, "Superflow", SC_PERF_TYPE_UINT64, desc, &g_perfContext);
	}


	SCPerfAddToClubbedTMTable("Superflow", &g_perfContext);
	g_perfCounterArray = SCPerfGetAllCountersArray(&g_perfContext);
}

/**
 * Frees all resources used by the superflow parser
 */
void SuperflowFree() {
#ifdef SUPERFLOW_DEACTIVATE
	return;
#endif
	Superflow *sflow = NULL;

	// Free the hashmap
	/*while ((sflow = superflow_hash_get_head(g_superflow_hashtable))) {
		FLOWLOCK_DESTROY(sflow);
		superflow_hash_del(g_superflow_hashtable, sflow);
	}*/
	//superflow_hash_free(g_superflow_hashtable);
	for (uint32_t i = 0; i < SUPERFLOW_NUM_HASHMAPS; i++) {
		while ((sflow = superflow_hash_get_head(g_superflow_maps[i].htbl))) {
			FLOWLOCK_DESTROY(sflow);
			superflow_hash_del(g_superflow_maps[i].htbl, sflow);
		}
		superflow_hash_free(g_superflow_maps[i].htbl);
		g_superflow_maps[i].htbl = NULL;
	}

	// Free the superflows
	free(g_superflows);

	// Release the performance counters
	SCPerfReleasePCA(g_perfCounterArray);
	g_perfCounterArray = NULL;
	SCPerfReleasePerfCounterS(g_perfContext.head);

	g_superflows = NULL;
	//g_superflow_hashtable = NULL;
	g_superflow_used_count = 0;

	g_superflow_memory = 0;
	g_superflow_message_timeout = 0;
	g_superflow_message_max_length = 0;

	g_superflow_memory = 0;
	g_superflow_count = 0;
	s_superflow_memory_real = 0;
}

/**
 * Called when suricata initializes a flow to do superflow specific setup
 */
void SuperflowInitFlow(Flow* flow) {
#ifdef SUPERFLOW_DEACTIVATE
	return;
#endif
	memset(&flow->superflow_state, 0, sizeof(SuperflowState));
	//printf("Init flow: %llx, %u\n", flow, flow->superflow_state.messages.msgs[0].capacity);
}

/**
 * Called when suricata frees a flow.
 * This finalizes all messages and reduces the refcount of
 * the associated superflow
 */
void SuperflowFreeFlow(Flow* flow) {
#ifdef SUPERFLOW_DEACTIVATE
	return;
#endif
	//printf("Free flow: %llx\n", flow);

	MessageSuperflowFinalize(&flow->superflow_state);
	free(flow->superflow_state.buffer_to_client.buffer);
	free(flow->superflow_state.buffer_to_server.buffer);
	for (uint8_t i = 0; i < SUPERFLOW_MESSAGE_COUNT; ++i) {
		free(flow->superflow_state.messages.msgs[i].buffer);
	}

	if (flow->superflow_state.superflow) {
		SC_ATOMIC_SUB(flow->superflow_state.superflow->refCount, 1);

		if (SC_ATOMIC_GET(flow->superflow_state.superflow->refCount) == 0) {
			SCPerfCounterIncr(g_perfId_superflow_free_count, g_perfCounterArray);
			SCPerfUpdateCounterArray(g_perfCounterArray, &g_perfContext, 0);
		}

	}
}

/**
 * Called when suricata recycles a flow.
 */
void SuperflowRecycleFlow(Flow* flow) {
#ifdef SUPERFLOW_DEACTIVATE
	return;
#endif
	SuperflowFreeFlow(flow);
	SuperflowInitFlow(flow);
}

/**
 * Returns a new superflow from the reserved superflows.
 * Returns NULLL if no more free superflows are available.
 */
Superflow* SuperflowFromHeap() {
	if (g_superflow_used_count == g_superflow_count) return NULL;
	SCMutexLock(&g_superflow_mutex);
	// Double check is neccessary
	if (g_superflow_used_count == g_superflow_count) return NULL;

	SCPerfCounterIncr(g_perfId_superflow_count, g_perfCounterArray);
	SCPerfUpdateCounterArray(g_perfCounterArray, &g_perfContext, 0);

	Superflow *new_sflow = &g_superflows[g_superflow_used_count++];

	FLOWLOCK_INIT(new_sflow);

	SCMutexUnlock(&g_superflow_mutex);

	return new_sflow;
}

/**
 * Returns the first superflow from the list of that hashmap that has refcount set to zero
 * and removes it from the hashmap.
 * Return NULL, if all superflows have a refcount > 0
 */
Superflow* SuperflowFromHash(SuperflowHashMap *map) {
	Superflow* sflow = superflow_hash_get_head(map->htbl);
	if (!sflow) return NULL;

	while (sflow != NULL && SC_ATOMIC_GET(sflow->refCount) > 0) {
		sflow = superflow_hash_next(map->htbl, sflow);
	}

	if (sflow) {
		superflow_hash_del(map->htbl, sflow);
	}

	return sflow;
}

/**
 * Returns the next free message in a superflow and increments the counter.
 */
SuperflowMessage * SuperflowGetNextMessage(SuperflowState * sfs) {
	Superflow * sflow = sfs->superflow;
	if (!sflow) return NULL;
	FLOWLOCK_WRLOCK(sflow);

	SuperflowMessage * res = NULL;

	if (sflow->messageCount != SUPERFLOW_MESSAGE_COUNT) {
		res = &sflow->msgs[sflow->messageCount++];
	}

end:
	FLOWLOCK_UNLOCK(sflow);
	return res;
}

#ifdef UNITTESTS
/**
 * This test simply tries to add some data to the flow message buffer and checks  it.
 */
int SuperflowTest01() {
	FlowInitConfig(1);
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	AlpProtoDetectThreadCtx dp_ctx;
	TcpSession ssn;

	SuperflowInit(1);
	AlpProtoFinalize2Thread(&dp_ctx);

	FLOW_INITIALIZE(&f);

	p.flow = &f;

	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, (uint8_t*)"a", 1, STREAM_START | STREAM_TOSERVER);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, (uint8_t*)"b", 1, STREAM_TOSERVER);

	if (msgs->size != 1) {
		printf("Expected one message in use\n");
		goto error;
	}

	if (memcmp("ab", msgs->msgs[0].buffer, 2) != 0) {
		printf("Message buffer doesn't contain \"ab\": \"%s\"\n", msgs->msgs[0].buffer);
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

/**
 * This tests adds the maximum number of messages to the flow.
 * It also triggers the http applayer parser and test if the
 * FLOW_NO_APPLAYER_INSPECTION flag is set properly.
 * The FLOW_NO_APPLAYER_INSPECTION flag should be set
 * if the applayer parser sets it before AND if the maximum number of messages is reached.
 */
int SuperflowTest02() {
	FlowInitConfig(1);
	Flow f;
	FlowMessages *msgs = &f.superflow_state.messages;
	Packet p;
	AlpProtoDetectThreadCtx dp_ctx;
	TcpSession ssn;

	SuperflowInit(1);
	AlpProtoFinalize2Thread(&dp_ctx);
	FLOW_INITIALIZE(&f);

	char *buffer_to_server = "GET / HTTP/1.0\nContent-length: -1\n\n";

	f.flags |= FLOW_IPV4;

	p.src.address.address_un_data32[0] = 0x12345678;
	p.dst.address.address_un_data32[0] = 0x87654321;
	p.flow = &f;
	f.protoctx = &ssn;

	for (uint32_t i = 0; i < SUPERFLOW_MESSAGE_COUNT; ++i) {
		char buffer[256];
		sprintf(buffer, "%u", i);
		uint8_t flags = 0;
		char * b = buffer;
		uint32_t len = strlen(buffer);

		if (i == 0) {
			flags |= STREAM_START;
			b = buffer_to_server;
			len = strlen(buffer_to_server);
		}

		flags |= (i % 2) ? STREAM_TOCLIENT : STREAM_TOSERVER;
		SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, (uint8_t*)b, len, flags);
	}

	if (msgs->size != SUPERFLOW_MESSAGE_COUNT) {
		printf("Expected %u message in use, but was: %u\n", SUPERFLOW_MESSAGE_COUNT, msgs->size);
		goto error;
	}

	if (f.flags & FLOW_NO_APPLAYER_INSPECTION) {
		printf("FLOW_NO_APPLAYER_INSPECTION shouldn't be set\n");
		goto error;
	}

	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, (uint8_t*)"x", 1, (SUPERFLOW_MESSAGE_COUNT % 2) ? STREAM_TOCLIENT : STREAM_TOSERVER);

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

/**
 * This test checks if there are problem when one message is very big.
 */
int SuperflowTest03() {
	FlowInitConfig(1);
	Flow f;
	Packet p;
	AlpProtoDetectThreadCtx dp_ctx;
	TcpSession ssn;

	FLOW_INITIALIZE(&f);

	f.flags |= FLOW_IPV4;

	p.src.address.address_un_data32[0] = 0x12345678;
	p.dst.address.address_un_data32[0] = 0x87654321;
	p.flow = &f;
	f.protoctx = &ssn;

	SuperflowInit(1);
	AlpProtoFinalize2Thread(&dp_ctx);

	uint8_t buffer[g_superflow_message_max_length*2];

	ssn.flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, g_superflow_message_max_length, STREAM_START | STREAM_TOSERVER);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, g_superflow_message_max_length, STREAM_TOSERVER);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, g_superflow_message_max_length, STREAM_TOSERVER);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, g_superflow_message_max_length, STREAM_TOSERVER);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, g_superflow_message_max_length * 2, STREAM_TOCLIENT);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, g_superflow_message_max_length, STREAM_TOCLIENT);
	SuperflowHandleTCPData(&p, &dp_ctx, &f, &ssn, buffer, g_superflow_message_max_length, STREAM_TOCLIENT);

	int r = 0;
	goto end;
//error:
//	r = -1;
end:
	FlowShutdown();
	SuperflowFree();
	AlpProtoDeFinalize2Thread(&dp_ctx);
	return r;
}

/**
 * This test checks if the refcounting works properly.
 */
int SuperflowTest04() {
	FlowInitConfig(1);
	Packet p;
	memset(&p, 0, sizeof(Packet));
	AlpProtoDetectThreadCtx dp_ctx;
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

	if (SC_ATOMIC_GET(f->superflow_state.superflow->refCount) != 1) {
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

	struct UT_hash_table_ *g_superflow_hashtable = SuperflowGetMap(ip4hdr.ip4_hdrun1.ip4_un1.ip_src.s_addr, ip4hdr.ip4_hdrun1.ip4_un1.ip_dst.s_addr)->htbl;

	Superflow *sflow = superflow_hash_get_head(g_superflow_hashtable);
	if (SC_ATOMIC_GET(sflow->refCount) != 1) {
		printf("Refcount of first superflow is not 1, %u\n", SC_ATOMIC_GET(sflow->refCount));
		goto error;
	}

	sflow = superflow_hash_next(g_superflow_hashtable, sflow);
	if (SC_ATOMIC_GET(sflow->refCount) != 2) {
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

/**
 * Used by test method to create a valid semi-random packet and pass it to the flowhandler.
 */
Superflow* emmitPacket(uint64_t i) {
	union SuperflowKey_ key;
	key.srvr = i >> 32;
	key.clnt = i;

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

/**
 * This test checks what happens, if the superflow heap is exhausted and
 * also if the head of the list is in use or all superflows are in use (in use = refcount > 0)
 */
int SuperflowTest05() {
	FlowInitConfig(1);
	AlpProtoDetectThreadCtx dp_ctx;
	AlpProtoFinalize2Thread(&dp_ctx);
	SuperflowInit(1);
	uint64_t i;

	for (i = 0; i < g_superflow_count; ++i) {
		emmitPacket(i);
	}


	/*if (superflow_hash_count(g_superflow_hashtable) != g_superflow_count) {
		printf("Superflow count is not SUPERFLOW_COUNT\n");
		goto error;
	}

	Superflow *sflow = superflow_hash_get_head(g_superflow_hashtable);
	uint64_t count = 1;
	while ((sflow = superflow_hash_next(g_superflow_hashtable, sflow))) {
		++count;
	}

	if (count != g_superflow_count) {
		printf("count is not SUPERFLOW_COUNT\n");
		goto error;
	}

	Superflow* sflow_head = superflow_hash_get_head(g_superflow_hashtable);
	sflow = emmitPacket(i++);

	if (sflow != sflow_head) {
		printf("New superflow is not sflow_head, %lx\n", (uint64_t)sflow);
		goto error;
	}

	sflow_head = superflow_hash_get_head(g_superflow_hashtable);
	//++sflow_head->refCount;
	SC_ATOMIC_ADD(sflow_head->refCount, 1);
	sflow_head = superflow_hash_next(g_superflow_hashtable, sflow_head);
	sflow = emmitPacket(i++);

	if (sflow != sflow_head) {
		printf("New superflow is not sflow_head, %lx, %lx\n", (uint64_t)sflow, (uint64_t)sflow_head);
		goto error;
	}

	sflow = superflow_hash_get_head(g_superflow_hashtable);
	//sflow->refCount++;
	SC_ATOMIC_ADD(sflow->refCount, 1);
	while ((sflow = superflow_hash_next(g_superflow_hashtable, sflow))) {
		SC_ATOMIC_ADD(sflow->refCount, 1);
		//sflow->refCount++;
	}

	sflow = emmitPacket(i++);

	if (sflow != NULL) {
		printf("Sflow should have been NULL\n");
		goto error;
	}*/

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

// Prototype for private method required for injecting packets into suricata.
TmEcode StreamTcp (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq);

/**
 * Creates a packet with the specified properties and injects it into suricate at a very low point.
 * The packet is inserted where the lowest layers (like ethernet) deliver their decoded packets to.
 */
Packet * emitTCPPacket(char* data, uint32_t data_len, uint8_t flags, char* src, char* dst, uint16_t srcport, uint16_t dstport,
						uint32_t * seq, uint32_t * ack, struct timeval ts, ThreadVars *tv,
					    StreamTcpThread *stt, PacketQueue *pq) {
    Packet *p = UTHBuildPacketReal((uint8_t*) data, data_len, IPPROTO_TCP, src, dst, srcport, dstport);
    p->ip4h->ip_verhl = 0x45; //(20 << 3) + 4;
    p->tcph->th_offx2 = 0x50;
    p->ts = ts;
    p->tcph->th_flags = flags;
    p->tcph->th_seq = htonl(*seq);
    if (flags & TH_ACK) {
    	p->tcph->th_ack = htonl(*ack);
    }
    p->tcph->th_win = htons(5480);
    FlowHandlePacket(NULL, p);
    StreamTcp(tv, p, stt, pq, pq);

    if ((flags & TH_SYN)  || (flags & TH_FIN)) {
    	++(*seq);
    } else {
    	*seq += data_len;
    }

    return p;
}

/**
 * This tests tests the superflow parser with actual packets. It does correct handshakes for
 * connection setup and teardown.
 */
int SuperflowTest06() {
	FlowInitConfig(1);
	AlpProtoDetectThreadCtx dp_ctx;
	AlpProtoFinalize2Thread(&dp_ctx);
	SuperflowInit(1);
	StreamTcpInitConfig(1);

    ThreadVars tv;
    StreamTcpThread stt;
    PacketQueue pq;
    TcpReassemblyThreadCtx ra_ctx;
    StreamMsgQueue stream_q;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset(&stream_q, 0, sizeof(StreamMsgQueue));

    ra_ctx.stream_q = &stream_q;
    stt.ra_ctx = &ra_ctx;

    uint32_t seq_to_server = 100;
    uint32_t seq_to_client = 300;
	uint16_t client_port = 54854;
	uint16_t server_port = 90;

    Flow *f = NULL;
    TcpSession *ssn = NULL;
    Packet *p = NULL;
    struct timeval ts;
    ts.tv_sec = 0;
    ts.tv_usec = 0;

    p = emitTCPPacket("", 0, TH_SYN, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    f = p->flow;
    FlowIncrUsecnt(f);
    ssn = (TcpSession *)f->protoctx;
    UTHFreePacket(p);

    if (ssn->state != TCP_SYN_SENT) {
    	printf("Connection not in state TCP_SYN_SENT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_SYN | TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_SYN_RECV) {
		printf("Connection not in state TCP_SYN_RECV\n");
		goto error;
	}

    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_ESTABLISHED) {
    	printf("Connection not in state TCP_ESTABLISHED\n");
    	goto error;
    }

    p = emitTCPPacket("test", 5, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (f->superflow_state.messages.size != 1) {
    	printf("Message size is not one\n");
    	goto error;
    }

    if (strcmp((char*)f->superflow_state.messages.msgs[0].buffer, "test") != 0) {
    	printf("Buffer doesn't contain \"test\"\n");
    	goto error;
    }

    ts.tv_usec = (g_superflow_message_timeout + 1) * 1000;

    p = emitTCPPacket("test2", 6, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (f->superflow_state.messages.size != 2) {
    	printf("Message size is not two\n");
    	goto error;
    }

    if (strcmp((char*)f->superflow_state.messages.msgs[1].buffer, "test2") != 0) {
		printf("Buffer doesn't contain \"test2\"\n");
		goto error;
	}

    p = emitTCPPacket("test345", 7, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (f->superflow_state.messages.size != 2) {
    	printf("Message size is not two\n");
    	goto error;
    }

    if (strncmp((char*)f->superflow_state.messages.msgs[1].buffer, "test2\0test345\0", 13) != 0) {
		printf("Buffer doesn't contain \"test2\\0test345\"\n");
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
	StreamTcpFreeConfig(TRUE);
	return r;
}

/**
 * This tests tests the superflow parser with actual packets. It does correct handshakes for
 * connection setup and teardown.
 * It tests if the superflow structures get set up correctly. (Like entropy)
 */
int SuperflowTest07() {
	FlowInitConfig(1);
	AlpProtoDetectThreadCtx dp_ctx;
	AlpProtoFinalize2Thread(&dp_ctx);
	SuperflowInit(1);
	StreamTcpInitConfig(1);

    ThreadVars tv;
    StreamTcpThread stt;
    PacketQueue pq;
    TcpReassemblyThreadCtx ra_ctx;
    StreamMsgQueue stream_q;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset(&stream_q, 0, sizeof(StreamMsgQueue));

    ra_ctx.stream_q = &stream_q;
    stt.ra_ctx = &ra_ctx;

    uint32_t seq_to_server = 100;
    uint32_t seq_to_client = 300;
	uint16_t client_port = 54854;
	uint16_t server_port = 90;

    Flow *f = NULL;
    TcpSession *ssn = NULL;
    Packet *p = NULL;
    Flow *f2 = NULL;
    TcpSession *ssn2 = NULL;
    struct timeval ts;
    ts.tv_sec = 0;
    ts.tv_usec = 0;

	p = emitTCPPacket("", 0, TH_SYN, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    f = p->flow;
    FlowIncrUsecnt(f);
    ssn = (TcpSession *)f->protoctx;
    UTHFreePacket(p);

    if (ssn->state != TCP_SYN_SENT) {
    	printf("Connection not in state TCP_SYN_SENT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_SYN | TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_SYN_RECV) {
		printf("Connection not in state TCP_SYN_RECV\n");
		goto error;
	}

    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_ESTABLISHED) {
    	printf("Connection not in state TCP_ESTABLISHED\n");
    	goto error;
    }

    char buffer[256];
    for (uint32_t i = 0; i < 256; ++i) {
    	buffer[i] = 'a';
    }

    p = emitTCPPacket(buffer, 256, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);
    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_FIN, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_FIN_WAIT1) {
    	printf("Connection not in state TCP_FIN_WAIT1\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_FIN | TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_TIME_WAIT) {
    	printf("Connection not in state TCP_TIME_WAIT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_CLOSED) {
    	printf("Connection not in state TCP_CLOSED\n");
    	goto error;
    }

    if (f->superflow_state.superflow->messageCount != 1) {
    	printf("Superflow message count is not one: %u\n", f->superflow_state.superflow->messageCount);
    	goto error;
    }

    if (f->superflow_state.superflow->msgs[0].length != 256) {
    	printf("Superflow msgs[0] length is not 256: %u\n", f->superflow_state.superflow->msgs[0].length);
    	goto error;
    }

    client_port = 1234;

    p = emitTCPPacket("", 0, TH_SYN, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    f2 = p->flow;
    FlowIncrUsecnt(f2);
    ssn2 = (TcpSession *)f2->protoctx;
    UTHFreePacket(p);

    if (f == f2) {
    	printf("Flow f shouldn't be the same as f2\n");
    	goto error;
    }

    if (ssn2->state != TCP_SYN_SENT) {
    	printf("Connection not in state TCP_SYN_SENT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_SYN | TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_SYN_RECV) {
		printf("Connection not in state TCP_SYN_RECV\n");
		goto error;
	}

    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_ESTABLISHED) {
    	printf("Connection not in state TCP_ESTABLISHED\n");
    	goto error;
    }

    for (uint32_t i = 0; i < 256; ++i) {
    	buffer[i] = i;
    }

    p = emitTCPPacket(buffer, 256, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);
    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_FIN, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_FIN_WAIT1) {
    	printf("Connection not in state TCP_FIN_WAIT1\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_FIN | TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_TIME_WAIT) {
    	printf("Connection not in state TCP_TIME_WAIT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_CLOSED) {
    	printf("Connection not in state TCP_CLOSED\n");
    	goto error;
    }

    if (f->superflow_state.superflow->messageCount != 2) {
    	printf("Superflow message count is not two: %u\n", f->superflow_state.superflow->messageCount);
    	goto error;
    }

    if (f->superflow_state.superflow->msgs[1].length != 256) {
    	printf("Superflow msgs[1] length is not 256: %u\n", f->superflow_state.superflow->msgs[1].length);
    	goto error;
    }

    if (SuperflowGetEntropy(&f->superflow_state.superflow->msgs[0]) > 0) {
    	printf("Entropy of superflow message[0] is greater than 0\n");
    	goto error;
    }

    if (SuperflowGetEntropy(&f->superflow_state.superflow->msgs[1]) < 0.99) {
    	printf("Entropy of superflow message[1] is less than 0.99: %f\n", SuperflowGetEntropy(&f->superflow_state.superflow->msgs[1]));
    	goto error;
    }

	int r = 0;
	goto end;
error:
	r = -1;
end:
	if (f) FlowDecrUsecnt(f);
	if (f2) FlowDecrUsecnt(f2);
	FlowShutdown();
	SuperflowFree();
	AlpProtoDeFinalize2Thread(&dp_ctx);
	StreamTcpFreeConfig(TRUE);
	return r;
}


/**
 * This tests tests the superflow parser with actual packets. It does correct handshakes for
 * connection setup and teardown.
 * A bigger amount of data is send after establishing (>4096 bytes)
 */
int SuperflowTest08() {
	FlowInitConfig(1);
	AlpProtoDetectThreadCtx dp_ctx;
	AlpProtoFinalize2Thread(&dp_ctx);
	SuperflowInit(1);
	StreamTcpInitConfig(1);

    ThreadVars tv;
    StreamTcpThread stt;
    PacketQueue pq;
    TcpReassemblyThreadCtx ra_ctx;
    StreamMsgQueue stream_q;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset(&stream_q, 0, sizeof(StreamMsgQueue));

    ra_ctx.stream_q = &stream_q;
    stt.ra_ctx = &ra_ctx;

    uint32_t seq_to_server = 100;
    uint32_t seq_to_client = 300;
	uint16_t client_port = 54854;
	uint16_t server_port = 90;

    Flow *f = NULL;
    TcpSession *ssn = NULL;
    Packet *p = NULL;
    Flow *f2 = NULL;
    TcpSession *ssn2 = NULL;
    struct timeval ts;
    ts.tv_sec = 0;
    ts.tv_usec = 0;

	p = emitTCPPacket("", 0, TH_SYN, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    f = p->flow;
    FlowIncrUsecnt(f);
    ssn = (TcpSession *)f->protoctx;
    UTHFreePacket(p);

    if (ssn->state != TCP_SYN_SENT) {
    	printf("Connection not in state TCP_SYN_SENT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_SYN | TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_SYN_RECV) {
		printf("Connection not in state TCP_SYN_RECV\n");
		goto error;
	}

    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_ESTABLISHED) {
    	printf("Connection not in state TCP_ESTABLISHED\n");
    	goto error;
    }

    char buffer[4096];
    for (uint32_t i = 0; i < 4000; ++i) {
    	buffer[i] = 'a';
    }

    p = emitTCPPacket(buffer, 4000, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);
    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket(buffer, 4000, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);
    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_FIN, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_FIN_WAIT1) {
    	printf("Connection not in state TCP_FIN_WAIT1\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_FIN | TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_TIME_WAIT) {
    	printf("Connection not in state TCP_TIME_WAIT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_CLOSED) {
    	printf("Connection not in state TCP_CLOSED\n");
    	goto error;
    }

    if (f->superflow_state.superflow->messageCount != 1) {
    	printf("Superflow message count is not one: %u\n", f->superflow_state.superflow->messageCount);
    	goto error;
    }

    if (f->superflow_state.superflow->msgs[0].length != 2048) {
    	printf("Superflow msgs[0] length is not 2048: %u\n", f->superflow_state.superflow->msgs[0].length);
    	goto error;
    }

    client_port = 1234;

    p = emitTCPPacket("", 0, TH_SYN, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    f2 = p->flow;
    FlowIncrUsecnt(f2);
    ssn2 = (TcpSession *)f2->protoctx;
    UTHFreePacket(p);

    if (f == f2) {
    	printf("Flow f shouldn't be the same as f2\n");
    	goto error;
    }

    if (ssn2->state != TCP_SYN_SENT) {
    	printf("Connection not in state TCP_SYN_SENT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_SYN | TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_SYN_RECV) {
		printf("Connection not in state TCP_SYN_RECV\n");
		goto error;
	}

    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_ESTABLISHED) {
    	printf("Connection not in state TCP_ESTABLISHED\n");
    	goto error;
    }

    for (uint32_t i = 0; i < 4096; ++i) {
    	buffer[i] = 'b';
    }

    p = emitTCPPacket(buffer, 3000, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);
    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_FIN, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_FIN_WAIT1) {
    	printf("Connection not in state TCP_FIN_WAIT1\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_FIN | TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_TIME_WAIT) {
    	printf("Connection not in state TCP_TIME_WAIT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_CLOSED) {
    	printf("Connection not in state TCP_CLOSED\n");
    	goto error;
    }

    if (f->superflow_state.superflow->messageCount != 2) {
    	printf("Superflow message count is not two: %u\n", f->superflow_state.superflow->messageCount);
    	goto error;
    }

    if (f->superflow_state.superflow->msgs[1].length != 2048) {
    	printf("Superflow msgs[1] length is not 2048: %u\n", f->superflow_state.superflow->msgs[1].length);
    	goto error;
    }

	int r = 0;
	goto end;
error:
	r = -1;
end:
	if (f) FlowDecrUsecnt(f);
	if (f2) FlowDecrUsecnt(f2);
	FlowShutdown();
	SuperflowFree();
	AlpProtoDeFinalize2Thread(&dp_ctx);
	StreamTcpFreeConfig(TRUE);
	return r;
}

/**
 * This tests tests the superflow parser with actual packets. It does correct handshakes for
 * connection setup and teardown.
 * A bigger amount of data is send after establishing
 */
int SuperflowTest09() {
	FlowInitConfig(1);
	AlpProtoDetectThreadCtx dp_ctx;
	AlpProtoFinalize2Thread(&dp_ctx);
	SuperflowInit(1);
	StreamTcpInitConfig(1);

    ThreadVars tv;
    StreamTcpThread stt;
    PacketQueue pq;
    TcpReassemblyThreadCtx ra_ctx;
    StreamMsgQueue stream_q;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset(&stream_q, 0, sizeof(StreamMsgQueue));

    ra_ctx.stream_q = &stream_q;
    stt.ra_ctx = &ra_ctx;

    uint32_t seq_to_server = 100;
    uint32_t seq_to_client = 300;
	uint16_t client_port = 54854;
	uint16_t server_port = 90;

    Flow *f = NULL;
    TcpSession *ssn = NULL;
    Packet *p = NULL;
    Flow *f2 = NULL;
    TcpSession *ssn2 = NULL;
    struct timeval ts;
    ts.tv_sec = 0;
    ts.tv_usec = 0;

#ifdef WRITE_PCAP
    FILE *fi = fopen("packet.pcap", "wb");
    struct pcap_file_header fhdr;
    fhdr.magic = 0xa1b2c3d4;
    fhdr.version_major = 2;
    fhdr.version_minor = 0;
    fhdr.thiszone = 0;
    fhdr.sigfigs = 0;
    fhdr.snaplen = 65535;
    fhdr.linktype = 228;
    fwrite((void*)&fhdr, sizeof(fhdr),1, fi);

    struct pcap_pkthdr {
    	uint32_t tss;
    	uint32_t tsus;
    	bpf_u_int32 caplen;	/* length of portion present */
    	bpf_u_int32 len;	/* length this packet (off wire) */
    };
    struct pcap_pkthdr hdr;

	hdr.tss = 0;
	hdr.tsus = 0;
#endif

	p = emitTCPPacket("", 0, TH_SYN, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
#ifdef WRITE_PCAP
	hdr.len = hdr.caplen = p->pktlen;
	fwrite((void*)&hdr, sizeof(hdr), 1, fi);
	fwrite(p->pkt, p->pktlen, 1, fi);
#endif
    f = p->flow;
    FlowIncrUsecnt(f);
    ssn = (TcpSession *)f->protoctx;
    UTHFreePacket(p);

    if (ssn->state != TCP_SYN_SENT) {
    	printf("Connection not in state TCP_SYN_SENT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_SYN | TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
#ifdef WRITE_PCAP
	hdr.len = hdr.caplen = p->pktlen;
	fwrite((void*)&hdr, sizeof(hdr), 1, fi);
	fwrite(p->pkt, p->pktlen, 1, fi);
#endif
    UTHFreePacket(p);

    if (ssn->state != TCP_SYN_RECV) {
		printf("Connection not in state TCP_SYN_RECV\n");
		goto error;
	}

    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
#ifdef WRITE_PCAP
	hdr.len = hdr.caplen = p->pktlen;
	fwrite((void*)&hdr, sizeof(hdr), 1, fi);
	fwrite(p->pkt, p->pktlen, 1, fi);
#endif
    UTHFreePacket(p);

    if (ssn->state != TCP_ESTABLISHED) {
    	printf("Connection not in state TCP_ESTABLISHED\n");
    	goto error;
    }

    char buffer[8000];
    for (uint32_t i = 0; i < 4000; ++i) {
    	buffer[i] = 'a';
    	buffer[4000 + i] = 'b';
    }

    for (int i = 0; i < 100; i++) {
#ifdef WRITE_PCAP
    	hdr.tss = i;
    	hdr.tsus = 100;
#endif
    	buffer[0] = i + '0';
    	buffer[1999] = i + 'A';
		p = emitTCPPacket(buffer, 2000, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
#ifdef WRITE_PCAP
		hdr.len = hdr.caplen = p->pktlen;
		fwrite((void*)&hdr, sizeof(hdr), 1, fi);
		fwrite(p->pkt, p->pktlen, 1, fi);
#endif
		UTHFreePacket(p);
		p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
#ifdef WRITE_PCAP
		hdr.len = hdr.caplen = p->pktlen;
		fwrite((void*)&hdr, sizeof(hdr), 1, fi);
		fwrite(p->pkt, p->pktlen, 1, fi);
#endif
		UTHFreePacket(p);

//		p = emitTCPPacket(buffer + 2000, 1000, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
//#ifdef WRITE_PCAP
//		hdr.len = hdr.caplen = p->pktlen;
//		fwrite((void*)&hdr, sizeof(hdr), 1, fi);
//		fwrite(p->pkt, p->pktlen, 1, fi);
//#endif
//		UTHFreePacket(p);
//		p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
//#ifdef WRITE_PCAP
//		hdr.len = hdr.caplen = p->pktlen;
//		fwrite((void*)&hdr, sizeof(hdr), 1, fi);
//		fwrite(p->pkt, p->pktlen, 1, fi);
//#endif
//		UTHFreePacket(p);
    }
#ifdef WRITE_PCAP
    fclose(fi);
#endif

    p = emitTCPPacket("", 0, TH_FIN, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_FIN_WAIT1) {
    	printf("Connection not in state TCP_FIN_WAIT1: %u\n", ssn->state);
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_FIN | TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_TIME_WAIT) {
    	printf("Connection not in state TCP_TIME_WAIT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn->state != TCP_CLOSED) {
    	printf("Connection not in state TCP_CLOSED\n");
    	goto error;
    }

    if (f->superflow_state.superflow->messageCount != 1) {
    	printf("Superflow message count is not one: %u\n", f->superflow_state.superflow->messageCount);
    	goto error;
    }

    if (f->superflow_state.superflow->msgs[0].length != 2048) {
    	printf("Superflow msgs[0] length is not 2048: %u\n", f->superflow_state.superflow->msgs[0].length);
    	goto error;
    }

    client_port = 1234;

    p = emitTCPPacket("", 0, TH_SYN, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    f2 = p->flow;
    FlowIncrUsecnt(f2);
    ssn2 = (TcpSession *)f2->protoctx;
    UTHFreePacket(p);

    if (f == f2) {
    	printf("Flow f shouldn't be the same as f2\n");
    	goto error;
    }

    if (ssn2->state != TCP_SYN_SENT) {
    	printf("Connection not in state TCP_SYN_SENT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_SYN | TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_SYN_RECV) {
		printf("Connection not in state TCP_SYN_RECV\n");
		goto error;
	}

    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_ESTABLISHED) {
    	printf("Connection not in state TCP_ESTABLISHED\n");
    	goto error;
    }

    for (uint32_t i = 0; i < 4096; ++i) {
    	buffer[i] = 'b';
    }

    p = emitTCPPacket(buffer, 3000, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);
    p = emitTCPPacket("", 0, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_FIN, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_FIN_WAIT1) {
    	printf("Connection not in state TCP_FIN_WAIT1\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_FIN | TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_TIME_WAIT) {
    	printf("Connection not in state TCP_TIME_WAIT\n");
    	goto error;
    }

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    if (ssn2->state != TCP_CLOSED) {
    	printf("Connection not in state TCP_CLOSED\n");
    	goto error;
    }

    if (f->superflow_state.superflow->messageCount != 2) {
    	printf("Superflow message count is not two: %u\n", f->superflow_state.superflow->messageCount);
    	goto error;
    }

    if (f->superflow_state.superflow->msgs[1].length != 2048) {
    	printf("Superflow msgs[1] length is not 2048: %u\n", f->superflow_state.superflow->msgs[1].length);
    	goto error;
    }

	int r = 0;
	goto end;
error:
	r = -1;
end:
	if (f) FlowDecrUsecnt(f);
	if (f2) FlowDecrUsecnt(f2);
	FlowShutdown();
	SuperflowFree();
	AlpProtoDeFinalize2Thread(&dp_ctx);
	StreamTcpFreeConfig(TRUE);
	return r;
}

int SuperflowTest10() {
	FlowInitConfig(1);
	AlpProtoDetectThreadCtx dp_ctx;
	AlpProtoFinalize2Thread(&dp_ctx);
	SuperflowInit(1);
	StreamTcpInitConfig(1);

	char* src = "1.2.3.4";
	char* dest = "4.3.2.1";
	uint16_t sport = 10;
	uint16_t dport = 1;

	uint8_t buffer[1024];

	Packet *p_udp = UTHBuildPacketReal(buffer, 0, IPPROTO_UDP, src, dest, sport, dport);
	FlowHandlePacket(NULL, p_udp);

	strcpy((char*)buffer, "Hello ");
	p_udp = UTHBuildPacketReal(buffer, 6, IPPROTO_UDP, src, dest, sport, dport);
	FlowHandlePacket(NULL, p_udp);
	UTHFreePacket(p_udp);

	strcpy((char*)buffer, "world!");
	p_udp = UTHBuildPacketReal(buffer, 7, IPPROTO_UDP, src, dest, sport, dport);
	FlowHandlePacket(NULL, p_udp);
	UTHFreePacket(p_udp);

	strcpy((char*)buffer, "foobar");
	p_udp = UTHBuildPacketReal(buffer, 7, IPPROTO_UDP, dest, src, dport, sport);
	FlowHandlePacket(NULL, p_udp);

	Packet *p_tcp = UTHBuildPacketReal(buffer, 0, IPPROTO_TCP, src, dest, sport, dport);


	FlowHandlePacket(NULL, p_tcp);

	if (!p_udp->flow) {
		printf("UDP has now flow attached\n");
		goto error;
	}

	if (p_udp->flow->superflow_state.superflow == p_tcp->flow->superflow_state.superflow) {
		printf("UDP and TCP flows shouldn't use the same superflow!\n");
		goto error;
	}

	if (p_udp->flow->superflow_state.messages.size != 2) {
		printf("UDP does not contain 2 messages: %u\n", p_udp->flow->superflow_state.messages.size);
		goto error;
	}

	if (p_udp->flow->superflow_state.messages.msgs[0].size != 13) {
		printf("UDP message[0] is not 13 chars long: %u\n", p_udp->flow->superflow_state.messages.msgs[0].size);
		goto error;
	}

	if (strcmp((char*)(p_udp->flow->superflow_state.messages.msgs[0].buffer), "Hello world!") != 0) {
		printf("Msgs[0] is not \"Hello world!\" : %s\n", p_udp->flow->superflow_state.messages.msgs[0].buffer);
		goto error;
	}

	if (p_udp->flow->superflow_state.messages.msgs[1].size != 7) {
		printf("UDP message[1] is not 7 chars long: %u\n", p_udp->flow->superflow_state.messages.msgs[1].size);
		goto error;
	}

	if (strcmp((char*)(p_udp->flow->superflow_state.messages.msgs[1].buffer), "foobar") != 0) {
		printf("Msgs[1] is not \"foobar\" : %s\n", p_udp->flow->superflow_state.messages.msgs[1].buffer);
		goto error;
	}

	int r = 0;
	goto end;
error:
	r = -1;
end:
	UTHFreePacket(p_udp);
	UTHFreePacket(p_tcp);

	FlowShutdown();
	SuperflowFree();
	AlpProtoDeFinalize2Thread(&dp_ctx);
	StreamTcpFreeConfig(TRUE);
	return r;
}

#endif

void SuperflowRegisterTests() {
#ifdef UNITTESTS
#ifndef SUPERFLOW_DEACTIVATE
	UtRegisterTest("SuperflowTest1", SuperflowTest01, 0);
	UtRegisterTest("SuperflowTest2", SuperflowTest02, 0);
	UtRegisterTest("SuperflowTest3", SuperflowTest03, 0);
	UtRegisterTest("SuperflowTest4", SuperflowTest04, 0);
	UtRegisterTest("SuperflowTest5", SuperflowTest05, 0);
	UtRegisterTest("SuperflowTest6", SuperflowTest06, 0);
	UtRegisterTest("SuperflowTest7", SuperflowTest07, 0);
	UtRegisterTest("SuperflowTest8", SuperflowTest08, 0);
	UtRegisterTest("SuperflowTest9", SuperflowTest09, 0);
	UtRegisterTest("SuperflowTest10", SuperflowTest10, 0);
#endif
#endif
}
