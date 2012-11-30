/*
 * detect-entropy.c
 *
 *  Created on: Nov 25, 2012
 *      Author: joerg
 */

#include <stdio.h>
#include <math.h>

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-entropy.h"

static int DetectEntropySetup (DetectEngineCtx *, Signature *, char *);
void DetectEntropyFree (void *);
int DetectEntropyMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m);
static void DetectEntropyRegisterTests(void);

typedef struct DetectEntropyData_ {
    float entropy;   /**< 1st length value in the signature*/
} DetectEntropyData;

void DetectEntropyRegister(void) {
    sigmatch_table[DETECT_ENTROPY].name = "entropy";
    sigmatch_table[DETECT_ENTROPY].Match = DetectEntropyMatch;
    sigmatch_table[DETECT_ENTROPY].Setup = DetectEntropySetup;
    sigmatch_table[DETECT_ENTROPY].Free = DetectEntropyFree;
    sigmatch_table[DETECT_ENTROPY].RegisterTests = DetectEntropyRegisterTests;
}


static int DetectEntropySetup (DetectEngineCtx * ctx, Signature * s, char * str) {
	DetectEntropyData *ed = NULL;
	SigMatch *sm = NULL;

	ed = SCMalloc(sizeof(DetectEntropyData));
	sm = SigMatchAlloc();
	if (sm == NULL)
		goto error;

	ed->entropy = atof(str);

	sm->type = DETECT_ENTROPY;

	sm->ctx = (void*) ed;


	SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

	return 0;

	error:
	    if (sm != NULL) SCFree(sm);
	    if (ed != NULL) SCFree(ed);

	    return -1;
}


int DetectEntropyMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m) {
	char ent[256];
	int i;
	float entropy = 0;
	DetectEntropyData *ed = m->ctx;

	if (p->ip4h == NULL || PKT_IS_PSEUDOPKT(p) || p->payload_len == 0)
	        return 0;

	//printf("IPv4 id: %d, offset: %d, len: %d\n", p->ip4h->ip_id, p->ip4h->ip_off, p->payload_len);

	if (!(p->cnc.flags & CNC_ENTROPY)) {
		memset(ent, 0, 256);
		for (i = 0; i < p->payload_len; ++i) {
			ent[p->payload[i]]++;
		}

		for (i = 0; i < 256; ++i) {
			if (ent[i] == 0) continue;
			float f = ((float)ent[i]) / p->payload_len;
			entropy += f * log(f);
		}
		entropy = -entropy / log(256);
		p->cnc.entropy = entropy;
		p->cnc.flags |= CNC_ENTROPY;
	} else {
		//printf("Using cached entropy\n");
		entropy = p->cnc.entropy;
	}

	//printf("Entropy: %f, Target: %f\n", entropy, ed->entropy);

	return entropy >= ed->entropy;
}

void DetectEntropyFree (void * ptr) {
	DetectEntropyData *ed = (DetectEntropyData*) ptr;
	SCFree(ed);
}

#ifdef UNITTESTS
static int EntropyTest1() {
	uint8_t payload[] = {
			1,2,3,4,5,6,7,8,9,10
	};
	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	int res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; entropy:0.4; sid:1;)");

	UTHFreePacket(p);

	return res;
}

static int EntropyTest2() {
	uint8_t payload[] = {
			1,1,1,1,1,1,1,1,1
	};
	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	int res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; entropy:0.4; sid:1;)");

	UTHFreePacket(p);

	return res;
}

static int EntropyTest3() {
	uint8_t payload[256];
	for (int i = 0; i < 256; ++i) {
		payload[i] = i;
	}
	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	int res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; entropy:0.99; sid:1;)");

	UTHFreePacket(p);

	return res;
}

static int EntropyTest4() {
	int res;
	uint8_t payload[] = {
			1,2,3,4,5,6,7,8,9,10,11
	};
	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; entropy:0.4; sid:1;)");
	if (!res) goto error;

	if (!p->cnc.flags & CNC_ENTROPY) {
		printf("Entropy flag not set");
		res = 0;
		goto error;
	}

	p->cnc.entropy = 0;
	res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; entropy:0.4; sid:1;)");
	if (res) goto error;

	return 1;

error:
	UTHFreePacket(p);
	return 0;
}

#endif

void DetectEntropyRegisterTests(void) {
#ifdef UNITTESTS
	UtRegisterTest("EntropyTest1", EntropyTest1, 1);
	UtRegisterTest("EntropyTest2", EntropyTest2, 0);
	UtRegisterTest("EntropyTest3", EntropyTest3, 1);
	UtRegisterTest("EntropyTest4", EntropyTest4, 1);
#endif
}
