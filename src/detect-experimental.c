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

#include "detect-experimental.h"

static int DetectExperimentalSetup (DetectEngineCtx *, Signature *, char *);
void DetectExperimentalFree (void *);
int DetectExperimentalMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m);
static void DetectExperimentalRegisterTests(void);

typedef struct DetectExperimentalData_ {
    uint32_t key;   /**< 1st length value in the signature*/
} DetectExperimentalData;

void DetectExperimentalRegister(void) {
    sigmatch_table[DETECT_EXPERIMENTAL].name = "experimental";
    sigmatch_table[DETECT_EXPERIMENTAL].Match = DetectExperimentalMatch;
    sigmatch_table[DETECT_EXPERIMENTAL].Setup = DetectExperimentalSetup;
    sigmatch_table[DETECT_EXPERIMENTAL].Free = DetectExperimentalFree;
    sigmatch_table[DETECT_EXPERIMENTAL].RegisterTests = DetectExperimentalRegisterTests;
}


static int DetectExperimentalSetup (DetectEngineCtx * ctx, Signature * s, char * str) {
	DetectExperimentalData *ed = NULL;
	SigMatch *sm = NULL;

	ed = SCMalloc(sizeof(DetectExperimentalData));
	sm = SigMatchAlloc();
	if (sm == NULL)
		goto error;

	ed->key = atoi(str);

	sm->type = DETECT_EXPERIMENTAL;

	sm->ctx = (void*) ed;


	SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

	return 0;

	error:
	    if (sm != NULL) SCFree(sm);
	    if (ed != NULL) SCFree(ed);

	    return -1;
}

static void xorCrypt(char* buf, uint32_t len, uint32_t key) {
	for (int i = 0; i < len; ++i) {
		buf[i] ^= (uint8_t)(key >> i % 4);
	}
}

int DetectExperimentalMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m) {
	char ent[256];
	int i;
	float entropy = 0;
	DetectExperimentalData *ed = m->ctx;
	printf("MATCH\n");
	if (p->ip4h == NULL || PKT_IS_PSEUDOPKT(p) || p->payload_len == 0)
	        return 0;

	printf("p->payload: %s\n", p->payload);
	xorCrypt(p->payload, p->payload_len, ed->key);
	printf("p->payload: %s\n", p->payload);

	return 1;
}

void DetectExperimentalFree (void * ptr) {
	DetectExperimentalData *ed = (DetectExperimentalData*) ptr;
	SCFree(ed);
}

#ifdef UNITTESTS

static int ExperimentalTest1() {
	char payload[] = "Hello world!";
	uint32_t key = 0x45157894;
	xorCrypt(payload, sizeof(payload), 0x45157894);

	Packet *p = UTHBuildPacket((uint8_t*)payload, sizeof(payload), IPPROTO_TCP);

	char sig[512];
	sprintf(sig, "alert tcp any any -> any any (msg:\"dummy\"; entropy:0; experimental:%d; entropy:0; sid:1;)", key);
	int res = UTHPacketMatchSig(p, sig);

	UTHFreePacket(p);

	return res;
}

static int ExperimentalTest2() {
	uint8_t payload[] = {
			1,1,1,1,1,1,1,1,1
	};
	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	int res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; entropy:0.4; sid:1;)");

	UTHFreePacket(p);

	return res;
}

static int ExperimentalTest3() {
	uint8_t payload[256];
	for (int i = 0; i < 256; ++i) {
		payload[i] = i;
	}
	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	int res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; entropy:0.99; sid:1;)");

	UTHFreePacket(p);

	return res;
}

static int ExperimentalTest4() {
	int res;
	uint8_t payload[] = {
			1,2,3,4,5,6,7,8,9,10,11
	};
	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; entropy:0.4; sid:1;)");
	if (!res) goto error;

	if (!p->cnc.flags & CNC_ENTROPY) {
		printf("Experimental flag not set");
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

void DetectExperimentalRegisterTests(void) {
#ifdef UNITTESTS
	UtRegisterTest("ExperimentalTest1", ExperimentalTest1, 1);
	/*UtRegisterTest("ExperimentalTest2", ExperimentalTest2, 0);
	UtRegisterTest("ExperimentalTest3", ExperimentalTest3, 1);
	UtRegisterTest("ExperimentalTest4", ExperimentalTest4, 1);*/
#endif
}
