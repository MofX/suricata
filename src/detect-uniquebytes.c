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

#include "detect-uniquebytes.h"

static int DetectUniqueBytesSetup (DetectEngineCtx *, Signature *, char *);
void DetectUniqueBytesFree (void *);
int DetectUniqueBytesMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m);
static void DetectUniqueBytesRegisterTests(void);

typedef struct DetectUniqueBytesData_ {
    uint8_t uniqueBytes;   /**< 1st length value in the signature*/
} DetectUniqueBytesData;

void DetectUniqueBytesRegister(void) {
    sigmatch_table[DETECT_UNIQUEBYTES].name = "uniqueBytes";
    sigmatch_table[DETECT_UNIQUEBYTES].Match = DetectUniqueBytesMatch;
    sigmatch_table[DETECT_UNIQUEBYTES].Setup = DetectUniqueBytesSetup;
    sigmatch_table[DETECT_UNIQUEBYTES].Free = DetectUniqueBytesFree;
    sigmatch_table[DETECT_UNIQUEBYTES].RegisterTests = DetectUniqueBytesRegisterTests;
}


static int DetectUniqueBytesSetup (DetectEngineCtx * ctx, Signature * s, char * str) {
	DetectUniqueBytesData *ed = NULL;
	SigMatch *sm = NULL;

	ed = SCMalloc(sizeof(DetectUniqueBytesData));
	sm = SigMatchAlloc();
	if (sm == NULL)
		goto error;

	ed->uniqueBytes = atoi(str);

	sm->type = DETECT_UNIQUEBYTES;

	sm->ctx = (void*) ed;

	SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

	return 0;

	error:
	    if (sm != NULL) SCFree(sm);
	    if (ed != NULL) SCFree(ed);

	    return -1;
}


int DetectUniqueBytesMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m) {
	char ent[256];
	int i;
	uint8_t uniqueBytes = 0;
	DetectUniqueBytesData *ed = m->ctx;

	if (p->ip4h == NULL || PKT_IS_PSEUDOPKT(p) || p->payload_len == 0)
	        return 0;

	//printf("IPv4 id: %d, offset: %d, len: %d\n", p->ip4h->ip_id, p->ip4h->ip_off, p->payload_len);

	if (!(p->cnc.flags & CNC_UNIQUEBYTES)) {
		memset(ent, 0, 256);
		for (i = 0; i < p->payload_len; ++i) {
			ent[p->payload[i]]++;
		}

		for (i = 0; i < 256; ++i) {
			if (ent[i] == 0) continue;
			++uniqueBytes;
		}
		p->cnc.uniqueBytes = uniqueBytes;
		p->cnc.flags |= CNC_UNIQUEBYTES;
	} else {
		//printf("Using cached uniqueBytes\n");
		uniqueBytes = p->cnc.uniqueBytes;
	}

	//printf("UniqueBytes: %d, Target: %d\n", uniqueBytes, ed->uniqueBytes);

	return uniqueBytes >= ed->uniqueBytes;
}

void DetectUniqueBytesFree (void * ptr) {
	DetectUniqueBytesData *ed = (DetectUniqueBytesData*) ptr;
	SCFree(ed);
}

#ifdef UNITTESTS
static int UniqueBytesTest1() {
	uint8_t payload[] = {
			1,2,3,4,5,6,7,8,9,10
	};
	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	int res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; uniqueBytes:10; sid:1;)");

	UTHFreePacket(p);

	return res;
}

static int UniqueBytesTest2() {
	uint8_t payload[] = {
			1,1,1,1,1,1,1,1,1,1
	};
	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	int res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; uniqueBytes:2; sid:1;)");

	UTHFreePacket(p);

	return res;
}

static int UniqueBytesTest3() {
	uint8_t payload[256];
	for (int i = 0; i < 256; ++i) {
		payload[i] = i;
	}
	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	int res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; uniqueBytes:256; sid:1;)");

	UTHFreePacket(p);

	return res;
}

static int UniqueBytesTest4() {
	int res;
	uint8_t payload[] = {
			1,2,3,4,5,6,7,8,9,10,11
	};
	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; uniqueBytes:11; sid:1;)");
	if (!res) goto error;

	if (!p->cnc.flags & CNC_UNIQUEBYTES) {
		printf("UniqueBytes flag not set");
		res = 0;
		goto error;
	}

	p->cnc.uniqueBytes = 0;
	res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; uniqueBytes:1; sid:1;)");
	if (res) goto error;

	return 1;

error:
	UTHFreePacket(p);
	return 0;
}

#endif

void DetectUniqueBytesRegisterTests(void) {
#ifdef UNITTESTS
	UtRegisterTest("UniqueBytesTest1", UniqueBytesTest1, 1);
	UtRegisterTest("UniqueBytesTest2", UniqueBytesTest2, 0);
	UtRegisterTest("UniqueBytesTest3", UniqueBytesTest3, 1);
	UtRegisterTest("UniqueBytesTest4", UniqueBytesTest4, 1);
#endif
}
