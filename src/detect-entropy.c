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

#include "detect-entropy.h"

static int DetectEntropySetup (DetectEngineCtx *, Signature *, char *);
void DetectEntropyFree (void *);
int DetectEntropyMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m);

typedef struct DetectEntropyData_ {
    float entropy;   /**< 1st length value in the signature*/
} DetectEntropyData;

void DetectEntropyRegister(void) {
    sigmatch_table[DETECT_ENTROPY].name = "entropy";
    sigmatch_table[DETECT_ENTROPY].Match = DetectEntropyMatch;
    sigmatch_table[DETECT_ENTROPY].Setup = DetectEntropySetup;
    sigmatch_table[DETECT_ENTROPY].Free = DetectEntropyFree;
    //sigmatch_table[DETECT_ENTROPY].RegisterTests = DetectUrilenRegisterTests;
    SCLogInfo("Register");
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

	printf("Init\n");

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

	printf("IPv4 id: %d, offset: %d, len: %d\n", p->ip4h->ip_id, p->ip4h->ip_off, p->payload_len);

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

	printf("Entropy: %f, %f, Target: %f\n", entropy, ed->entropy);

	return entropy >= ed->entropy;
}

void DetectEntropyFree (void * ptr) {
	DetectEntropyData *ed = (DetectEntropyData*) ptr;
	SCFree(ed);
}
