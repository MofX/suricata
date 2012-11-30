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

#define PARSE_REGEX "^\\s*\"?\\s*(?:(?:(?:offset:\\s*(\\d+))|(?:len:\\s*([124])))(?:\\s+|\"?$))+$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectPayloadLenFieldSetup (DetectEngineCtx *, Signature *, char *);
void DetectPayloadLenFieldFree (void *);
int DetectPayloadLenFieldMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m);
static void DetectPayloadLenFieldRegisterTests(void);

typedef struct DetectPayloadLenFieldData_ {
    uint32_t offset;
    uint8_t len;
} DetectPayloadLenFieldData;

void DetectPayloadLenFieldRegister(void) {
    sigmatch_table[DETECT_PAYLOADLENFIELD].name = "payloadlenfield";
    sigmatch_table[DETECT_PAYLOADLENFIELD].Match = DetectPayloadLenFieldMatch;
    sigmatch_table[DETECT_PAYLOADLENFIELD].Setup = DetectPayloadLenFieldSetup;
    sigmatch_table[DETECT_PAYLOADLENFIELD].Free = DetectPayloadLenFieldFree;
    sigmatch_table[DETECT_PAYLOADLENFIELD].RegisterTests = DetectPayloadLenFieldRegisterTests;

    const char *eb;
    int eo;

    parse_regex = pcre_compile(PARSE_REGEX, 0, &eb, &eo, NULL);

    if (parse_regex == NULL) {
    	SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
    	goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
        if(eb != NULL)
        {
            SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
            goto error;
        }
        return;

error:
	return;
}

static int DetectPayloadLenFieldParse(DetectPayloadLenFieldData *dt, const char * sig) {
	char *args[3] = {NULL,NULL,NULL};
	#define MAX_SUBSTRINGS 30
	int ret = 0, res = 0;
	int ov[MAX_SUBSTRINGS];

	dt->offset = 0;

	ret = pcre_exec(parse_regex, parse_regex_study, sig, strlen(sig), 0, 0, ov, MAX_SUBSTRINGS);
	if (ret < 3) goto error;

	const char *str_ptr;
	pcre_get_substring(sig, ov, MAX_SUBSTRINGS, 1, &str_ptr);
	if (strlen(str_ptr)) {
		dt->offset = atoi(str_ptr);
	}

	pcre_get_substring(sig, ov, MAX_SUBSTRINGS, 2, &str_ptr);
	if (strlen(str_ptr)) {
		dt->len = atoi(str_ptr);
	}

	return 1;

error:
	return -1;
}

static int DetectPayloadLenFieldSetup (DetectEngineCtx * ctx, Signature * s, char * str) {
	DetectPayloadLenFieldData *ed = NULL;
	SigMatch *sm = NULL;

	ed = SCMalloc(sizeof(DetectPayloadLenFieldData));
	sm = SigMatchAlloc();
	if (sm == NULL)
		goto error;

	if (DetectPayloadLenFieldParse(ed, str) == -1) {
		printf("Parse failed: %s\n", str);
		goto error;
	}

	sm->type = DETECT_PAYLOADLENFIELD;

	sm->ctx = (void*) ed;


	SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

	return 0;

	error:
	    if (sm != NULL) SCFree(sm);
	    if (ed != NULL) SCFree(ed);

	    printf("Setup failed\n");

	    return -1;
}


int DetectPayloadLenFieldMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m) {
	DetectPayloadLenFieldData *ed = m->ctx;

	if (p->ip4h == NULL || PKT_IS_PSEUDOPKT(p) || p->payload_len == 0 || p->payload_len < ed->len + ed->offset)
		return 0;

	uint32_t read_len = 0;

	// This works just for little endian systems and streams
	memcpy(((char*)&read_len), p->payload + ed->offset, ed->len);

	//printf("Found len: %d\n", read_len);


	return read_len == p->payload_len;
}

void DetectPayloadLenFieldFree (void * ptr) {
	DetectPayloadLenFieldData *ed = (DetectPayloadLenFieldData*) ptr;
	SCFree(ed);
}

#ifdef UNITTESTS
static int PayloadLenFieldParseTest1() {
	DetectPayloadLenFieldData dt;

	DetectPayloadLenFieldParse(&dt, "offset:3 len:1");

	return dt.offset == 3 && dt.len == 1;
}

static int PayloadLenFieldParseTest2() {
	DetectPayloadLenFieldData dt;

	DetectPayloadLenFieldParse(&dt, "len:1    offset:3");

	return dt.offset == 3 && dt.len == 1;
}

static int PayloadLenFieldParseTest3() {
	DetectPayloadLenFieldData dt;

	DetectPayloadLenFieldParse(&dt, "len:1");

	return dt.offset == 0 && dt.len == 1;
}

static int PayloadLenFieldParseTest4() {
	DetectPayloadLenFieldData dt;

	DetectPayloadLenFieldParse(&dt, "\"len:1\"");

	return dt.offset == 0 && dt.len == 1;
}

static int PayloadLenFieldTest1() {
	uint8_t payload[] = {
			1,2,3,4,5,6,7,8,9,10
	};
	uint8_t len = sizeof(payload);

	payload[2] = len;

	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	int res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; payloadlenfield:offset:2 len:1; sid:1;)");

	UTHFreePacket(p);

	return res;
}

static int PayloadLenFieldTest2() {
	uint8_t payload[4096];

	uint16_t len = sizeof(payload);

	memcpy(payload + 2, &len, 4);

	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	int res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; payloadlenfield:offset:2 len:4; sid:1;)");

	UTHFreePacket(p);

	return res;
}

static int PayloadLenFieldTest3() {
	uint8_t payload[256];
	for (int i = 0; i < 256; ++i) {
		payload[i] = i;
	}

	uint16_t len = sizeof(payload);

	memcpy(payload + 1, &len, 2);

	Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

	int res = UTHPacketMatchSig(p, "alert tcp any any -> any any (msg:\"dummy\"; payloadlenfield:offset:1 len:2; sid:1;)");

	UTHFreePacket(p);

	return res;
}

#endif

void DetectPayloadLenFieldRegisterTests(void) {
#ifdef UNITTESTS
	UtRegisterTest("PayloadLenFieldParseTest1", PayloadLenFieldParseTest1, 1);
	UtRegisterTest("PayloadLenFieldParseTest2", PayloadLenFieldParseTest2, 1);
	UtRegisterTest("PayloadLenFieldParseTest3", PayloadLenFieldParseTest3, 1);
	UtRegisterTest("PayloadLenFieldParseTest4", PayloadLenFieldParseTest4, 1);
	UtRegisterTest("PayloadLenFieldTest1", PayloadLenFieldTest1, 1);
	UtRegisterTest("PayloadLenFieldTest2", PayloadLenFieldTest2, 1);
	UtRegisterTest("PayloadLenFieldTest3", PayloadLenFieldTest3, 1);
#endif
}

