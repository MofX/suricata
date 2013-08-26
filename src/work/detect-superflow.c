#include <stdio.h>
#include <math.h>

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "app-layer-detect-proto.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-private.h"
#include "stream-tcp.h"

#include "detect-engine.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-superflow.h"

#include "superflow.h"

#define ENTROPY_REGEX "(?:e(?P<entropy_op>[>=\\<])?(?P<entropy_value>\\d+(?:\\.\\d+)?))"
#define LENGTH_REGEX  "(?:l(?P<length_op>[>=\\<])?(?P<length_value>\\d+))"
#define ONE_SFLOW_REGEX "(?:" ENTROPY_REGEX "?" LENGTH_REGEX "?)*"

#define TYPE_REGEX "(?:(?:(?P<type>[tu])\s*[:;]\s*)?)"
#define PARSE_REGEX "^\s*" TYPE_REGEX "(?P<sflows>.+)\s*$"
//"^\\s*(?P<entry>" ONE_SFLOW_REGEX ")+\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static pcre *parse_single_sflow_regex;
static pcre_extra *parse_single_sflow_regex_study;


static int DetectSuperflowSetup (DetectEngineCtx *, Signature *, char *);
void DetectSuperflowFree (void *);
int DetectSuperflowMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m);
static void DetectSuperflowRegisterTests(void);

#define OP_EQ 1
#define OP_GT 2
#define OP_LT 4

typedef struct DetectSuperflowDataMsg_ {
	int length;
	float entropy;
	uint16_t length_op;
	uint16_t entropy_op;
} DetectSuperflowDataMsg;

typedef struct DetectSuperflowData_ {
	DetectSuperflowDataMsg msgs[SUPERFLOW_MESSAGE_COUNT];
	uint32_t count;
	char flags;
} DetectSuperflowData;

#define DETECT_SUPERFLOW_FLAG_UDP 1
#define DETECT_SUPERFLOW_FLAG_TCP 2

void DetectSuperflowRegister(void) {
#ifdef SUPERFLOW_DEACTIVATE
	return;
#endif
    sigmatch_table[DETECT_SUPERFLOW].name = "superflow";
    sigmatch_table[DETECT_SUPERFLOW].Match = DetectSuperflowMatch;
    sigmatch_table[DETECT_SUPERFLOW].Setup = DetectSuperflowSetup;
    sigmatch_table[DETECT_SUPERFLOW].Free = DetectSuperflowFree;
    sigmatch_table[DETECT_SUPERFLOW].RegisterTests = DetectSuperflowRegisterTests;

    const char *eb;
    int eo;

    //printf("Regex: %s\n", ONE_SFLOW_REGEX);
    parse_single_sflow_regex = pcre_compile(ONE_SFLOW_REGEX, 0, &eb, &eo, NULL);
    if (parse_single_sflow_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",
        		ONE_SFLOW_REGEX, eo, eb);
        goto error;
    }

    parse_single_sflow_regex_study = pcre_study(parse_single_sflow_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    parse_regex = pcre_compile(PARSE_REGEX, 0, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",
        		PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

error:
	return;
}

static void DetectSuperflowInitData(DetectSuperflowData * sd) {
	sd->count = 0;
	sd->flags = 0;
	for (int i = 0; i < SUPERFLOW_MESSAGE_COUNT; ++i) {
		sd->msgs[i].entropy = sd->msgs[i].length = -1;
		sd->msgs[i].entropy_op = sd->msgs[i].length_op = OP_EQ;
	}
}

static DetectSuperflowData *DetectSuperflowParse(char * str) {
	DetectSuperflowData *sd = NULL;
	sd = SCMalloc(sizeof(DetectSuperflowData));
	if (sd == NULL)
		return NULL;

	DetectSuperflowInitData(sd);

	#define MAX_SUBSTRINGS 20
	int ret = 0, ret2 = 0;
	int ov[MAX_SUBSTRINGS];
	const char *buffer = NULL;
	const char *strSflows = NULL;

	ret = pcre_exec(parse_regex, parse_regex_study, str, strlen(str), 0, 0, ov, MAX_SUBSTRINGS);
	ret2 = pcre_get_named_substring(parse_regex, str, ov, ret, "sflows", &strSflows);
	if (ret2 <= 0) {
		printf("Error: No rules in superflow rule.\n");
		goto error;
	}

	ret2 = pcre_get_named_substring(parse_regex, str, ov, ret, "type", &buffer);
	if (ret2 > 0) {
		if (buffer[0] == 't' || buffer[0] == 'T') {
			sd->flags |= DETECT_SUPERFLOW_FLAG_TCP;
		} else if (buffer[0] == 'u' || buffer[0] == 'U') {
			sd->flags |= DETECT_SUPERFLOW_FLAG_UDP;
		}
	} else {
		sd->flags |= DETECT_SUPERFLOW_FLAG_TCP;
	}

	char *ch = strSflows;
	char *strend = ch + strlen(ch);
	int i = 0;
	while (ch && ch < strend) {
		if (i >= SUPERFLOW_MESSAGE_COUNT) {
			printf("Error: Too much entries in superflow rule.\n");
			goto error;
		}
		++sd->count;

		char* chnext = strchr(ch, ',');
		if (chnext) {
			*chnext = 0;
			++chnext;
		}
		ret = pcre_exec(parse_single_sflow_regex, parse_single_sflow_regex_study, ch, strlen(ch), 0, 0, ov, MAX_SUBSTRINGS);
		if (!ret) {
			goto error;
		}

		ret2 = pcre_get_named_substring(parse_single_sflow_regex, ch, ov, ret, "entropy_value", &buffer);
		if (ret2 > 0) {
			sd->msgs[i].entropy = atof(buffer);
			pcre_free_substring(buffer);
		}
		ret2 = pcre_get_named_substring(parse_single_sflow_regex, ch, ov, ret, "entropy_op", &buffer);
		if (ret2 > 0) {
			if (strcmp(buffer, ">") == 0) {
				sd->msgs[i].entropy_op = OP_GT;
			} else if (strcmp(buffer, "<") == 0) {
				sd->msgs[i].entropy_op = OP_LT;
			}
			pcre_free_substring(buffer);
		}

		buffer = NULL;
		ret2 = pcre_get_named_substring(parse_single_sflow_regex, ch, ov, ret, "length_value", &buffer);
		if (ret2 > 0) {
			sd->msgs[i].length = atof(buffer);
			pcre_free_substring(buffer);
		}
		ret2 = pcre_get_named_substring(parse_single_sflow_regex, ch, ov, ret, "length_op", &buffer);
		if (ret2 > 0) {
			if (strcmp(buffer, ">") == 0) {
				sd->msgs[i].length_op = OP_GT;
			} else if (strcmp(buffer, "<") == 0) {
				sd->msgs[i].length_op = OP_LT;
			}
			pcre_free_substring(buffer);
		}

		ch = chnext;
		++i;
	}

	goto end;
error:
	free(sd);
	sd = NULL;
end:
	pcre_free(strSflows);
	return sd;
}

static int DetectSuperflowSetup (DetectEngineCtx * ctx, Signature * s, char * str) {
	//printf("Setup\n");
	DetectSuperflowData *ed = NULL;
	SigMatch *sm = NULL;

	sm = SigMatchAlloc();
	if (sm == NULL)
		goto error;

	ed = DetectSuperflowParse(str);

	//printf("Rule \"%s\" flags:%u, count:%u\n", str, ed->flags, ed->count);

	sm->type = DETECT_SUPERFLOW;
	sm->ctx = (void*) ed;


	SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

	return 0;

	error:
	    if (sm != NULL) SCFree(sm);
	    if (ed != NULL) SCFree(ed);

	    return -1;
}


int DetectSuperflowMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m) {
	DetectSuperflowData *sd = m->ctx;
	//printf("MATCH\n");

	if (p->ip4h == NULL || PKT_IS_PSEUDOPKT(p) || !PKT_IS_IPV4(p) || !p->flow || !p->flow->superflow_state.superflow)
		return 0;

	if ((sd->flags & DETECT_SUPERFLOW_FLAG_TCP) && !PKT_IS_TCP(p))
		return 0;

	if ((sd->flags & DETECT_SUPERFLOW_FLAG_UDP) && !PKT_IS_UDP(p))
		return 0;


	Superflow *sflow = p->flow->superflow_state.superflow;

	FLOWLOCK_RDLOCK(sflow);
	// It is probably possible to unlock the mutex now. That way it just acts as a memory barrier

	//printf("Checking %d msgs\n", sd->count);

	// There may be more messages in the Superflow than defined in the rule.
	if (sflow->messageCount < sd->count) goto error;

	for (int i = 0; i < sd->count; ++i) {
		DetectSuperflowDataMsg *msg = &sd->msgs[i];
		SuperflowMessage *sflow_msg = &sflow->msgs[i];

		// The last message may not be finished yet
		if (unlikely(!(sflow_msg->flags & SUPERFLOW_MESSAGE_FLAG_INUSE))) goto error;

		/*printf("Msg %d: %d / %0.2f got(valid: %d) %d / %f\n",
				i, msg->length, msg->entropy,
				sflow->messageCount > i && (sflow_msg->flags & SUPERFLOW_MESSAGE_FLAG_INUSE),
				sflow_msg->length, SuperflowGetEntropy(sflow_msg));*/

		if (msg->entropy >= 0) {
			float entropy = SuperflowGetEntropy(sflow_msg);
			switch (msg->entropy_op) {
			case OP_EQ:
				if (msg->entropy != entropy) goto error;
				break;
			case OP_LT:
				if (msg->entropy < entropy) goto error;
				break;
			case OP_GT:
				if (msg->entropy > entropy) goto error;
				break;
			}
		}

		if (msg->length >= 0) {
			switch (msg->length_op) {
			case OP_EQ:
				if (msg->length != sflow_msg->length) goto error;
				break;
			case OP_LT:
				if (msg->length < sflow_msg->length) goto error;
				break;
			case OP_GT:
				if (msg->length > sflow_msg->length) goto error;
				break;
			}
		}
	}

	int res = 1;
	goto end;
error:
	res = 0;
end:
	FLOWLOCK_UNLOCK(sflow);
	return res;
}

void DetectSuperflowFree (void * ptr) {
	DetectSuperflowData *ed = (DetectSuperflowData*) ptr;
	SCFree(ed);
}

#ifdef UNITTESTS

static int ParseTest1() {
	DetectSuperflowData * sd = NULL;
	DetectSuperflowData exp;
	DetectSuperflowInitData(&exp);
	exp.msgs[0].entropy = 0.1;
	exp.msgs[0].entropy_op = OP_GT;
	exp.count = 1;
	exp.flags = DETECT_SUPERFLOW_FLAG_TCP;
	sd = DetectSuperflowParse("e>0.1");

	if (memcmp(&exp, sd, sizeof(DetectSuperflowData))) {
		goto error;
	}

	return 1;
error:
	free(sd);
	return -1;
}

static int ParseTest2() {
	DetectSuperflowData * sd = NULL;
	DetectSuperflowData exp;
	DetectSuperflowInitData(&exp);
	exp.msgs[0].length = 12;
	exp.msgs[0].length_op = OP_GT;
	exp.count = 1;
	exp.flags = DETECT_SUPERFLOW_FLAG_TCP;
	sd = DetectSuperflowParse("l>12");

	if (memcmp(&exp, sd, sizeof(DetectSuperflowData))) {
		goto error;
	}

	return 1;
error:
	free(sd);
	return -1;
}

static int ParseTest3() {
	DetectSuperflowData * sd = NULL;
	DetectSuperflowData exp;
	DetectSuperflowInitData(&exp);
	exp.msgs[0].entropy = 0.1;
	exp.msgs[0].length = 12;
	exp.count = 1;
	exp.flags = DETECT_SUPERFLOW_FLAG_TCP;
	sd = DetectSuperflowParse("l12e0.1");

	if (memcmp(&exp, sd, sizeof(DetectSuperflowData))) {
		goto error;
	}

	return 1;
error:
	free(sd);
	return -1;
}

static int ParseTest4() {
	DetectSuperflowData * sd = NULL;
	DetectSuperflowData exp;
	DetectSuperflowInitData(&exp);
	exp.msgs[0].entropy = 0.1;
	exp.msgs[0].length = 12;
	exp.msgs[1].entropy = 0.3;
	exp.msgs[2].length = 345;
	exp.msgs[2].length_op = OP_LT;
	exp.msgs[4].entropy = 0.2;
	exp.count = 5;
	exp.flags = DETECT_SUPERFLOW_FLAG_TCP;
	const char* str = "l12e0.1,e0.3,l<345,,e0.2";
	char buffer[1024];
	memcpy(buffer, str, strlen(str));
	sd = DetectSuperflowParse(buffer);

	if (memcmp(&exp, sd, sizeof(DetectSuperflowData))) {
		goto error;
	}

	return 1;
error:
	free(sd);
	return -1;
}

static int ParseTest5() {
	DetectSuperflowData * sd = NULL;
	DetectSuperflowData exp;
	DetectSuperflowInitData(&exp);
	exp.msgs[0].entropy = 0.1;
	exp.msgs[0].length = 12;
	exp.msgs[1].length = 25;
	exp.msgs[1].entropy = 0.3;
	exp.count = 2;
	exp.flags = DETECT_SUPERFLOW_FLAG_TCP;
	const char* str = "l12e0.1,e0.3l25";
	char buffer[1024];
	memcpy(buffer, str, strlen(str));
	sd = DetectSuperflowParse(buffer);

	if (memcmp(&exp, sd, sizeof(DetectSuperflowData))) {
		goto error;
	}

	return 1;
error:
	free(sd);
	return -1;
}

static int ParseTest6() {
	DetectSuperflowData * sd = NULL;
	DetectSuperflowData exp;
	char buffer[1024];
	char buffer2[1024];
	memset(buffer, 0, 1024);
	DetectSuperflowInitData(&exp);
	for (int i = 0; i < SUPERFLOW_MESSAGE_COUNT; ++i) {
		exp.msgs[i].entropy = i/100.;
		exp.msgs[i].length = i;

		char localbuffer[100];
		sprintf(localbuffer, "%sl%de%0.2f", i > 0 ? "," : "", exp.msgs[i].length, exp.msgs[i].entropy);

		strcat(buffer, localbuffer);
	}
	exp.count = SUPERFLOW_MESSAGE_COUNT;
	exp.flags = DETECT_SUPERFLOW_FLAG_TCP;
	memcpy(buffer2, buffer, 1024);
	sd = DetectSuperflowParse(buffer);

	if (memcmp(&exp, sd, sizeof(DetectSuperflowData))) {
		goto error;
	}
	free(sd);
	sd = NULL;

	strcat(buffer2, ",l10,l11");
	sd = DetectSuperflowParse(buffer2);
	if (sd != NULL) goto error;

	free(sd);
	return 1;
error:
	free(sd);
	return -1;
}

static int ParseTest7() {
	DetectSuperflowData * sd = NULL;
	DetectSuperflowData exp;
	DetectSuperflowInitData(&exp);
	exp.msgs[0].entropy = 0.1;
	exp.msgs[0].length = 12;
	exp.msgs[1].length = 25;
	exp.msgs[1].entropy = 0.3;
	exp.count = 2;
	exp.flags = DETECT_SUPERFLOW_FLAG_UDP;
	const char* str = "u;l12e0.1,e0.3l25";
	char buffer[1024];
	memcpy(buffer, str, strlen(str));
	sd = DetectSuperflowParse(buffer);

	if (memcmp(&exp, sd, sizeof(DetectSuperflowData))) {
		goto error;
	}

	return 1;
error:
	free(sd);
	return -1;
}

static int ParseTest8() {
	DetectSuperflowData * sd = NULL;
	DetectSuperflowData exp;
	DetectSuperflowInitData(&exp);
	exp.msgs[0].entropy = 0.1;
	exp.msgs[0].length = 12;
	exp.msgs[1].length = 25;
	exp.msgs[1].entropy = 0.3;
	exp.count = 2;
	exp.flags = DETECT_SUPERFLOW_FLAG_TCP;
	const char* str = "t;l12e0.1,e0.3l25";
	char buffer[1024];
	memcpy(buffer, str, strlen(str));
	sd = DetectSuperflowParse(buffer);

	if (memcmp(&exp, sd, sizeof(DetectSuperflowData))) {
		goto error;
	}

	return 1;
error:
	free(sd);
	return -1;
}

// Prototype for private method required for injecting packets into suricata.
TmEcode StreamTcp (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq);

/**
 * Creates a packet with the specified properties and injects it into suricate at a very low point.
 * The packet is inserted where the lowest layers (like ethernet) deliver their decoded packets to.
 */
static Packet * emitTCPPacket(char* data, uint32_t data_len, uint8_t flags, char* src, char* dst, uint16_t srcport, uint16_t dstport,
						uint32_t * seq, uint32_t * ack, struct timeval ts, ThreadVars *tv,
					    StreamTcpThread *stt, PacketQueue *pq) {
    Packet *p = UTHBuildPacketReal((uint8_t*) data, data_len, IPPROTO_TCP, src, dst, srcport, dstport);
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
 * Create a TCP stream and match it against a superflow rule.
 */
int Test1() {
	FlowInitConfig(1);
	AlpProtoDetectThreadCtx dp_ctx;
	AlpProtoFinalize2Thread(&dp_ctx);
	DetectEngineCtx *de_ctx = DetectEngineCtxInit();
	DetectEngineThreadCtx *det_ctx = NULL;
	SuperflowInit(1);
	StreamTcpInitConfig(1);

    ThreadVars tv;
    ThreadVars tv_dt;
    StreamTcpThread stt;
    PacketQueue pq;
    TcpReassemblyThreadCtx ra_ctx;
    StreamMsgQueue stream_q;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset(&stream_q, 0, sizeof(StreamMsgQueue));
    memset(&tv, 0, sizeof(tv));
    memset(&tv_dt, 0, sizeof(tv_dt));

    de_ctx->flags |= DE_QUIET;

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

    char * sig = "alert tcp any any -> any any (msg:\"dummy\"; superflow:l5e<0.5,; sid:1;)";
    de_ctx->sig_list = SigInit(de_ctx, sig);
	if (de_ctx->sig_list == NULL) {
		printf("Sig list is NULL\n");
		goto error;
	}
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv_dt, (void *)de_ctx, (void *)&det_ctx);

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

    ts.tv_usec = (g_superflow_message_timeout + 1) * 1000;

    p = emitTCPPacket("test2", 6, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("test345", 7, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);

    SigMatchSignatures(&tv_dt, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, de_ctx->sig_list->id) != 1) {
    	UTHFreePacket(p);
		goto error;
	}
    UTHFreePacket(p);

	int r = 1;
	goto end;
error:
	r = -1;
end:
	if (de_ctx) {
		SigGroupCleanup(de_ctx);
		SigCleanSignatures(de_ctx);
	}
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
	FlowShutdown();
	SuperflowFree();
	AlpProtoDeFinalize2Thread(&dp_ctx);
	StreamTcpFreeConfig(TRUE);
	return r;
}

/**
 * Create a TCP stream and match it against a superflow UDP rule -> fail.
 */
int Test2() {
	FlowInitConfig(1);
	AlpProtoDetectThreadCtx dp_ctx;
	AlpProtoFinalize2Thread(&dp_ctx);
	DetectEngineCtx *de_ctx = DetectEngineCtxInit();
	DetectEngineThreadCtx *det_ctx = NULL;
	SuperflowInit(1);
	StreamTcpInitConfig(1);

    ThreadVars tv;
    ThreadVars tv_dt;
    StreamTcpThread stt;
    PacketQueue pq;
    TcpReassemblyThreadCtx ra_ctx;
    StreamMsgQueue stream_q;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset(&stream_q, 0, sizeof(StreamMsgQueue));
    memset(&tv, 0, sizeof(tv));
    memset(&tv_dt, 0, sizeof(tv_dt));

    de_ctx->flags |= DE_QUIET;

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

    char * sig = "alert udp any any -> any any (msg:\"dummy\"; superflow:u:l5e<0.5,; sid:1;)";
    de_ctx->sig_list = SigInit(de_ctx, sig);
	if (de_ctx->sig_list == NULL) {
		printf("Sig list is NULL\n");
		goto error;
	}
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv_dt, (void *)de_ctx, (void *)&det_ctx);

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

    ts.tv_usec = (g_superflow_message_timeout + 1) * 1000;

    p = emitTCPPacket("test2", 6, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("test345", 7, TH_ACK, "45.12.45.78", "54.54.65.85", client_port, server_port, &seq_to_server, &seq_to_client, ts, &tv, &stt, &pq);
    UTHFreePacket(p);

    p = emitTCPPacket("", 0, TH_ACK, "54.54.65.85", "45.12.45.78", server_port, client_port, &seq_to_client, &seq_to_server, ts, &tv, &stt, &pq);

    SigMatchSignatures(&tv_dt, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, de_ctx->sig_list->id) == 1) {
    	UTHFreePacket(p);
		goto error;
	}
    UTHFreePacket(p);

	int r = 1;
	goto end;
error:
	r = -1;
end:
	if (de_ctx) {
		SigGroupCleanup(de_ctx);
		SigCleanSignatures(de_ctx);
	}
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
	FlowShutdown();
	SuperflowFree();
	AlpProtoDeFinalize2Thread(&dp_ctx);
	StreamTcpFreeConfig(TRUE);
	return r;
}

#endif

void DetectSuperflowRegisterTests(void) {
#ifdef UNITTESTS
	UtRegisterTest("DetectSuperflowParseTest1", ParseTest1, 1);
	UtRegisterTest("DetectSuperflowParseTest2", ParseTest2, 1);
	UtRegisterTest("DetectSuperflowParseTest3", ParseTest3, 1);
	UtRegisterTest("DetectSuperflowParseTest4", ParseTest4, 1);
	UtRegisterTest("DetectSuperflowParseTest5", ParseTest5, 1);
	UtRegisterTest("DetectSuperflowParseTest6", ParseTest6, 1);
	UtRegisterTest("DetectSuperflowParseTest7", ParseTest7, 1);
	UtRegisterTest("DetectSuperflowParseTest8", ParseTest8, 1);
#ifndef SUPERFLOW_DEACTIVATE
	UtRegisterTest("DetectSuperflowTest1", Test1, 1);
	UtRegisterTest("DetectSuperflowTest2", Test2, 1);
#endif
#endif
}
