/*
 * test.c
 *
 *  Created on: Jan 23, 2013
 *      Author: joerg
 */

#include "test.h"

#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"
#include "debug.h"
#include "detect.h"

#include "tm-threads.h"

#include "stream-tcp-private.h"
#include "stream.h"

#include "util-unittest.h"

TmEcode TestThreadInit(ThreadVars *tv, void *initdata, void **data);
TmEcode Test (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq);
void TestExitPrintStats(ThreadVars *tv, void *data);
TmEcode TestThreadDeinit(ThreadVars *tv, void *data);
void TestRegisterTests (void);

void TmModuleTestRegister (void)
{
	printf("Test: Register\n");
    tmm_modules[TMM_TEST].name = "Test";
    tmm_modules[TMM_TEST].ThreadInit = TestThreadInit;
    tmm_modules[TMM_TEST].Func = Test;
    tmm_modules[TMM_TEST].ThreadExitPrintStats = TestExitPrintStats;
    tmm_modules[TMM_TEST].ThreadDeinit = TestThreadDeinit;
    tmm_modules[TMM_TEST].RegisterTests = TestRegisterTests;
    tmm_modules[TMM_TEST].cap_flags = 0;
    tmm_modules[TMM_TEST].flags = TM_FLAG_TEST_TM;
}

TmEcode TestThreadInit(ThreadVars *tv, void *initdata, void **data)
{
	printf("Test: init\n");
	SCReturnInt(TM_ECODE_OK);
}

TmEcode Test (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
	if (PKT_IS_TCP(p))
	{
		FLOWLOCK_RDLOCK(p->flow);
		TcpSession* tcpSession = (TcpSession*) p->flow->protoctx;
		if (tcpSession) {
			StreamMsg* msg = tcpSession->toclient_smsg_head;
			//printf("To Client: ");
			//while (msg) {
			//	printf("%s", msg->data.data);
			//	msg = msg->next;
			//}
			//printf("\n-----\n");
		}
		FLOWLOCK_UNLOCK(p->flow);
	}
	//printf("Test: Test %d\n", PKT_IS_TCP(p));
	SCReturnInt(TM_ECODE_OK);
}

void TestExitPrintStats(ThreadVars *tv, void *data)
{
	printf("Test: ExitPrintStats\n");
}

TmEcode TestThreadDeinit(ThreadVars *tv, void *data)
{
	printf("Test: TestThreadDeinit\n");
	SCReturnInt(TM_ECODE_OK);
}

void TestRegisterTests (void) {
	printf("Test: TestRegisterTests\n");
#ifdef UNITTESTS
#endif
}
