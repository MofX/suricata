
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

#include "work/superflow.h"
#include "work/superflow-applayer-wrapper.h"
#include "work/message.h"

int SuperflowDispatchAppLayer(AlpProtoDetectThreadCtx *dp_ctx, Flow *f,
        TcpSession *ssn, uint8_t *data, uint32_t data_len, uint8_t flags);

int SuperflowHandleTCPData(Packet *p, AlpProtoDetectThreadCtx *dp_ctx, Flow *f,
        TcpSession *ssn, uint8_t *data, uint32_t data_len, uint8_t flags) {

#ifdef PRINT
    if (data_len > 0) {
        printf("=> Init Stream Data (app layer) -- start %s%s\n",
                flags & STREAM_TOCLIENT ? "toclient" : "",
                flags & STREAM_TOSERVER ? "toserver" : "");
        PrintRawDataFp(stdout, data, data_len);
        printf("=> Init Stream Data -- end\n");
    }
#endif

    //return SuperflowDispatchAppLayer(dp_ctx, f, ssn, data, data_len, flags);



	static unsigned int filtered_flow_flags = FLOW_NO_APPLAYER_INSPECTION;
	static unsigned int filtered_tcpstream_flags = STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
    SCEnter();

    SuperflowState *sst = &f->superflow_state;
    FlowBuffer *d;
    if (data_len > 0) {
		if (flags & STREAM_TOSERVER) {
			d = &sst->buffer_to_server;
		} else {
			d = &sst->buffer_to_client;
		}
		if (data_len > d->capacity - d->size) {
			uint32_t size = d->size + data_len;
			//printf("Reallocating superflow buffer from %u to %u\n", d->capacity, size);
			d->buffer = realloc(d->buffer, size);
			d->capacity = size;
		}

		memcpy(d->buffer + d->size, data, data_len);
		d->size += data_len;
    }

    // Restore flags
    f->flags = (f->flags & ~filtered_flow_flags) | f->superflow_state.flow_flags;
    ssn->flags = (ssn->flags & ~filtered_tcpstream_flags) | f->superflow_state.tcpstream_flags;
    if (sst->tcpstream_flags & STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED) {
    	flags = flags & ~STREAM_START;
    } else {
    	flags |= STREAM_START;
    }

    if (data_len == 0) {
    	SuperflowDispatchAppLayer(dp_ctx, f, ssn, data, 0, flags);
    } else {
    	MessageAdd(p, data, data_len, flags);
    	SuperflowDispatchAppLayer(dp_ctx, f, ssn, d->buffer + d->posRead, d->size - d->posRead, flags);
        if (ssn->flags & STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED) {
        	d->posRead = d->size;
        }
    }

    // set flags
    sst->tcpstream_flags = ssn->flags & filtered_tcpstream_flags;
    sst->flow_flags = f->flags & filtered_flow_flags;
    f->flags &= ~filtered_flow_flags;

    if ((sst->flow_flags & FLOW_NO_APPLAYER_INSPECTION) && (sst->flags & SUPERFLOW_FLAG_MESSAGE_OVERFLOW)) {
    	f->flags |= FLOW_NO_APPLAYER_INSPECTION;
    }

    ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;

    SCReturnInt(0);
}

//#define PRINT

int SuperflowDispatchAppLayer(AlpProtoDetectThreadCtx *dp_ctx, Flow *f,
        TcpSession *ssn, uint8_t *data, uint32_t data_len, uint8_t flags) {
    DEBUG_ASSERT_FLOW_LOCKED(f);

    int r = 0;
#if DEBUG
    BUG_ON(f == NULL);
    BUG_ON(ssn == NULL);
#endif

    SCLogDebug("data_len %u flags %02X", data_len, flags);
    if (!(f->flags & FLOW_NO_APPLAYER_INSPECTION)) {
        /* if we don't know the proto yet and we have received a stream
         * initializer message, we run proto detection.
         * We receive 2 stream init msgs (one for each direction) but we
         * only run the proto detection once. */
        if (f->alproto == ALPROTO_UNKNOWN && (flags & STREAM_GAP)) {
            ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
            SCLogDebug("ALPROTO_UNKNOWN flow %p, due to GAP in stream start", f);
            StreamTcpSetSessionNoReassemblyFlag(ssn, 0);
        } else if (f->alproto == ALPROTO_UNKNOWN && (flags & STREAM_START)) {
            SCLogDebug("Stream initializer (len %" PRIu32 ")", data_len);
#ifdef PRINT
            if (data_len > 0) {
                printf("=> Init Stream Data (app layer) -- start %s%s\n",
                        flags & STREAM_TOCLIENT ? "toclient" : "",
                        flags & STREAM_TOSERVER ? "toserver" : "");
                PrintRawDataFp(stdout, data, data_len);
                printf("=> Init Stream Data -- end\n");
            }
#endif

            PACKET_PROFILING_APP_PD_START(dp_ctx);
            f->alproto = AppLayerDetectGetProto(&alp_proto_ctx, dp_ctx, f,
                    data, data_len, flags, IPPROTO_TCP);
            PACKET_PROFILING_APP_PD_END(dp_ctx);

            if (f->alproto != ALPROTO_UNKNOWN) {
                ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;

                PACKET_PROFILING_APP_START(dp_ctx, f->alproto);
                r = AppLayerParse(dp_ctx->alproto_local_storage[f->alproto], f, f->alproto, flags, data, data_len);
                PACKET_PROFILING_APP_END(dp_ctx, f->alproto);
            } else {
                if ((f->flags & FLOW_TS_PM_PP_ALPROTO_DETECT_DONE) &&
                    (f->flags & FLOW_TC_PM_PP_ALPROTO_DETECT_DONE)) {
                    FlowSetSessionNoApplayerInspectionFlag(f);
                    ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
                }
            }
        } else {
            SCLogDebug("stream data (len %" PRIu32 " alproto "
                    "%"PRIu16" (flow %p)", data_len, f->alproto, f);
#ifdef PRINT
            if (data_len > 0) {
                printf("=> Stream Data (app layer) -- start %s%s\n",
                        flags & STREAM_TOCLIENT ? "toclient" : "",
                        flags & STREAM_TOSERVER ? "toserver" : "");
                PrintRawDataFp(stdout, data, data_len);
                printf("=> Stream Data -- end\n");
            }
#endif
            /* if we don't have a data object here we are not getting it
             * a start msg should have gotten us one */
            if (f->alproto != ALPROTO_UNKNOWN) {
                PACKET_PROFILING_APP_START(dp_ctx, f->alproto);
                r = AppLayerParse(dp_ctx->alproto_local_storage[f->alproto], f, f->alproto, flags, data, data_len);
                PACKET_PROFILING_APP_END(dp_ctx, f->alproto);
            } else {
                SCLogDebug(" smsg not start, but no l7 data? Weird");
            }
        }
    } else {
    	//printf("!!!!!!!!!!!!!!!!!!!!!!!!\n");
        SCLogDebug("FLOW_AL_NO_APPLAYER_INSPECTION is set");
    }

    return r;
}
