/**
 * \file
 * \author Jörg Vehlow <fh@jv-coder.de>
 *
 * This file provides a wrapper around the original AppLayerHandleTCPData from app-layer.c.
 *
 * The wrapper function ensures that it get's all the data it needs and it calls the superflow
 * handlers and the applayer parsers afterwards.
 *
 */

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

//#define PRINT

/**
 * This is the main wrapper function. It gets called from app-layer.c when there is packet
 * payload available or the stream is closed.
 * flags will be a combination of STREAM_*
 * Important flags are STREAM_TOCLIENT, STREAM_TOSERVER and STREAM_EOF
 *
 * The most challenging part of this function is about the data being parsed to this function and the
 * data the app layer parser needs.
 *
 * This function can get called multiple times with the same data. Each time there will be some more
 * data. This may look like:
 * 		"GET"
 * 		"GET /"
 * 		"GET / HTTP/1.1"
 * The data begins with the first byte of the stream until an applayer parser tell suricata,
 * that it parsed the data. Then suricata will only pass new data.
 *
 * Because the superflow parser needs only new data, this wrapper always tells suricata, that an
 * applayer parsed the data. This way only new data gets passed to this function.
 * The applayer still requires getting old data as well. For that reason a buffer is filled with the
 * data parsed from suricata until the applayer parser has parsed the data successfully.
 *
 * If the applayer parser is done parsing the superflow parser might still require data.
 * For that reason suricata is told to pass data until the superflow parser is ready
 * (all msg buffers are filled) and the applayer parser is done.
 */
int SuperflowHandleTCPData(Packet *p, AlpProtoDetectThreadCtx *dp_ctx, Flow *f,
        TcpSession *ssn, uint8_t *data, uint32_t data_len, uint8_t flags) {

#ifdef PRINT
    if (data_len > 0) {
        printf("=> Init Stream Data (app layer) -- start %s%s\n",
                flags & STREAM_TOCLIENT ? "toclient" : "",
                flags & STREAM_TOSERVER ? "toserver" : "");
        PrintRawDataFp(stdout, data, data_len);
        printf("=> Init Stream Data -- end\n");
    } else {
    	printf("=> Got stream Data with zero length:%u\n", flags);
    }
#endif

    //return SuperflowDispatchAppLayer(dp_ctx, f, ssn, data, data_len, flags);

	static uint32_t filtered_flow_flags = FLOW_NO_APPLAYER_INSPECTION;
	static uint32_t filtered_tcpstream_flags = STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;

    SuperflowState *sst = &f->superflow_state;
    FlowBuffer *flowBuffer;
    // Write received buffer to internal buffer
    // TODO: This can be skipped after the parser has parsed the data once.
    if (data_len > 0) {
		if (flags & STREAM_TOSERVER) {
			flowBuffer = &sst->buffer_to_server;
		} else {
			flowBuffer = &sst->buffer_to_client;
		}
		if (data_len > (uint16_t)(flowBuffer->capacity - flowBuffer->size)) {
			// TODO: Stop filling the buffer after a specified number of bytes
			uint32_t size = flowBuffer->size + data_len;
			//printf("Reallocating superflow buffer from %u to %u\n", d->capacity, size);
			flowBuffer->buffer = realloc(flowBuffer->buffer, size);

			if (!flowBuffer->buffer) {
				printf("Realloc failed\n");
				exit(-1);
			}

			flowBuffer->capacity = size;
		}

		memcpy(flowBuffer->buffer + flowBuffer->size, data, data_len);
		flowBuffer->size += data_len;
    }

    // Restore flags to build a consistent state when calling the applayer parser
    f->flags = (f->flags & ~filtered_flow_flags) | f->superflow_state.flow_flags;
    ssn->flags = (ssn->flags & ~filtered_tcpstream_flags) | f->superflow_state.tcpstream_flags;
    if (sst->tcpstream_flags & STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED) {
    	flags = flags & ~STREAM_START;
    } else {
    	flags |= STREAM_START;
    }

    if (data_len == 0) {
    	if (flags & STREAM_EOF) {
    		// Tell the superflow parser, that the stream has ended
    		MessageOnStreamEnd(p);
    	}
    	// Dispatch the data to the default applayer parser
    	SuperflowDispatchAppLayer(dp_ctx, f, ssn, data, 0, flags);
    } else {
    	// Tell the superflow parser, that data arrived
    	MessageAdd(p, data, data_len, flags);

    	// Dispatch the data to the default applayer parser
    	char * b = flowBuffer->buffer + flowBuffer->posRead;
    	int size = flowBuffer->size - flowBuffer->posRead;

    	if (flowBuffer->posRead < 0) {
    		printf("Posread is less than zero\n");
    		exit(-1);
    	}

    	if (b >= flowBuffer->buffer + flowBuffer->capacity) {
    		printf("Current buffer position is beyond it's capacity, %d, %llx > %llx\n", size, b, flowBuffer->buffer + flowBuffer->capacity);
    		exit(-1);
    	}

    	if (b + size > flowBuffer->buffer + flowBuffer->capacity) {
    		printf("Buffer end is beyond it's capacity, %x, %llx > %llx\n", size, b, flowBuffer->buffer + flowBuffer->capacity);
    		exit(-1);
    	}


    	SuperflowDispatchAppLayer(dp_ctx, f, ssn, flowBuffer->buffer + flowBuffer->posRead, flowBuffer->size - flowBuffer->posRead, flags);
        if (ssn->flags & STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED) {
        	// The app layer parser has parsed the data.
        	// That means we can drop the data in the buffer.
        	flowBuffer->posRead = flowBuffer->size;
        }
    }

    // backup the flag state seen by the applayer parser
    sst->tcpstream_flags = ssn->flags & filtered_tcpstream_flags;
    sst->flow_flags = f->flags & filtered_flow_flags;
    f->flags &= ~filtered_flow_flags;

    // set the flags seen by suricata
    if ((sst->flow_flags & FLOW_NO_APPLAYER_INSPECTION) && (sst->flags & SUPERFLOW_FLAG_MESSAGE_OVERFLOW)) {
    	f->flags |= FLOW_NO_APPLAYER_INSPECTION;
    }
    ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;

    return 0;
}

/**
 * This is the original AppLayerHandleTCPData from app-layer.c
 */
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
