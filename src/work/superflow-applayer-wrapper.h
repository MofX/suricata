/**
 * \file
 * \author Jörg Vehlow <fh@jv-coder.de>
 *
 */
#ifndef __SUPERFLOW_WRAPPER_H__
#define __SUPERFLOW_WRAPPER_H__

int SuperflowHandleTCPData(Packet *p, AlpProtoDetectThreadCtx *dp_ctx, Flow *f,
        TcpSession *ssn, uint8_t *data, uint32_t data_len, uint8_t flags);

#endif //__SUPERFLOW_WRAPPER_H__
