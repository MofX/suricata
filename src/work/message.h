#ifndef __MESSAGE_H__
#define __MESSAGE_H__

void MessageAdd(Packet *p, uint8_t * data, uint32_t data_len, uint8_t flags);
void MessageSuperflowFinalize(SuperflowState* sfs);
void MessageOnStreamEnd(Packet *p);

void MessageRegisterTests();

#endif // __MESSAGE_H__
