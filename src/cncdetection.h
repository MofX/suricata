
typedef struct CNCDetection_ {
	float entropy;
	uint8_t uniqueBytes;
	uint8_t flags;
} CNCDetection;

#define CNC_ENTROPY				(1)
#define CNC_UNIQUEBYTES			(1<<1)
