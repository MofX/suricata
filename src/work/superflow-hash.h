#ifndef __SUPERFLOW_HASH_H__
#define __SUPERFLOW_HASH_H__

#include <stdint.h>

#include "superflow.h"

#define HASH_BKT_CAPACITY_THRESH 10      /* expand when bucket count reaches */

#ifndef uthash_fatal
#define uthash_fatal(msg) exit(-1)        /* fatal error (out of memory,etc) */
#endif
#ifndef uthash_malloc
#define uthash_malloc(sz) malloc(sz)      /* malloc fcn                      */
#endif
#ifndef uthash_free
#define uthash_free(ptr,sz) free(ptr)     /* free fcn                        */
#endif

#ifndef uthash_noexpand_fyi
#define uthash_noexpand_fyi(tbl)          /* can be defined to log noexpand  */
#endif
#ifndef uthash_expand_fyi
#define uthash_expand_fyi(tbl)            /* can be defined to log expands   */
#endif

struct Superflow_;
union SuperflowKey_;

typedef struct UT_hash_bucket_ {
   uint32_t hh_head;
   unsigned count;

   /* expand_mult is normally set to 0. In this situation, the max chain length
    * threshold is enforced at its default value, HASH_BKT_CAPACITY_THRESH. (If
    * the bucket's chain exceeds this length, bucket expansion is triggered).
    * However, setting expand_mult to a non-zero value delays bucket expansion
    * (that would be triggered by additions to this particular bucket)
    * until its chain length reaches a *multiple* of HASH_BKT_CAPACITY_THRESH.
    * (The multiplier is simply expand_mult+1). The whole idea of this
    * multiplier is to reduce bucket expansions, since they are expensive, in
    * situations where we know that a particular bucket tends to be overused.
    * It is better to let its chain length grow to a longer yet-still-bounded
    * value, than to do an O(n) bucket expansion too often.
    */
   unsigned expand_mult;
} UT_hash_bucket;

/* random signature used only to find hash tables in external analysis */
#define HASH_SIGNATURE 0xa0111fe1
#define HASH_BLOOM_SIGNATURE 0xb12220f2

typedef struct UT_hash_table_ {
   struct UT_hash_bucket_ *buckets;
   unsigned num_buckets, log2_num_buckets;
   unsigned num_items;
   uint32_t tail; /* tail hh in app order, for fast append    */
   uint32_t head; /* tail hh in app order, for fast append    */

   /* in an ideal situation (all buckets used equally), no bucket would have
    * more than ceil(#items/#buckets) items. that's the ideal chain length. */
   unsigned ideal_chain_maxlen;

   /* nonideal_items is the number of items in the hash whose chain position
    * exceeds the ideal chain maxlen. these items pay the penalty for an uneven
    * hash distribution; reaching them in a chain traversal takes >ideal steps */
   unsigned nonideal_items;

   /* ineffective expands occur when a bucket doubling was performed, but
    * afterward, more than half the items in the hash had nonideal chain
    * positions. If this happens on two consecutive expansions we inhibit any
    * further expansion, as it's not helping; this happens when the hash
    * function isn't a good fit for the key domain. When expansion is inhibited
    * the hash will still work, albeit no longer in constant time. */
   unsigned ineff_expands, noexpand;

   unsigned hashv;                   /* result of hash-fcn(key)        */

   uint32_t signature; /* used only to find hash tables in external analysis */
#ifdef HASH_BLOOM
   uint32_t bloom_sig; /* used only to test bloom exists in external analysis */
   uint8_t *bloom_bv;
   char bloom_nbits;
#endif

   struct Superflow_* base;

} UT_hash_table;

typedef struct UT_hash_handle_ {
   uint32_t prev;                       /* index to prev element in app order      */
   uint32_t next;                       /* index to next element in app order      */
   uint32_t hh_prev;					/* index to previous hh in bucket order    */
   uint32_t hh_next;					/* index to next hh in bucket order        */
   unsigned hashv;						/* result of hash-fcn(key)        */
} UT_hash_handle;


struct UT_hash_table_ * superflow_hash_new(struct Superflow_* base);
void superflow_hash_free(struct UT_hash_table_* tbl);
struct Superflow_* superflow_hash_get_head(struct UT_hash_table_ *tbl);
struct Superflow_* superflow_hash_next(struct UT_hash_table_ *tbl, struct Superflow_* current);
void superflow_hash_add(struct UT_hash_table_ *tbl, struct Superflow_* value);
void superflow_hash_touch(struct UT_hash_table_ *tbl, struct Superflow_* value);
struct Superflow_* superflow_hash_find(struct UT_hash_table_ * tbl, struct Superflow_* value);
struct Superflow_* superflow_hash_find_by_key(struct UT_hash_table_ * tbl, union SuperflowKey_ *key);
void superflow_hash_del(struct UT_hash_table_ * tbl, struct Superflow_* value);
unsigned int superflow_hash_count(struct UT_hash_table_ *tbl);

void SuperflowHashRegisterTests();

#endif //__SUPERFLOW_HASH_H__
