#include <stdlib.h>
#include <memory.h>
#include <stdio.h>

#include "suricata-common.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "superflow.h"
#include "superflow-hash.h"

typedef struct UT_hash_table_ UT_hash_table;
typedef struct UT_hash_bucket_ UT_hash_bucket;


__inline Superflow * hash_index_to_superflow(UT_hash_table *tbl, uint32_t index) {
	if (index == 0) return NULL;
	return &tbl->base[index];
}

__inline uint32_t hash_superflow_to_index(UT_hash_table *tbl, Superflow* flow) {
	if (flow == NULL) return 0;
	return (uint32_t) (flow - tbl->base);
}

UT_hash_table * superflow_hash_new(Superflow* base) {
	const unsigned int initial_num_buckets_log2 = 24;
	const unsigned int initial_num_buckets = 1 << initial_num_buckets_log2; //power<2, initial_num_buckets_log2>::value;
	UT_hash_table *tbl = (UT_hash_table*) malloc(sizeof(UT_hash_table));
	memset(tbl, 0, sizeof(UT_hash_table));
	tbl->log2_num_buckets = initial_num_buckets_log2;
	tbl->num_buckets = initial_num_buckets;
	tbl->buckets = (UT_hash_bucket*)uthash_malloc(initial_num_buckets * sizeof(UT_hash_bucket));
	tbl->base = base - 1;
	if (! tbl->buckets) { uthash_fatal( "out of memory"); }
	memset(tbl->buckets, 0, initial_num_buckets*sizeof(UT_hash_bucket));

	tbl->signature = HASH_SIGNATURE;

	return tbl;
}

void superflow_hash_free(UT_hash_table* tbl) {
	if (tbl == NULL) return;

	if (tbl->num_items != 0) {
		printf("WARNING: Freeing hash table with %d items\n", tbl->num_items);
	}

	uthash_free(tbl->buckets, tbl->num_buckets*sizeof(UT_hash_bucket) );
	uthash_free(tbl, sizeof(UT_hash_table));
}

unsigned int superflow_hash_count(struct UT_hash_table_ *tbl) {
	if (tbl == NULL) return 0;
	else return tbl->num_items;
}

Superflow* superflow_hash_get_head(UT_hash_table *tbl) {

	return hash_index_to_superflow(tbl, tbl->head);
}

unsigned int hash_fcn(void* key, unsigned int keylen, unsigned int num_bkts, unsigned int *hashv) {
	unsigned int bkt;

	unsigned _hj_i, _hj_j, _hj_k;
	char *_hj_key = (char*) (key);
	*hashv = 0xfeedbeef;
	_hj_i = _hj_j = 0x9e3779b9;
	_hj_k = (unsigned) keylen;
	while (_hj_k >= 12) {
		_hj_i +=
				(_hj_key[0] + ((unsigned) _hj_key[1] << 8)
						+ ((unsigned) _hj_key[2] << 16)
						+ ((unsigned) _hj_key[3] << 24));
		_hj_j +=
				(_hj_key[4] + ((unsigned) _hj_key[5] << 8)
						+ ((unsigned) _hj_key[6] << 16)
						+ ((unsigned) _hj_key[7] << 24));
		*hashv += (_hj_key[8] + ((unsigned) _hj_key[9] << 8)
				+ ((unsigned) _hj_key[10] << 16)
				+ ((unsigned) _hj_key[11] << 24));
		do {
			_hj_i -= _hj_j;
			_hj_i -= *hashv;
			_hj_i ^= (*hashv >> 13);
			_hj_j -= *hashv;
			_hj_j -= _hj_i;
			_hj_j ^= (_hj_i << 8);
			*hashv -= _hj_i;
			*hashv -= _hj_j;
			*hashv ^= (_hj_j >> 13);
			_hj_i -= _hj_j;
			_hj_i -= *hashv;
			_hj_i ^= (*hashv >> 12);
			_hj_j -= *hashv;
			_hj_j -= _hj_i;
			_hj_j ^= (_hj_i << 16);
			*hashv -= _hj_i;
			*hashv -= _hj_j;
			*hashv ^= (_hj_j >> 5);
			_hj_i -= _hj_j;
			_hj_i -= *hashv;
			_hj_i ^= (*hashv >> 3);
			_hj_j -= *hashv;
			_hj_j -= _hj_i;
			_hj_j ^= (_hj_i << 10);
			*hashv -= _hj_i;
			*hashv -= _hj_j;
			*hashv ^= (_hj_j >> 15);
		} while (0);
		_hj_key += 12;
		_hj_k -= 12;
	}
	*hashv += keylen;
	switch (_hj_k) {
	case 11:
		*hashv += ((unsigned) _hj_key[10] << 24);
		/* no break */
	case 10:
		*hashv += ((unsigned) _hj_key[9] << 16);
		/* no break */
	case 9:
		*hashv += ((unsigned) _hj_key[8] << 8);
		/* no break */
	case 8:
		_hj_j += ((unsigned) _hj_key[7] << 24);
		/* no break */
	case 7:
		_hj_j += ((unsigned) _hj_key[6] << 16);
		/* no break */
	case 6:
		_hj_j += ((unsigned) _hj_key[5] << 8);
		/* no break */
	case 5:
		_hj_j += _hj_key[4];
		/* no break */
	case 4:
		_hj_i += ((unsigned) _hj_key[3] << 24);
		/* no break */
	case 3:
		_hj_i += ((unsigned) _hj_key[2] << 16);
		/* no break */
	case 2:
		_hj_i += ((unsigned) _hj_key[1] << 8);
		/* no break */
	case 1:
		_hj_i += _hj_key[0];
		/* no break */
	}
	_hj_i -= _hj_j;
	_hj_i -= *hashv;
	_hj_i ^= (*hashv >> 13);
	_hj_j -= *hashv;
	_hj_j -= _hj_i;
	_hj_j ^= (_hj_i << 8);
	*hashv -= _hj_i;
	*hashv -= _hj_j;
	*hashv ^= (_hj_j >> 13);
	_hj_i -= _hj_j;
	_hj_i -= *hashv;
	_hj_i ^= (*hashv >> 12);
	_hj_j -= *hashv;
	_hj_j -= _hj_i;
	_hj_j ^= (_hj_i << 16);
	*hashv -= _hj_i;
	*hashv -= _hj_j;
	*hashv ^= (_hj_j >> 5);
	_hj_i -= _hj_j;
	_hj_i -= *hashv;
	_hj_i ^= (*hashv >> 3);
	_hj_j -= *hashv;
	_hj_j -= _hj_i;
	_hj_j ^= (_hj_i << 10);
	*hashv -= _hj_i;
	*hashv -= _hj_j;
	*hashv ^= (_hj_j >> 15);
	bkt = *hashv & (num_bkts - 1);

	return bkt;
}

void hash_expand_buckets(UT_hash_table * tbl) {
	unsigned _he_bkt;
	unsigned _he_bkt_i;
	Superflow *_he_thh, *_he_hh_nxt;
	UT_hash_bucket *_he_new_buckets, *_he_newbkt;
	_he_new_buckets = (UT_hash_bucket*)uthash_malloc(2 * tbl->num_buckets * sizeof(UT_hash_bucket));
	if (!_he_new_buckets) { uthash_fatal( "out of memory"); }
	memset(_he_new_buckets, 0, 2 * tbl->num_buckets * sizeof(UT_hash_bucket));
	tbl->ideal_chain_maxlen =
		(tbl->num_items >> (tbl->log2_num_buckets + 1)) + ((tbl->num_items & (tbl->num_buckets * 2 - 1)) ? 1 : 0);
	tbl->nonideal_items = 0;
	for(_he_bkt_i = 0; _he_bkt_i < tbl->num_buckets; _he_bkt_i++)
	{
		_he_thh = hash_index_to_superflow(tbl, tbl->buckets[ _he_bkt_i ].hh_head);
		while (_he_thh) {
			_he_hh_nxt = hash_index_to_superflow(tbl, _he_thh->hh.hh_next);
			_he_bkt = ((_he_thh->hh.hashv) & ((tbl->num_buckets * 2) - 1));
			_he_newbkt = &(_he_new_buckets[ _he_bkt ]);
			if (++(_he_newbkt->count) > tbl->ideal_chain_maxlen) {
				tbl->nonideal_items++;
				_he_newbkt->expand_mult = _he_newbkt->count /
					tbl->ideal_chain_maxlen;
			}
			_he_thh->hh.hh_prev = 0;
			_he_thh->hh.hh_next = _he_newbkt->hh_head;
			if (_he_newbkt->hh_head)
				hash_index_to_superflow(tbl, _he_newbkt->hh_head)->hh.hh_prev = hash_superflow_to_index(tbl, _he_thh);
			_he_newbkt->hh_head = hash_superflow_to_index(tbl, _he_thh);
			_he_thh = _he_hh_nxt;
		}
	}
	uthash_free( tbl->buckets, tbl->num_buckets * sizeof(struct UT_hash_bucket) );
	tbl->num_buckets *= 2;
	tbl->log2_num_buckets++;
	tbl->buckets = _he_new_buckets;
	tbl->ineff_expands = (tbl->nonideal_items > (tbl->num_items >> 1)) ? (tbl->ineff_expands+1) : 0;
	if (tbl->ineff_expands > 1) {
		tbl->noexpand=1;
		uthash_noexpand_fyi(tbl);
	}
	uthash_expand_fyi(tbl);
}

void hash_add_to_bucket(UT_hash_table *tbl, unsigned bkt, Superflow *value) {
	UT_hash_bucket *head = &tbl->buckets[bkt];
	head->count++;
	value->hh.hh_next = head->hh_head;
	value->hh.hh_prev = 0;
	if (head->hh_head) {
		hash_index_to_superflow(tbl, head->hh_head)->hh.hh_prev = hash_superflow_to_index(tbl, value);
	}
	head->hh_head = hash_superflow_to_index(tbl, value);
	if (head->count >= ((head->expand_mult + 1) * HASH_BKT_CAPACITY_THRESH) && tbl->noexpand != 1) {
		hash_expand_buckets(tbl);
	}
}

void superflow_hash_add(UT_hash_table *tbl, Superflow* value) {
	unsigned _ha_bkt;
	value->hh.next = 0;

	if (!tbl->head) {
		value->hh.prev = 0;
		tbl->tail = hash_superflow_to_index(tbl, value);
		tbl->head = hash_superflow_to_index(tbl, value);
	} else {
		hash_index_to_superflow(tbl, tbl->tail)->hh.next = hash_superflow_to_index(tbl, value);
		value->hh.prev = tbl->tail;
		tbl->tail = hash_superflow_to_index(tbl, value);
	}
	tbl->num_items++;
	_ha_bkt = hash_fcn(&(value->addrs), sizeof(union SuperflowKey_), tbl->num_buckets, &value->hh.hashv);
	hash_add_to_bucket(tbl, _ha_bkt, value);
}

void superflow_hash_touch(UT_hash_table *tbl, Superflow* value) {
	// TODO: This can be optimized. Currently it is just remove and add in sequence

	if (hash_superflow_to_index(tbl, value) == tbl->tail) {
		tbl->tail = value->hh.prev;
	}
	if (value->hh.prev) {
		hash_index_to_superflow(tbl, value->hh.prev)->hh.next = value->hh.next;
	} else {
		tbl->head = value->hh.next;
	}
	if (value->hh.next) {
		hash_index_to_superflow(tbl, value->hh.next)->hh.prev = value->hh.prev;
	}

	if  (value->hh.prev == 0 && value->hh.next == 0) {
		tbl->head = 0;
		tbl->tail = 0;
	}

	value->hh.next = 0;

	if (!tbl->head) {
		value->hh.prev = 0;
		tbl->tail = hash_superflow_to_index(tbl, value);
		tbl->head = hash_superflow_to_index(tbl, value);
	} else {
		hash_index_to_superflow(tbl, tbl->tail)->hh.next = hash_superflow_to_index(tbl, value);
		value->hh.prev = tbl->tail;
		tbl->tail = hash_superflow_to_index(tbl, value);
	}
}

Superflow* hash_find_in_bkt(UT_hash_table* tbl, unsigned bkt, union SuperflowKey_ *key) {
	Superflow *out = NULL;
	UT_hash_bucket *head = &tbl->buckets[bkt];
	if (head->hh_head) out = hash_index_to_superflow(tbl, head->hh_head);
	else out=NULL;
	while (out) {
		if (memcmp(&out->addrs, key, sizeof(union SuperflowKey_)) == 0) break;
		if (out->hh.hh_next) out = hash_index_to_superflow(tbl, out->hh.hh_next);
		else out = NULL;
	}
	return out;
}

Superflow* superflow_hash_find(UT_hash_table * tbl, Superflow* value) {
	return superflow_hash_find_by_key(tbl, &value->addrs);
}

Superflow* superflow_hash_find_by_key(UT_hash_table * tbl, union SuperflowKey_ *key) {
	Superflow* out = NULL;
	unsigned int hashv = 0;
	unsigned _hf_bkt;
	if (tbl->head) {
		_hf_bkt = hash_fcn(key, sizeof(union SuperflowKey_), tbl->num_buckets, &hashv);
		out = hash_find_in_bkt(tbl, _hf_bkt, key);
	}

	return out;
}

void hash_del_in_bkt(UT_hash_table *tbl, uint32_t bkt, Superflow *hh_del) {
	UT_hash_bucket *head = &tbl->buckets[bkt];
	head->count--;
	if (head->hh_head == hash_superflow_to_index(tbl, hh_del)) {
		head->hh_head = hh_del->hh.hh_next;
	}
	if (hh_del->hh.hh_prev) {
		hash_index_to_superflow(tbl, hh_del->hh.hh_prev)->hh.hh_next = hh_del->hh.hh_next;
	}
	if (hh_del->hh.hh_next) {
		hash_index_to_superflow(tbl, hh_del->hh.hh_next)->hh.hh_prev = hh_del->hh.hh_prev;
	}
}

void superflow_hash_del(UT_hash_table * tbl, Superflow* value) {
	unsigned _hd_bkt;
	if (hash_superflow_to_index(tbl, value) == tbl->tail) {
		tbl->tail = value->hh.prev;
	}
	if (value->hh.prev) {
		hash_index_to_superflow(tbl, value->hh.prev)->hh.next = value->hh.next;
	} else {
		tbl->head = value->hh.next;
	}
	if (value->hh.next) {
		hash_index_to_superflow(tbl, value->hh.next)->hh.prev = value->hh.prev;
	}

	if  (value->hh.prev == 0 && value->hh.next == 0) {
		tbl->head = 0;
		tbl->tail = 0;
	}

	_hd_bkt = value->hh.hashv & (tbl->num_buckets - 1);
	hash_del_in_bkt(tbl, _hd_bkt, value);
	tbl->num_items--;
}

Superflow* superflow_hash_next( UT_hash_table *tbl, Superflow* current )
{
	if (current) {
		return hash_index_to_superflow(tbl, current->hh.next);
	}// else {
	return NULL;
	//}
	//return (current ? hash_index_to_superflow(tbl, current->hh.next) : NULL);
}

int SuperflowHashTest01() {
	UT_hash_table *tbl;
	Superflow sflows[10];

	tbl = superflow_hash_new(sflows);

	if (superflow_hash_count(tbl) != 0) {
		printf("Hashtable size is not zero\n");
		goto error;
	}

	if (superflow_hash_get_head(tbl) != NULL) {
		printf("Head is not NULL\n");
		goto error;
	}


	int r = 0;
	goto end;
error:
	r = -1;
end:
	superflow_hash_free(tbl);
	return r;
}

int SuperflowHashTest02() {
	UT_hash_table *tbl;
	Superflow sflows[10];

	for (unsigned int i = 0; i < 10; ++i) {
		sflows[i].addrs.key = i;
	}

	tbl = superflow_hash_new(sflows);

	superflow_hash_add(tbl, &sflows[0]);

	if (superflow_hash_count(tbl) != 1) {
		printf("Hashtable size is not one\n");
		goto error;
	}

	if (superflow_hash_get_head(tbl) == NULL) {
		printf("Head is NULL\n");
		goto error;
	}

	superflow_hash_add(tbl, &sflows[1]);

	if (superflow_hash_count(tbl) != 2) {
		printf("Hashtable size is not two\n");
		goto error;
	}

	superflow_hash_del(tbl, &sflows[1]);

	if (superflow_hash_count(tbl) != 1) {
		printf("Hashtable size is not one\n");
		goto error;
	}

	if (superflow_hash_get_head(tbl) != &sflows[0]) {
		printf("Head is not sflows[0]\n");
		goto error;
	}

	if (superflow_hash_next(tbl, &sflows[0]) != NULL) {
		printf("Next is not NULL\n");
		goto error;
	}

	superflow_hash_del(tbl, &sflows[0]);

	if (superflow_hash_count(tbl) != 0) {
		printf("Hashtable size is not null\n");
		goto error;
	}

	if (superflow_hash_get_head(tbl) != NULL) {
		printf("Head is not NULL\n");
		goto error;
	}


	int r = 0;
	goto end;
error:
	r = -1;
end:
	superflow_hash_free(tbl);
	return r;
}

int SuperflowHashTest03() {
	UT_hash_table *tbl;
	Superflow sflows[10];

	for (unsigned int i = 0; i < 10; ++i) {
		sflows[i].addrs.key = i;
	}

	tbl = superflow_hash_new(sflows);

	superflow_hash_add(tbl, &sflows[0]);

	if (superflow_hash_count(tbl) != 1) {
		printf("Hashtable size is not one\n");
		goto error;
	}

	if (superflow_hash_get_head(tbl) == NULL) {
		printf("Head is NULL\n");
		goto error;
	}

	superflow_hash_add(tbl, &sflows[1]);

	if (superflow_hash_count(tbl) != 2) {
		printf("Hashtable size is not two\n");
		goto error;
	}

	superflow_hash_del(tbl, &sflows[0]);

	if (superflow_hash_count(tbl) != 1) {
		printf("Hashtable size is not one\n");
		goto error;
	}

	if (superflow_hash_get_head(tbl) != &sflows[1]) {
		printf("Head is not sflows[1]\n");
		goto error;
	}

	if (superflow_hash_next(tbl, &sflows[1]) != NULL) {
		printf("Next is not NULL\n");
		goto error;
	}

	superflow_hash_del(tbl, &sflows[1]);

	if (superflow_hash_count(tbl) != 0) {
		printf("Hashtable size is not null\n");
		goto error;
	}

	if (superflow_hash_get_head(tbl) != NULL) {
		printf("Head is not NULL\n");
		goto error;
	}


	int r = 0;
	goto end;
error:
	r = -1;
end:
	superflow_hash_free(tbl);
	return r;
}

int SuperflowHashTest04() {
	UT_hash_table *tbl;
	Superflow sflows[10];

	for (unsigned int i = 0; i < 10; ++i) {
		sflows[i].addrs.key = i;
	}

	tbl = superflow_hash_new(sflows);

	superflow_hash_add(tbl, &sflows[0]);
	superflow_hash_add(tbl, &sflows[1]);
	superflow_hash_add(tbl, &sflows[2]);

	if (superflow_hash_get_head(tbl) != &sflows[0]) {
		printf("Head is not sflows[0]\n");
		goto error;
	}

	superflow_hash_touch(tbl, &sflows[0]);

	if (superflow_hash_get_head(tbl) != &sflows[1]) {
		printf("Head is not sflows[1]\n");
		goto error;
	}

	superflow_hash_touch(tbl, &sflows[1]);

	Superflow *sflow;
	while ((sflow = superflow_hash_get_head(tbl))) {
		superflow_hash_del(tbl, sflow);
	}

	int r = 0;
	goto end;
error:
	r = -1;
end:
	superflow_hash_free(tbl);
	return r;
}

int SuperflowHashTest05() {
	UT_hash_table *tbl;
	Superflow sflow;

	tbl = superflow_hash_new(&sflow);

	superflow_hash_add(tbl, &sflow);

	superflow_hash_del(tbl, &sflow);

	if (superflow_hash_count(tbl) != 0) {
		printf("Hashtable size is not null\n");
		goto error;
	}

	if (superflow_hash_get_head(tbl) != NULL) {
		printf("Head is not NULL\n");
		goto error;
	}

	int r = 0;
	goto end;
error:
	r = -1;
end:
	superflow_hash_free(tbl);
	return r;
}

void SuperflowHashRegisterTests() {
	UtRegisterTest("SuperflowHashTest1", SuperflowHashTest01, 0);
	UtRegisterTest("SuperflowHashTest2", SuperflowHashTest02, 0);
	UtRegisterTest("SuperflowHashTest3", SuperflowHashTest03, 0);
	UtRegisterTest("SuperflowHashTest4", SuperflowHashTest04, 0);
	UtRegisterTest("SuperflowHashTest5", SuperflowHashTest05, 0);
}
