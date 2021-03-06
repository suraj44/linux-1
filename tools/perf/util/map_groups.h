/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_MAP_GROUPS_H
#define __PERF_MAP_GROUPS_H

#include <linux/refcount.h>
#include <linux/rbtree.h>
#include <stdio.h>
#include <stdbool.h>
#include <linux/types.h>
#include "rwsem.h"

struct ref_reloc_sym;
struct machine;
struct map;
struct thread;

struct maps {
	struct rb_root      entries;
	struct rw_semaphore lock;
};

void maps__insert(struct maps *maps, struct map *map);
void maps__remove(struct maps *maps, struct map *map);
void __maps__remove(struct maps *maps, struct map *map);
struct map *maps__find(struct maps *maps, u64 addr);
struct map *maps__first(struct maps *maps);
struct map *map__next(struct map *map);

#define maps__for_each_entry(maps, map) \
	for (map = maps__first(maps); map; map = map__next(map))

#define maps__for_each_entry_safe(maps, map, next) \
	for (map = maps__first(maps), next = map__next(map); map; map = next, next = map__next(map))

struct symbol *maps__find_symbol_by_name(struct maps *maps, const char *name, struct map **mapp);

struct map_groups {
	struct maps	 maps;
	struct machine	 *machine;
	struct map	 *last_search_by_name;
	struct map	 **maps_by_name;
	refcount_t	 refcnt;
	unsigned int	 nr_maps;
	unsigned int	 nr_maps_allocated;
#ifdef HAVE_LIBUNWIND_SUPPORT
	void				*addr_space;
	struct unwind_libunwind_ops	*unwind_libunwind_ops;
#endif
};

#define KMAP_NAME_LEN 256

struct kmap {
	struct ref_reloc_sym *ref_reloc_sym;
	struct map_groups    *kmaps;
	char		     name[KMAP_NAME_LEN];
};

struct map_groups *map_groups__new(struct machine *machine);
void map_groups__delete(struct map_groups *mg);
bool map_groups__empty(struct map_groups *mg);

static inline struct map_groups *map_groups__get(struct map_groups *mg)
{
	if (mg)
		refcount_inc(&mg->refcnt);
	return mg;
}

void map_groups__put(struct map_groups *mg);
void map_groups__init(struct map_groups *mg, struct machine *machine);
void map_groups__exit(struct map_groups *mg);
int map_groups__clone(struct thread *thread, struct map_groups *parent);
size_t map_groups__fprintf(struct map_groups *mg, FILE *fp);

void map_groups__insert(struct map_groups *mg, struct map *map);

void map_groups__remove(struct map_groups *mg, struct map *map);

static inline struct map *map_groups__find(struct map_groups *mg, u64 addr)
{
	return maps__find(&mg->maps, addr);
}

#define map_groups__for_each_entry(mg, map) \
	for (map = maps__first(&mg->maps); map; map = map__next(map))

#define map_groups__for_each_entry_safe(mg, map, next) \
	for (map = maps__first(&mg->maps), next = map__next(map); map; map = next, next = map__next(map))

struct symbol *map_groups__find_symbol(struct map_groups *mg, u64 addr, struct map **mapp);
struct symbol *map_groups__find_symbol_by_name(struct map_groups *mg, const char *name, struct map **mapp);

struct addr_map_symbol;

int map_groups__find_ams(struct map_groups *mg, struct addr_map_symbol *ams);

int map_groups__fixup_overlappings(struct map_groups *mg, struct map *map, FILE *fp);

struct map *map_groups__find_by_name(struct map_groups *mg, const char *name);

int map_groups__merge_in(struct map_groups *kmaps, struct map *new_map);

void __map_groups__sort_by_name(struct map_groups *mg);

#endif // __PERF_MAP_GROUPS_H
