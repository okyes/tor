/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"

#include "config.h"
#include "conscache.h"
#include "storagedir.h"

struct consensus_cache_entry_t {
  int refcnt;
  int can_remove;

  char *fname;
  config_line_t *labels;
  consensus_cache_t *in_cache;

  tor_mmap_t *map;
  size_t bodylen;
  const uint8_t *body;
};

struct consensus_cache_t {
  storage_dir_t *dir;
  smartlist_t *entries;
};

static void consensus_cache_rescan(consensus_cache_t *);
static void consensus_cache_entry_map(consensus_cache_t *,
                                      consensus_cache_entry_t *);

consensus_cache_t *
consensus_cache_open(const char *subdir, int max_entries)
{
  consensus_cache_t *cache = tor_malloc_zero(sizeof(consensus_cache_t));
  char *directory = get_datadir_fname(subdir);
  cache->dir = storage_dir_new(directory, max_entries);
  tor_free(directory);
  consensus_cache_rescan(cache);
  return cache;
}

void
consensus_cache_free(consensus_cache_t *cache)
{
  if (! cache)
    return;

  if (cache->entries) {
    SMARTLIST_FOREACH_BEGIN(cache->entries, consensus_cache_entry_t *, ent) {
      consensus_cache_entry_decref(ent);
      ent->in_cache = NULL;
    } SMARTLIST_FOREACH_END(ent);
    smartlist_free(cache->entries);
  }
  storage_dir_free(cache->dir);
  tor_free(cache);
}

consensus_cache_entry_t *
consensus_cache_add(consensus_cache_t *cache,
                    const config_line_t *labels,
                    const uint8_t *data,
                    size_t datalen)
{
  char *fname = NULL;
  int r = storage_dir_save_labelled_to_file(cache->dir,
                                            labels, data, datalen, &fname);
  if (r < 0 || fname == NULL) {
    return NULL;
  }
  consensus_cache_entry_t *ent =
    tor_malloc_zero(sizeof(consensus_cache_entry_t));
  ent->fname = fname;
  ent->refcnt = 1;
  ent->labels = config_lines_dup(labels);
  ent->in_cache = cache;
  smartlist_add(cache->entries, ent);

  return ent;
}

consensus_cache_entry_t *
consensus_cache_find_first(consensus_cache_t *cache,
                           const char *key,
                           const char *value)
{
  smartlist_t *tmp = smartlist_new();
  consensus_cache_find_all(tmp, cache, key, value);
  consensus_cache_entry_t *ent = NULL;
  if (smartlist_len(tmp))
    ent = smartlist_get(tmp, 0);
  smartlist_free(tmp);
  return ent;
}

void
consensus_cache_find_all(smartlist_t *out,
                         consensus_cache_t *cache,
                         const char *key,
                         const char *value)
{
  smartlist_t *tmp = smartlist_new();
  smartlist_add_all(tmp, cache->entries);
  consensus_cache_filter_list(tmp, key, value);
  smartlist_add_all(out, tmp);
  smartlist_free(tmp);
}

void
consensus_cache_filter_list(smartlist_t *lst,
                            const char *key,
                            const char *value)
{
  if (BUG(lst == NULL))
    return;
  SMARTLIST_FOREACH_BEGIN(lst, consensus_cache_entry_t *, ent) {
    const char *found_val = consensus_cache_entry_get_value(ent, key);
    if (! found_val || strcmp(value, found_val)) {
      SMARTLIST_DEL_CURRENT(lst, ent);
    }
  } SMARTLIST_FOREACH_END(ent);
}

const char *
consensus_cache_entry_get_value(const consensus_cache_entry_t *ent,
                                const char *key)
{
  const config_line_t *match = config_line_find(ent->labels, key);
  if (match)
    return match->value;
  else
    return NULL;
}

const config_line_t *
consensus_cache_entry_get_labels(const consensus_cache_entry_t *ent)
{
  return ent->labels;
}

void
consensus_cache_entry_incref(consensus_cache_entry_t *ent)
{
  ++ent->refcnt;
}

void
consensus_cache_entry_decref(consensus_cache_entry_t *ent)
{
  if (! ent)
    return;
  if (BUG(ent->refcnt <= 0))
    return;

  --ent->refcnt;
  if (ent->refcnt > 0)
    return;

  /* Refcount is zero; we can free it. */
  if (ent->map) {
    tor_munmap_file(ent->map);
  }
  tor_free(ent->fname);
  config_free_lines(ent->labels);
  memwipe(ent, 0, sizeof(consensus_cache_entry_t));
  tor_free(ent);
}

void
consensus_cache_entry_mark_for_removal(consensus_cache_entry_t *ent)
{
  ent->can_remove = 1;
}

int
consensus_cache_entry_get_body(const consensus_cache_entry_t *ent,
                               const uint8_t **body_out,
                               size_t *sz_out)
{
  if (! ent->map) {
    if (! ent->in_cache)
      return -1;

    consensus_cache_entry_map((consensus_cache_t *)ent->in_cache,
                              (consensus_cache_entry_t *)ent);
    if (! ent->map) {
      return -1;
    }
  }

  *body_out = ent->body;
  *sz_out = ent->bodylen;
  return 0;
}

static void
consensus_cache_rescan(consensus_cache_t *cache)
{
  if (cache->entries) {
    /* XXXXXX */
  }

  cache->entries = smartlist_new();
  const smartlist_t *fnames = storage_dir_list(cache->dir);
  SMARTLIST_FOREACH_BEGIN(fnames, const char *, fname) {
    tor_mmap_t *map = NULL;
    config_line_t *labels = NULL;
    const uint8_t *body;
    size_t bodylen;
    map = storage_dir_map_labelled(cache->dir, fname,
                                   &labels, &body, &bodylen);
    if (! map) {
      /* Can't load this; continue */
      /* XXXX warn */
      continue;
    }
    consensus_cache_entry_t *ent =
      tor_malloc_zero(sizeof(consensus_cache_entry_t));
    ent->fname = tor_strdup(fname);
    ent->labels = labels;
    ent->refcnt = 1;
    ent->in_cache = cache;
    smartlist_add(cache->entries, ent);
    tor_munmap_file(map); /* don't actually need to keep this around */
  } SMARTLIST_FOREACH_END(fname);
}

static void
consensus_cache_entry_map(consensus_cache_t *cache,
                          consensus_cache_entry_t *ent)
{
  if (ent->map)
    return;

  config_line_t *labels = NULL;
  ent->map = storage_dir_map_labelled(cache->dir, ent->fname,
                                      &labels, &ent->body, &ent->bodylen);
  config_free_lines(labels);
}

