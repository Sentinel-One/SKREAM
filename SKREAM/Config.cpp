#include "Config.h"

static_assert(!(USE_POOL_BLOATER_MITIGATION && USE_POOL_SLIDER_MITIGATION),
    "USE_POOL_BLOATER_MITIGATION and USE_POOL_SLIDER_MITIGATION are mutually exclusive");

static_assert(MIN_POOL_CHUNKS_TO_ADD >= 1,
    "MIN_POOL_CHUNKS_TO_ADD must be greater than or equal to 1");

static_assert(MAX_POOL_CHUNKS_TO_ADD >= MIN_POOL_CHUNKS_TO_ADD,
    "MAX_POOL_CHUNKS_TO_ADD must be greater than or equal to MIN_POOL_CHUNKS_TO_ADD");