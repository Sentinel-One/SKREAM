#pragma once

//
// Params for enabling/disabling specific mitigations.
//

#define USE_POOL_BLOATER_MITIGATION    (1)
#define USE_POOL_SLIDER_MITIGATION     (0)

//
// Params for the PoolBloater mitigation.
//

#define MIN_POOL_CHUNKS_TO_ADD  (1)
#define MAX_POOL_CHUNKS_TO_ADD  (5)