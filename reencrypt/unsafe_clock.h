#ifndef __CLOCK_H__
#define __CLOCK_H__
#define __CLOCK_H__

#include "types.h"

/* Gets a timestamp from the operating system */
reencrypt_status unsafe_timestamp(uint64_t *ts);

#endif