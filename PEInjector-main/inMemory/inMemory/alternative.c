#include "helper.h"
#include "alternative.h"

UINT64 * al_memcpy(UINT64 * dest, const UINT64 * src, UINT64 n) {
	BYTE* d = (BYTE*)dest;
	BYTE* s = (BYTE*)src;

	while (n--) {
		*d++ = *s++;
	}
	return dest;
}