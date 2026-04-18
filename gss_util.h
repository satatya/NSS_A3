#ifndef GSS_UTIL_H
#define GSS_UTIL_H

#include <gssapi/gssapi.h>
#include <stddef.h>

void display_gss_error(const char *prefix, OM_uint32 maj, OM_uint32 min);
int  extract_session_key(gss_ctx_id_t ctx,
                         unsigned char **key, size_t *key_len);

#endif
