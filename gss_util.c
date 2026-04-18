#include "gss_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void display_gss_error(const char *prefix, OM_uint32 maj, OM_uint32 min) {
    OM_uint32 msg_ctx = 0, tmp_min;
    gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;

    fprintf(stderr, "[GSS ERROR] %s:\n", prefix);
    do {
        gss_display_status(&tmp_min, maj, GSS_C_GSS_CODE,
                           GSS_C_NO_OID, &msg_ctx, &msg);
        fprintf(stderr, "  MAJ: %.*s\n", (int)msg.length, (char *)msg.value);
        gss_release_buffer(&tmp_min, &msg);
    } while (msg_ctx != 0);

    msg_ctx = 0;
    do {
        gss_display_status(&tmp_min, min, GSS_C_MECH_CODE,
                           GSS_C_NO_OID, &msg_ctx, &msg);
        fprintf(stderr, "  MIN: %.*s\n", (int)msg.length, (char *)msg.value);
        gss_release_buffer(&tmp_min, &msg);
    } while (msg_ctx != 0);
}

/* OID 1.2.840.113554.1.2.2.5.5 — GSS_C_INQ_SSPI_SESSION_KEY.
 * Retrieves the raw Kerberos session key from the established context.
 * Both initiator and acceptor receive IDENTICAL bytes, so HKDF on each
 * side produces the same K_file without any extra key exchange. */
static gss_OID_desc inq_session_key_oid_desc = {
    11,
    (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"
};
static const gss_OID GSS_C_INQ_SSPI_SESSION_KEY = &inq_session_key_oid_desc;

int extract_session_key(gss_ctx_id_t ctx,
                        unsigned char **key, size_t *key_len) {
    OM_uint32 maj, min;
    gss_buffer_set_t key_set = GSS_C_NO_BUFFER_SET;

    maj = gss_inquire_sec_context_by_oid(&min, ctx,
                                         GSS_C_INQ_SSPI_SESSION_KEY,
                                         &key_set);
    if (GSS_ERROR(maj)) {
        display_gss_error("gss_inquire_sec_context_by_oid", maj, min);
        return -1;
    }
    if (key_set == GSS_C_NO_BUFFER_SET || key_set->count < 1) {
        fprintf(stderr, "[GSS ERROR] No session key returned\n");
        if (key_set) gss_release_buffer_set(&min, &key_set);
        return -1;
    }

    *key_len = key_set->elements[0].length;
    *key = malloc(*key_len);
    if (!*key) { gss_release_buffer_set(&min, &key_set); return -1; }
    memcpy(*key, key_set->elements[0].value, *key_len);

    gss_release_buffer_set(&min, &key_set);
    return 0;
}
