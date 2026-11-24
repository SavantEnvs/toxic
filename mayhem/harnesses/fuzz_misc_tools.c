/* Fuzzes the string helpers in src/misc_tools.c that toxic applies to strings received from peers
 * (file-transfer names, nicks, status messages, public keys): get_file_name, get_base_dir,
 * copy_tox_str, filter_string, valid_nick, mbs_to_wcs_buf, wcs_to_mbs_buf, tox_pk_string_to_bytes,
 * hex_string_to_bytes, colour_string_to_int, string_contains_blocked_word.
 * Byte 0 picks the output buffer size (1..256) so truncation paths are reached; the rest is the
 * string. Every call respects the buffer-size contract documented in misc_tools.h. */
#include "fuzz_common.h"

#include <wchar.h>
#include <locale.h>

#include "toxic.h"
#include "misc_tools.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    (void) argv;
    setlocale(LC_ALL, "C.UTF-8");
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) {
        return 0;
    }
    const size_t bufsize = (size_t) data[0] + 1;
    const size_t len = size - 1;
    char *str = malloc(len + 1);
    memcpy(str, data + 1, len);
    str[len] = '\0';
    const size_t slen = strlen(str);

    char *out = malloc(bufsize);
    get_file_name(out, bufsize, str);

    char *dir = malloc(slen + 1);
    get_base_dir(str, slen, dir);
    free(dir);

    char *msg = malloc(bufsize);
    size_t mlen = copy_tox_str(msg, bufsize, (const char *) data + 1, len);
    filter_string(msg, mlen, true);
    free(msg);

    char *tmp = strdup(str);
    filter_string(tmp, slen, false);
    free(tmp);

    valid_nick(str);

    wchar_t *wbuf = malloc(bufsize * sizeof(wchar_t));
    int wn = mbs_to_wcs_buf(wbuf, str, bufsize);
    if (wn >= 0 && (size_t) wn < bufsize) {
        wbuf[wn] = L'\0';
        char *mb = malloc(bufsize * MB_LEN_MAX + 1);
        wcs_to_mbs_buf(mb, wbuf, bufsize * MB_LEN_MAX + 1);
        free(mb);
    }
    free(wbuf);

    char pk[TOX_PUBLIC_KEY_SIZE];
    tox_pk_string_to_bytes(str, slen, pk, sizeof(pk));
    if (slen >= TOX_PUBLIC_KEY_SIZE * 2) {
        char key[TOX_PUBLIC_KEY_SIZE];
        hex_string_to_bytes(key, TOX_PUBLIC_KEY_SIZE, str);
    }

    colour_string_to_int(str);

    /* Blocked-word match: the first space-separated token is the blocked word, the remainder
     * is the incoming line. */
    char *space = strchr(str, ' ');
    if (space != NULL) {
        *space = '\0';
        char *words[1] = { str };
        Client_Data cd = {0};
        cd.blocked_words = words;
        cd.num_blocked_words = 1;
        string_contains_blocked_word(space + 1, &cd);
    }

    free(out);
    free(str);
    return 0;
}
