/* Fuzzes the toxcore event callbacks toxic registers (src/windows.c on_friend_request,
 * on_friend_message, on_friend_name, on_friend_status_message, on_file_recv,
 * on_lossless_custom_packet, on_friend_connection_status, on_friend_status, on_friend_typing):
 * the path by which bytes sent by a remote peer (requests, messages, names, status messages,
 * file names, custom packets such as game invites) reach toxic's own code — friendlist.c, chat.c,
 * prompt.c, file_transfers.c, line_info.c, game_base.c. It also replays the conference callbacks
 * (on_conference_invite/_message/_peer_name/_title/_peer_list_changed -> conference.c) and the
 * NGC group callbacks (on_group_invite/_message/_private_message/_topic_change/_nick_change/
 * _password/_status_change/_peer_limit/_privacy_state/_topic_lock/_voice_state/_self_join/
 * _rejected -> groupchats.c), the way peers' invites, names, titles and topics reach toxic.
 *
 * Group and conference records need a group to exist: on the first such record the harness creates
 * one offline exactly as /group and /conference do (tox_group_new + init_groupchat_win,
 * tox_conference_new + init_conference_win) and dispatches with that number. The peer is always
 * our own peer (group: tox_group_self_get_peer_id, conference: peer 0), the only peer an offline
 * Tox has, so every peer id is one toxcore could report. on_group_peer_join/_peer_exit and
 * on_group_moderation are not replayed: toxcore only reports them for other peers, which an
 * offline Tox cannot have. groupchats.c groupchats[] and conference.c conferences[] are
 * file-static; kill_all_windows closes the windows, which resets them and max_*_index to 0.
 *
 * Per input the harness builds a fresh Toxic as main.c does (offline Tox, never bootstrapped,
 * no profile path), adds one friend (number 0) and then replays a sequence of callback records:
 *     [callback id: 1 byte][payload length: 2 bytes LE][payload]
 * Payloads are capped at the size toxcore itself guarantees for that callback (tox.h limits), so
 * every call is one toxcore could make. Kept across inputs: the curses screen on /dev/null and
 * name_lookup's "disabled" flag, both set once in LLVMFuzzerInitialize. */
#include "fuzz_common.h"

#include <locale.h>
#include <ncurses.h>

#include "toxic.h"
#include "windows.h"
#include "friendlist.h"
#include "file_transfers.h"
#include "settings.h"
#include "run_options.h"
#include "name_lookup.h"
#include "groupchats.h"
#include "conference.h"
#include "paths.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    (void) argv;
    setlocale(LC_ALL, "C.UTF-8");
    FILE *out = fopen("/dev/null", "w");
    FILE *in = fopen("/dev/null", "r");
    if (newterm("xterm", out, in) == NULL && newterm("vt100", out, in) == NULL) {
        fprintf(stderr, "fuzz_execute: cannot initialise curses\n");
        abort();
    }
    resizeterm(40, 120);
    name_lookup_init(NULL, -1);   /* marks name lookups disabled (no curl thread) */
    return 0;
}

static Tox *new_offline_tox(void)
{
    struct Tox_Options *opts = tox_options_new(NULL);
    tox_options_set_udp_enabled(opts, false);
    tox_options_set_local_discovery_enabled(opts, false);
    tox_options_set_ipv6_enabled(opts, false);
    tox_options_set_experimental_disable_dns(opts, true);
    tox_options_set_tcp_port(opts, 0);
    Tox *tox = tox_new(opts, NULL);
    tox_options_free(opts);
    return tox;
}

static size_t cap(size_t n, size_t max)
{
    return n < max ? n : max;
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

/* Lazily creates one NGC group, as cmd_groupchat does. Returns false if it cannot. */
static bool ensure_group(Toxic *toxic, bool *made, uint32_t *gnum, uint32_t *self_peer)
{
    if (*made) {
        return true;
    }
    static const char name[] = "fuzzgroup";
    Tox_Err_Group_New err;
    const uint32_t g = tox_group_new(toxic->tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *) name,
                                     sizeof(name) - 1, (const uint8_t *) "me", 2, &err);
    if (err != TOX_ERR_GROUP_NEW_OK) {
        return false;
    }
    if (init_groupchat_win(toxic, g, name, sizeof(name) - 1, Group_Join_Type_Create) != 0) {
        return false;
    }
    Tox_Err_Group_Self_Query qerr;
    *self_peer = tox_group_self_get_peer_id(toxic->tox, g, &qerr);
    if (qerr != TOX_ERR_GROUP_SELF_QUERY_OK) {
        return false;
    }
    *gnum = g;
    *made = true;
    return true;
}

/* Lazily creates one text conference. cmd_conference passes title NULL, length 0, which makes
 * conference_set_title call memcpy(dst, NULL, 0) (UBSan nonnull-attribute, on every /conference);
 * this passes an empty non-NULL title, as main.c's profile-load path passes a real one. */
static bool ensure_conference(Toxic *toxic, bool *made, uint32_t *cnum)
{
    if (*made) {
        return true;
    }
    Tox_Err_Conference_New err;
    const uint32_t c = tox_conference_new(toxic->tox, &err);
    if (err != TOX_ERR_CONFERENCE_NEW_OK) {
        return false;
    }
    if (init_conference_win(toxic, c, TOX_CONFERENCE_TYPE_TEXT, "", 0) < 0) {
        return false;
    }
    /* toxcore reports the new conference's peer list (our own peer) before any other peer event;
     * without it peer_list is NULL and peer_in_conference(c, 0) indexes it. */
    on_conference_peer_list_changed(toxic->tox, c, toxic);
    *cnum = c;
    *made = true;
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Toxic *toxic = calloc(1, sizeof(Toxic));
    toxic->c_config = calloc(1, sizeof(Client_Config));
    toxic->run_opts = calloc(1, sizeof(Run_Options));
    toxic->windows = calloc(1, sizeof(Windows));
    Paths *paths = calloc(1, sizeof(Paths));
    toxic->paths = paths;
    settings_load_main(toxic->c_config, toxic->run_opts);   /* no config file: defaults only */
    init_friendlist(toxic);

    Tox *tox = new_offline_tox();
    if (tox == NULL) {
        abort();
    }
    toxic->tox = tox;
    init_windows(toxic);

    uint8_t friend_pk[TOX_PUBLIC_KEY_SIZE];
    memset(friend_pk, 0x11, sizeof(friend_pk));
    const uint32_t fnum = tox_friend_add_norequest(tox, friend_pk, NULL);
    if (fnum != UINT32_MAX) {
        on_friend_added(toxic, fnum, false);
    }

    bool have_group = false, have_conf = false;
    uint32_t gnum = 0, gself = 0, cnum = 0;

    size_t off = 0;
    unsigned int records = 0;
    while (off + 3 <= size && records++ < 64) {
        const uint8_t id = data[off];
        size_t len = (size_t) data[off + 1] | ((size_t) data[off + 2] << 8);
        off += 3;
        len = cap(len, size - off);
        const uint8_t *p = data + off;
        off += len;

        switch (id % 27) {
            case 0: {   /* friend request: 32-byte public key + message */
                if (len < TOX_PUBLIC_KEY_SIZE) {
                    break;
                }
                on_friend_request(tox, p, p + TOX_PUBLIC_KEY_SIZE,
                                  cap(len - TOX_PUBLIC_KEY_SIZE, TOX_MAX_FRIEND_REQUEST_LENGTH), toxic);
                break;
            }
            case 1: {   /* message: first byte selects normal/action */
                if (len < 1) {
                    break;
                }
                on_friend_message(tox, fnum, (p[0] & 1) ? TOX_MESSAGE_TYPE_ACTION : TOX_MESSAGE_TYPE_NORMAL,
                                  p + 1, cap(len - 1, TOX_MAX_MESSAGE_LENGTH), toxic);
                break;
            }
            case 2:
                on_friend_name(tox, fnum, p, cap(len, TOX_MAX_NAME_LENGTH), toxic);
                break;
            case 3:
                on_friend_status_message(tox, fnum, p, cap(len, TOX_MAX_STATUS_MESSAGE_LENGTH), toxic);
                break;
            case 4: {   /* file offer: file number, 8-byte size, file name */
                if (len < 9) {
                    break;
                }
                uint64_t fsize = 0;
                memcpy(&fsize, p + 1, sizeof(fsize));
                on_file_recv(tox, fnum, p[0], TOX_FILE_KIND_DATA, fsize, p + 9,
                             cap(len - 9, TOX_MAX_FILENAME_LENGTH), toxic);
                break;
            }
            case 5: {   /* lossless custom packet: toxcore only delivers ids 160..191 */
                if (len < 1 || p[0] < 160 || p[0] > 191) {
                    break;
                }
                on_lossless_custom_packet(tox, fnum, p, cap(len, TOX_MAX_CUSTOM_PACKET_SIZE), toxic);
                break;
            }
            case 6:
                on_friend_connection_status(tox, fnum, (Tox_Connection)(len % 3), toxic);
                break;
            case 7:
                on_friend_status(tox, fnum, (Tox_User_Status)(len % 3), toxic);
                break;
            case 8:
                on_friend_typing(tox, fnum, (len & 1) != 0, toxic);
                break;
            case 9:   /* conference invite from friend 0: type byte + invite cookie */
                if (len < 1) {
                    break;
                }
                on_conference_invite(tox, fnum, (p[0] & 1) ? TOX_CONFERENCE_TYPE_AV : TOX_CONFERENCE_TYPE_TEXT,
                                     p + 1, cap(len - 1, TOX_MAX_CUSTOM_PACKET_SIZE), toxic);
                break;
            case 10: {   /* group invite from friend 0: [name len][group name][invite data] */
                if (len < 1) {
                    break;
                }
                const size_t nlen = cap(cap(p[0], len - 1), TOX_GROUP_MAX_GROUP_NAME_LENGTH);
                on_group_invite(tox, fnum, p + 1 + nlen, cap(len - 1 - nlen, TOX_MAX_CUSTOM_PACKET_SIZE),
                                p + 1, nlen, toxic);
                break;
            }
            case 11:   /* conference message: type byte + text */
                if (len < 1 || !ensure_conference(toxic, &have_conf, &cnum)) {
                    break;
                }
                on_conference_message(tox, cnum, 0, (p[0] & 1) ? TOX_MESSAGE_TYPE_ACTION : TOX_MESSAGE_TYPE_NORMAL,
                                      p + 1, cap(len - 1, TOX_MAX_MESSAGE_LENGTH), toxic);
                break;
            case 12:
                if (ensure_conference(toxic, &have_conf, &cnum)) {
                    on_conference_peer_name(tox, cnum, 0, p, cap(len, TOX_MAX_NAME_LENGTH), toxic);
                }
                break;
            case 13:
                if (ensure_conference(toxic, &have_conf, &cnum)) {
                    on_conference_title(tox, cnum, 0, p, cap(len, TOX_MAX_NAME_LENGTH), toxic);
                }
                break;
            case 14:
                if (ensure_conference(toxic, &have_conf, &cnum)) {
                    on_conference_peer_list_changed(tox, cnum, toxic);
                }
                break;
            case 15:   /* group message: type byte + text */
            case 16: { /* group private message: type byte + text */
                if (len < 1 || !ensure_group(toxic, &have_group, &gnum, &gself)) {
                    break;
                }
                const Tox_Message_Type t = (p[0] & 1) ? TOX_MESSAGE_TYPE_ACTION : TOX_MESSAGE_TYPE_NORMAL;
                const size_t mlen = cap(len - 1, TOX_GROUP_MAX_MESSAGE_LENGTH);
                if (id % 27 == 15) {
                    on_group_message(tox, gnum, gself, t, p + 1, mlen, 0, toxic);
                } else {
                    on_group_private_message(tox, gnum, gself, t, p + 1, mlen, 0, toxic);
                }
                break;
            }
            case 17:
                if (ensure_group(toxic, &have_group, &gnum, &gself)) {
                    on_group_topic_change(tox, gnum, gself, p, cap(len, TOX_GROUP_MAX_TOPIC_LENGTH), toxic);
                }
                break;
            case 18:
                if (ensure_group(toxic, &have_group, &gnum, &gself)) {
                    on_group_nick_change(tox, gnum, gself, p, cap(len, TOX_MAX_NAME_LENGTH), toxic);
                }
                break;
            case 19:
                if (ensure_group(toxic, &have_group, &gnum, &gself)) {
                    on_group_password(tox, gnum, p, cap(len, TOX_GROUP_MAX_PASSWORD_SIZE), toxic);
                }
                break;
            case 20:
                if (ensure_group(toxic, &have_group, &gnum, &gself)) {
                    on_group_status_change(tox, gnum, gself, (Tox_User_Status)(len % 3), toxic);
                }
                break;
            case 21:
                if (len >= 2 && ensure_group(toxic, &have_group, &gnum, &gself)) {
                    on_group_peer_limit(tox, gnum, rd16(p), toxic);
                }
                break;
            case 22:
                if (ensure_group(toxic, &have_group, &gnum, &gself)) {
                    on_group_privacy_state(tox, gnum, (Tox_Group_Privacy_State)(len % 2), toxic);
                }
                break;
            case 23:
                if (ensure_group(toxic, &have_group, &gnum, &gself)) {
                    on_group_topic_lock(tox, gnum, (Tox_Group_Topic_Lock)(len % 2), toxic);
                }
                break;
            case 24:
                if (ensure_group(toxic, &have_group, &gnum, &gself)) {
                    on_group_voice_state(tox, gnum, (Tox_Group_Voice_State)(len % 3), toxic);
                }
                break;
            case 25:
                if (ensure_group(toxic, &have_group, &gnum, &gself)) {
                    on_group_self_join(tox, gnum, toxic);
                }
                break;
            case 26:
                if (ensure_group(toxic, &have_group, &gnum, &gself)) {
                    on_group_rejected(tox, gnum, (Tox_Group_Join_Fail)(len % 3), toxic);
                }
                break;
        }
    }

    kill_all_file_transfers(toxic);
    kill_all_windows(toxic);
    tox_kill(tox);
    free(toxic->friends);
    free(toxic->blocked);
    free(toxic->windows);
    free(toxic->run_opts);
    free(toxic->c_config);
    free(paths);
    free(toxic);
    return 0;
}
