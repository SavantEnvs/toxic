/* Fuzzes toxic's command-line interpreter (src/execute.c execute -> parse_command /
 * parse_special_command -> the global command handlers in src/global_commands.c) as typed into
 * the home (prompt) window. Input = one command line.
 *
 * Per input the harness builds a fresh Toxic the way main.c's toxic_init/init_windows do (offline
 * Tox: UDP, local discovery, IPv6 and DNS off, never bootstrapped; no profile path, so store_data
 * is a no-op), runs the line, and tears everything down. Only state kept across inputs: the
 * curses screen (on /dev/null, created once) and name_lookup's "disabled" flag (set once so /add
 * never starts a network lookup); neither is changed by the commands below.
 *
 * Commands are ALLOW-LISTED by name: the rest exit the process (/exit, /q, /quit), run programs
 * (/run), touch the network (/connect, /join, /conference, /group) or files (/avatar, /log,
 * /myqr), or start games and AV. */
#include "fuzz_common.h"

#include <locale.h>
#include <ncurses.h>

#include "toxic.h"
#include "windows.h"
#include "execute.h"
#include "friendlist.h"
#include "settings.h"
#include "run_options.h"
#include "name_lookup.h"
#include "paths.h"

static const char *const allowed[] = {
    "/accept", "/add", "/clear", "/color", "/decline", "/help", "/myid", "/nick", "/note",
    "/nospam", "/requests", "/status",
};

static bool command_allowed(const char *line)
{
    size_t n = strcspn(line, " ");
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); ++i) {
        if (strlen(allowed[i]) == n && memcmp(line, allowed[i], n) == 0) {
            return true;
        }
    }
    return false;
}

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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* The client hands execute() a line converted from its wchar_t line[MAX_STR_SIZE] input buffer
     * with wcs_to_mbs_buf(..., MAX_STR_SIZE) (chat.c / prompt.c), so it is never longer than this. */
    if (size == 0 || size >= MAX_STR_SIZE) {
        return -1;
    }
    char line[MAX_STR_SIZE];
    memcpy(line, data, size);
    line[size] = '\0';
    if (line[0] != '/' || !command_allowed(line)) {
        return -1;
    }

    Toxic *toxic = calloc(1, sizeof(Toxic));
    toxic->c_config = calloc(1, sizeof(Client_Config));
    toxic->run_opts = calloc(1, sizeof(Run_Options));
    toxic->windows = calloc(1, sizeof(Windows));
    Paths *paths = calloc(1, sizeof(Paths));
    toxic->paths = paths;
    settings_load_main(toxic->c_config, toxic->run_opts);   /* no config file: defaults only */
    init_friendlist(toxic);

    toxic->tox = new_offline_tox();
    if (toxic->tox == NULL) {
        abort();
    }

    init_windows(toxic);
    ToxWindow *home = toxic->home_window;

    execute(home->window, home, toxic, line, GLOBAL_COMMAND_MODE);

    kill_all_windows(toxic);
    tox_kill(toxic->tox);
    free(toxic->friends);
    free(toxic->blocked);
    free(toxic->windows);
    free(toxic->run_opts);
    free(toxic->c_config);
    free(paths);
    free(toxic);
    return 0;
}
