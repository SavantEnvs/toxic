/* Fuzzes toxic's libconfig settings loader (src/settings.c): the toxic.conf file the client reads
 * at start-up and on /reload. Input = the config file. Calls the same public loaders main.c calls:
 * settings_load_config_file, settings_load_main, settings_load_friends, settings_load_groups,
 * settings_load_conferences and settings_load_blocked_words. */
#include "fuzz_common.h"

#include "toxic.h"
#include "settings.h"
#include "friendlist.h"
#include "run_options.h"
#include "paths.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char path[512];
    if (fuzz_write_tmp(path, sizeof(path), "conf", data, size) != 0) {
        return 0;
    }

    Run_Options *run_opts = calloc(1, sizeof(Run_Options));
    Client_Config *c_config = calloc(1, sizeof(Client_Config));
    Paths paths = {0};
    run_opts->use_custom_config_file = true;
    snprintf(run_opts->config_path, sizeof(run_opts->config_path), "%s", path);

    if (settings_load_config_file(run_opts, &paths, NULL)) {
        settings_load_main(c_config, run_opts);

        /* One active friend whose public key is 32 x 0x11 so per-friend sections
         * ("pk_1111...") reach the alias / colour / flag setters. */
        FriendsList friends = {0};
        ToxicFriend *list = calloc(1, sizeof(ToxicFriend));
        memset(list[0].pub_key, 0x11, sizeof(list[0].pub_key));
        list[0].active = true;
        list[0].num = 0;
        friends.list = list;
        friends.max_idx = 1;
        friends.num_friends = 1;
        settings_load_friends(&friends, run_opts);
        free(list);

        Windows windows = {0};
        settings_load_groups(&windows, run_opts);
        settings_load_conferences(&windows, run_opts);

        Client_Data client_data = {0};
        settings_load_blocked_words(&client_data, run_opts);
        for (size_t i = 0; i < client_data.num_blocked_words; ++i) {
            free(client_data.blocked_words[i]);
        }
        free(client_data.blocked_words);
    }

    unlink(path);
    free(c_config);
    free(run_opts);
    return 0;
}
