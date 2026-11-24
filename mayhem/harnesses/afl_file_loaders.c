/* AFL file-input driver for two toxic file loaders whose state lives in file-static globals that no
 * public API resets (bootstrap.c Nodes, name_lookup.c Nameservers), so each input gets a fresh
 * process (AFL fork server) instead of an in-process libFuzzer loop.
 *
 *   afl_file_loaders dht   <file>   DHT nodes list JSON  -> load_DHT_nodeslist (src/bootstrap.c)
 *   afl_file_loaders names <file>   nameserver list      -> name_lookup_init   (src/name_lookup.c)
 */
#include <stdint.h>
#include <pthread.h>

#include "fuzz_common.h"

#include "toxic.h"
#include "bootstrap.h"
#include "name_lookup.h"
#include "settings.h"
#include "run_options.h"
#include "paths.h"

static int read_file(const char *path, uint8_t **out, size_t *out_size)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    size_t cap = 4096, n = 0;
    uint8_t *buf = malloc(cap);
    size_t r;
    while ((r = fread(buf + n, 1, cap - n, fp)) > 0) {
        n += r;
        if (n == cap) {
            cap *= 2;
            buf = realloc(buf, cap);
        }
    }
    fclose(fp);
    *out = buf;
    *out_size = n;
    return 0;
}

static Run_Options run_opts;

static void remove_nodes_copy(void)
{
    if (run_opts.nodes_path[0] != '\0') {
        unlink(run_opts.nodes_path);
    }
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s dht|names <file>\n", argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "names") == 0) {
        /* read-only loader: hand it the input path directly */
        int ret = name_lookup_init(argv[2], 0);
        printf("name_lookup_init=%d\n", ret);
        return 0;
    }

    if (strcmp(argv[1], "dht") != 0) {
        return 2;
    }

    /* The nodes loader opens the file "r+" and may rewrite it, so work on a private copy. */
    uint8_t *data = NULL;
    size_t size = 0;
    if (read_file(argv[2], &data, &size) != 0) {
        return 2;
    }
    static Client_Config c_config;
    static Paths paths;
    static Toxic toxic;
    if (fuzz_write_tmp(run_opts.nodes_path, sizeof(run_opts.nodes_path), "nodes", data, size) != 0) {
        return 2;
    }
    free(data);
    atexit(remove_nodes_copy);
    c_config.nodeslist_update_freq = 0;   /* never download a fresh list over the network */
    toxic.run_opts = &run_opts;
    toxic.c_config = &c_config;
    toxic.paths = &paths;

    int ret = load_DHT_nodeslist(&toxic);
    printf("load_DHT_nodeslist=%d\n", ret);
    /* The loader runs in a detached thread: pthread_exit lets it finish before the process exits.
     * The process then exits as if exit(0) was called, so the atexit hook removes the temp copy. */
    pthread_exit(NULL);
}
