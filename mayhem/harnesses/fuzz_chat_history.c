/* Fuzzes toxic's chat-log history loader (src/log.c load_chat_history): the per-contact log file
 * toxic re-reads when a chat window opens. Input = the log file. The parsed lines go through
 * line_info_load_history / line_info_add into the window's history queue. */
#include "fuzz_common.h"

#include "toxic.h"
#include "windows.h"
#include "log.h"
#include "line_info.h"
#include "settings.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct chatlog *log = calloc(1, sizeof(struct chatlog));
    if (fuzz_write_tmp(log->path, sizeof(log->path), "log", data, size) != 0) {
        free(log);
        return 0;
    }

    Client_Config *c_config = calloc(1, sizeof(Client_Config));
    c_config->history_size = 700;            /* toxic's default (settings.c ui_defaults) */
    c_config->show_timestamps = true;

    ToxWindow *self = calloc(1, sizeof(ToxWindow));
    self->type = WINDOW_TYPE_CHAT;
    self->chatwin = calloc(1, sizeof(ChatContext));
    self->chatwin->hst = calloc(1, sizeof(struct history));
    line_info_init(self->chatwin->hst);

    load_chat_history(log, self, c_config);

    line_info_cleanup(self->chatwin->hst);
    free(self->chatwin);
    free(self);
    unlink(log->path);
    free(log);
    free(c_config);
    return 0;
}
