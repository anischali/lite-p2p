#ifndef __CLEANUP_HPP__
#define __CLEANUP_HPP__
#include "list_head.h"
#include "cstdlib"
#include "cstring"


struct at_exit_context_t {
    void (*cleanup)(void *context);
    void *context;
    struct list_head list;
};


class at_exit_engine {
private:
    
    struct list_head list;

    static void on_exit_engine_cleanup(int status, void *context) {
        struct at_exit_context_t *ctx, *save;
        struct list_head *array = (struct list_head *)context;

        list_for_each_entry_safe(ctx, save, array, list) {
            if (ctx && ctx->cleanup) {
                ctx->cleanup(ctx->context);
                list_del(&ctx->list);
                free(ctx);
                ctx = NULL;
            }
        }

        printf("Cleanup success!\n");

    };

public:
    at_exit_engine() {
        INIT_LIST_HEAD(&list);
        on_exit(at_exit_engine::on_exit_engine_cleanup, &list);
    };

    void on_exit_register(void *context, void (*cleanup)(void *context)) {
        struct at_exit_context_t *ctx = (struct at_exit_context_t *)calloc(1, sizeof(struct at_exit_context_t)); 
        
        __glibcxx_assert(ctx != NULL);

        INIT_LIST_HEAD(&ctx->list);
        ctx->context = context;
        ctx->cleanup = cleanup;

        list_add_tail(&ctx->list, &list);
    }
};

#endif