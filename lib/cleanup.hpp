#ifndef __CLEANUP_HPP__
#define __CLEANUP_HPP__
#include "list_head.h"
#include "cstdlib"
#include "cstring"
#include <csignal>
#include <cstdarg>

class at_exit_cleanup {
private:
    
    struct list_head list;
    struct at_exit_context_t {
        void (*cleanup)(void *context);
        void *context;
        struct list_head list;
    };

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
    };

    static void at_exit_sig_handler(int sig) {
        exit(sig);
    };

public:
    

    at_exit_cleanup(...) {
        va_list args;
        va_start(args, NULL);
        
        INIT_LIST_HEAD(&list);
        
        on_exit(at_exit_cleanup::on_exit_engine_cleanup, &list);
        int sig;
        do {
            sig = va_arg(args, int);
            if (sig < 0)
                break;
            
            signal(sig, at_exit_cleanup::at_exit_sig_handler);
        } while (sig > 0);

        va_end(args);
    };

    void at_exit_cleanup_add(void *context, void (*cleanup)(void *context)) {
        struct at_exit_context_t *ctx = (struct at_exit_context_t *)calloc(1, sizeof(struct at_exit_context_t)); 
        
        __glibcxx_assert(ctx != NULL);

        INIT_LIST_HEAD(&ctx->list);
        ctx->context = context;
        ctx->cleanup = cleanup;

        list_add_tail(&ctx->list, &list);
    }
};

#endif