#ifndef __CLEANUP_HPP__
#define __CLEANUP_HPP__
#include "lite-p2p/list_head.hpp"
#include "cstdlib"
#include "cstring"
#include <csignal>
#include <cstdarg>
#include <vector>

namespace lite_p2p
{
    class at_exit_cleanup
    {
    private:
        struct list_head list = {0};
        struct at_exit_context_t
        {
            void (*cleanup)(void *context);
            void *context;
            struct list_head list;
        };

        static void on_exit_engine_cleanup(int status, void *context)
        {
            struct at_exit_context_t *ctx = NULL, *save = NULL;
            struct list_head *array = reinterpret_cast<struct list_head *>(context);

            if (!array || list_empty(array))
                return;

            list_for_each_entry_safe(ctx, save, array, list)
            {
                if (ctx && ctx->cleanup && ctx->context)
                {
                    ctx->cleanup(ctx->context);
                    list_del(&ctx->list);
                    free(ctx);
                    ctx = NULL;
                }
            }
        };

        static void at_exit_sig_handler(int sig)
        {
            exit(sig);
        };

    public:
        at_exit_cleanup()
        {
            INIT_LIST_HEAD(&list);
#if defined(__ANDROID__)
    // not suppot cleanup for now
#else
            on_exit(at_exit_cleanup::on_exit_engine_cleanup, &list);
#endif
        };

        at_exit_cleanup(std::vector<int> sigs) : at_exit_cleanup()
        {

            for (int i = 0; i < (int)sigs.size(); ++i)
            {
                signal(sigs[i], at_exit_cleanup::at_exit_sig_handler);
            }
        };

        void at_exit_cleanup_add(void *context, void (*cleanup)(void *context))
        {
            struct at_exit_context_t *ctx = (struct at_exit_context_t *)calloc(1, sizeof(struct at_exit_context_t));

            if (!ctx)
                return;

            INIT_LIST_HEAD(&ctx->list);
            ctx->context = context;
            ctx->cleanup = cleanup;

            list_add_tail(&ctx->list, &list);
        }

        void at_exit() {

        }
    };
};
#endif