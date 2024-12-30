#include <lite-p2p/common/common.hpp>

using namespace lite_p2p::common;

struct at_exit_context_t
{
    void (*cleanup)(void *context);
    void *context;
    struct list_head list;
};

static void at_exit_sig_handler(int sig)
{
    exit(sig);
};

static void on_exit_engine_cleanup(int status, void * context)
{
    struct at_exit_context_t *ctx = NULL, *save = NULL;
    struct list_head *array;

    if (!context)
        return;

    array = static_cast<struct list_head *>(context);
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

    delete array;
};

at_exit_cleanup::at_exit_cleanup()
{
    cleanup_list = new struct list_head;
    INIT_LIST_HEAD(cleanup_list);
#if defined(__ANDROID__)
    // not suppot cleanup for now
#else
    on_exit(on_exit_engine_cleanup, cleanup_list);
#endif
};

at_exit_cleanup::at_exit_cleanup(std::initializer_list<int> sigs) : at_exit_cleanup()
{ 
    for (auto&& s : sigs)
    {
        signal(s, at_exit_sig_handler);
    }
};

void at_exit_cleanup::at_exit_cleanup_add(void *context, void (*cleanup)(void *context))
{
    struct at_exit_context_t *ctx;

    if (!cleanup)
        return;

    ctx = (struct at_exit_context_t *)calloc(1, sizeof(struct at_exit_context_t));
    if (!ctx)
        return;

    INIT_LIST_HEAD(&ctx->list);
    ctx->context = context;
    ctx->cleanup = cleanup;

    list_add_tail(&ctx->list, cleanup_list);
}