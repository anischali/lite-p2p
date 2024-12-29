#ifndef __COMMON_HPP__
#define __COMMON_HPP__
#include "lite-p2p/types/list_head.hpp"
#include <cstring>
#include <csignal>
#include <cstdarg>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>


namespace lite_p2p::common
{

    static inline int rand_int(int min, int max)
    {
        return (int)(rand() % (max - min + 1) + min);
    }

    static inline bool c_array_cmp(uint8_t a1[], uint8_t a2[], int len)
    {

        while (len-- > 0 && *(a1++) != *(a2++))
            ;
        return len == 0;
    }

    static inline void print_hexbuf(const char *label, std::vector<uint8_t> &buf)
    {

        printf("%s (%d): ", label, (int)buf.size());
        for (size_t i = 0; i < buf.size(); ++i)
        {
            printf("%02x", buf[i]);
        }

        printf("\n");
    }

    static inline std::vector<uint8_t> read_file(const std::string filename) {
        
        int fd;
        
        fd = open(filename.c_str(), O_RDONLY);
        if (fd < 0)
            return {};

        size_t size = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        std::vector<uint8_t> file_buf(size);
        read(fd, file_buf.data(), size);
        close(fd);

        return file_buf;
    }

    static inline void write_file(std::vector<uint8_t> file_buf, const std::string filename, bool append) {
        
        int fd;
        
        if (!file_buf.size())
            return;

        if (append) {
            fd = open(filename.c_str(), O_WRONLY | O_APPEND);
            if (fd < 0)
                return;
        }
        else {
            fd = open(filename.c_str(), O_WRONLY | O_CREAT, 0666);
            if (fd < 0)
                return;
        }

        write(fd, file_buf.data(), file_buf.size());
        close(fd);
    }

    static inline std::string parse(std::string label)
    {
        char buf[512];
        int cx = 0, cnt = 0;

        printf("%s: ", label.c_str());
        while ((cx = getc(stdin)) != '\n')
        {
            buf[cnt] = cx;
            cnt = ((cnt + 1) % 512);
        }
        buf[cnt] = 0;

        printf("\n");
        return std::string(buf);
    }

    class at_exit_cleanup
    {
    private:
        struct list_head cleanup_list = { &cleanup_list, &cleanup_list }; 
        struct at_exit_context_t
        {
            void (*cleanup)(void *context);
            void *context;
            struct list_head list;
        };

        static void on_exit_engine_cleanup(int status, void *context)
        {
            struct at_exit_context_t *ctx = NULL, *save = NULL;
            struct list_head *array = NULL;
            
            if (!context)
                return;

            array = (struct list_head *)context;
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
        explicit at_exit_cleanup()
        {
            INIT_LIST_HEAD(&cleanup_list);
#if defined(__ANDROID__)
            // not suppot cleanup for now
#else
            on_exit(at_exit_cleanup::on_exit_engine_cleanup, &cleanup_list);
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
            struct at_exit_context_t *ctx; 
            
            if (!cleanup)
                return;

            ctx = (struct at_exit_context_t *)calloc(1, sizeof(struct at_exit_context_t));
            if (!ctx)
                return;

            INIT_LIST_HEAD(&ctx->list);
            ctx->context = context;
            ctx->cleanup = cleanup;

            list_add_tail(&ctx->list, &cleanup_list);
        }

        void at_exit()
        {
        }
    };
};
#endif