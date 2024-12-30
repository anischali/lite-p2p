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
        struct list_head *cleanup_list;

    public:
        explicit at_exit_cleanup();
        at_exit_cleanup(std::initializer_list<int> sigs);

        void at_exit_cleanup_add(void *context, void (*cleanup)(void *context));
    };
};
#endif