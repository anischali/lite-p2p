#include <lite-p2p/lite_json.hpp>
#include <errno.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>



using namespace lite_p2p;
using namespace nlohmann;


lite_json::lite_json()
{

}

lite_json::~lite_json()
{

}


void* 
lite_json::json_load(const std::string filename, void *(*callback) (nlohmann::json &js))
{
    void *obj = nullptr;
    char *str = nullptr;
    size_t size = 0;

    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0)
        return nullptr;

    if (!callback)
        goto out;

    size = lseek(fd, 0, SEEK_END);
    str = (char *)calloc(size, sizeof(*str));
    lseek(fd, 0, SEEK_SET);
    
    if ((read(fd, str, (size_t)(size * sizeof(*str)))) <= 0)
        goto free_mem;

    obj = this->decode(str, callback);

free_mem:
    free(str);
    str = nullptr;
out:
    close(fd);
    return obj;
}


nlohmann::json
lite_json::encode(const void *obj, nlohmann::json (*callback)(const void *obj))
{
    if (!callback || !obj)
        return nullptr;

    return callback(obj);
}

void *
lite_json::decode(const char *json_str, void *(*callback)(nlohmann::json &js))
{
    if (!callback || !json_str)
        return nullptr;

    nlohmann::json js = nlohmann::json::parse(json_str);

    return callback(js);
}

int
lite_json::json_save(const void *obj, const std::string filename, nlohmann::json (*callback)(const void *obj))
{
    int fd = -1;
    int err = 0;
    nlohmann::json js = nullptr;
    std::string str;

    fd = open(filename.c_str(), O_WRONLY | O_CREAT, 0666);
    if (fd < 0)
        return -EINVAL;

    if (!callback || !obj)
        goto out;

    js = this->encode(obj, callback);

    str = js.dump(4);

    if ((write(fd, str.c_str(), str.size()) <= 0))
    {
        err = -EIO;
        goto out;
    }

out:
    close(fd);
    return err;
}
