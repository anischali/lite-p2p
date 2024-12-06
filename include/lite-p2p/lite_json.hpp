#ifndef __LITE_JSON_HPP
#define __LITE_JSON_HPP
#include <nlohmann/json.hpp>




namespace lite_p2p {
    class lite_json {
    public:
        lite_json();

        ~lite_json();


        nlohmann::json encode(const void *obj, nlohmann::json (*callback)(const void *obj));
        void *decode(const char *json, void *(*callback)(nlohmann::json &js));
    
        void *json_load(const std::string filename, void *(*callback)(nlohmann::json &js));
        int json_save(const void *obj, const std::string filename, nlohmann::json (*callback)(const void *obj));

    };
};

#endif