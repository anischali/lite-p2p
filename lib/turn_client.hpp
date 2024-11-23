#ifndef __TURN_CLIENT_HPP__
#define __TURN_CLIENT_HPP__


class turn_client
{
private:
    const char *hostname;
    const char *credential;
    /* data */
public:
    turn_client(/* args */);
    ~turn_client();
};

#endif