#include "lib/stun_client.hpp"
#include "lib/peer_connection.hpp"
#include <time.h>
#include <thread>



void visichat_listener(void *args) {
    int ret;
    static char buf[512];
    udp_peer_connection *conn = (udp_peer_connection *)args; 
    socklen_t len = sizeof(conn->remote);
    struct sockaddr_in s_addr;

    printf("receiver thread start [OK]\n");

    while(true) {
        ret = recvfrom(conn->sock_fd, buf, 512, 0, (struct sockaddr *)&s_addr, &len);
        if (ret < 0 || buf[0] == 0)
            continue;

        buf[ret] = 0;

        if (!strncmp("exit", &buf[0], 4))
            continue;

        fprintf(stdout, "[%s:%d]: %s\n\r> ", inet_ntoa(s_addr.sin_addr), ntohs(s_addr.sin_port), buf);
    }
}

void visichat_sender(void *args) {
    int cnt = 0;
    char c = 0;
    static char buf[512];
    udp_peer_connection *conn = (udp_peer_connection *)args;

    printf("sender thread start [OK]\n");

    while(true) {
        printf("\r> ");
        while((c = getc(stdin)) != '\n') {
            buf[cnt] = c;
            cnt = ((cnt + 1) % sizeof(buf));
        }

        if (cnt <= 0)
            continue;

        sendto(conn->sock_fd, buf, cnt, 0, (struct sockaddr *)&conn->remote, sizeof(conn->remote));
        cnt = 0;

        if (!strncmp("exit", &buf[0], 4)) {
            sleep(1);
            printf("sender thread stop [OK]\n");
            return;
        }
    }
}



//stun:stun.l.google.com 19302
int main(int argc, char *argv[]) {

    if (argc < 4) {
        printf("wrong arguments number !\n");
        return -1;
    }
    
    srand(time(NULL));
    udp_peer_connection conn(atoi(argv[3]));
    stun_client stun(conn.sock_fd);

    int ret = stun.stun_request(argv[1], atoi(argv[2]));
    printf("STUN: %s [%d]\n", inet_ntoa(stun.ext_ip.sin_addr), ntohs(stun.ext_ip.sin_port));
    if (ret < 0) {
        conn.~udp_peer_connection();
        return ret;
    }

    conn.remote.sin_addr.s_addr = htonl(inet_network("24.48.39.41"));//stun.ext_ip.sin_addr.s_addr;//htonl(inet_network("192.168.0.10"));
    conn.remote.sin_family = AF_INET;
    conn.remote.sin_port = htons(atoi(argv[4]));

    printf("bind: %s [%d]\n", inet_ntoa(conn.local.sin_addr), ntohs(conn.local.sin_port));

    std::thread recver(visichat_listener, &conn);
    std::thread sender(visichat_sender, &conn);

    sender.join();
    recver.join();

    conn.~udp_peer_connection();
    stun.~stun_client();

    return 0;
}