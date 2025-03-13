#include <lite-p2p/types/list_head.hpp>

INIT_HEAD(l1);
INIT_HEAD(l2);

#define log(l) printf("%s - [next: %p - prev: %p]\n", #l, (&l)->next, (&l)->prev);

int main(int argc, char const *argv[])
{
    
    log(l1);
    log(l2);

    printf("After one add\n");
    list_add_tail(&l1, &l2);
    log(l1);
    log(l2);

    printf("After two add\n");
    list_add_tail(&l1, &l2);
    log(l1);
    log(l2);

   

    return 0;
}
