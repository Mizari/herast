#include <stdio.h>

struct foo {
    int bar;
    char zxc[16];
};

int main()
{
    struct foo kek = {12345, "123456789012345"};
    puts("asdf");
    printf("Whoa - %s\n", kek.zxc);
    return 0;
}
