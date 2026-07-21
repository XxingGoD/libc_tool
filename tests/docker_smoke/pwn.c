#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[64];
    puts("libc_tool docker smoke");
    fflush(stdout);
    if (read(STDIN_FILENO, buf, sizeof(buf)) < 0) {
        return 1;
    }
    return 0;
}
