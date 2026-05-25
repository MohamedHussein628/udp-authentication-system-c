#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(5000);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);

    const char *msg = "hello, PKE!";
    printf("Sent test message!\n");

    sendto(s, msg, strlen(msg), 0, (struct sockaddr *)&a, sizeof(a));
    close(s);
    return 0;
}
