#include "common.h"

#define MAX_USERS 1000
static unsigned int storedKeys[MAX_USERS]; // 0 = not set

int main(void)
{
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    memset(storedKeys, 0, sizeof(storedKeys));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT_PKE);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    printf("[PKE] Public Key Server running on port %d...\n", SERVER_PORT_PKE);

    while (1)
    {
        PClientToPKServer recvMsg;
        ssize_t n = recvfrom(sockfd, &recvMsg, sizeof(recvMsg), 0,
                             (struct sockaddr *)&client_addr, &addr_len);
        if (n < 0)
        {
            perror("recvfrom");
            continue;
        }

        if (recvMsg.messageType == registerKey)
        {
            if (recvMsg.userID < MAX_USERS)
            {
                storedKeys[recvMsg.userID] = recvMsg.publicKey;
                printf("[PKE] registerKey user=%u key=%u\n", recvMsg.userID, recvMsg.publicKey);
            }
            else
            {
                printf("[PKE] ERROR: userID %u out of range\n", recvMsg.userID);
            }

            PKServerToPClientOrLodiServer reply = {
                .messageType = ackRegisterKey,
                .userID = recvMsg.userID,
                .publicKey = recvMsg.publicKey};
            sendto(sockfd, &reply, sizeof(reply), 0,
                   (struct sockaddr *)&client_addr, addr_len);
        }
        else if (recvMsg.messageType == requestKey)
        {
            unsigned int target = recvMsg.userID;
            unsigned int key = (target < MAX_USERS) ? storedKeys[target] : 0;

            printf("[PKE] requestKey for user=%u -> key=%u\n", target, key);

            PKServerToPClientOrLodiServer reply = {
                .messageType = responsePublicKey,
                .userID = target,
                .publicKey = key // 0 means "not found"
            };
            sendto(sockfd, &reply, sizeof(reply), 0,
                   (struct sockaddr *)&client_addr, addr_len);
        }
        else
        {
            printf("[PKE] Unknown messageType=%d (ignored)\n", recvMsg.messageType);
        }
    }

    close(sockfd);
    return 0;
}
