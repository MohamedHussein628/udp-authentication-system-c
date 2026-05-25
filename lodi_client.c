// lodi_client.c
#include "common.h"

static void send_register(int sockfd, struct sockaddr_in *pke_addr,
                          unsigned int userID, unsigned int publicKey)
{
    PClientToPKServer msg = {.messageType = registerKey, .userID = userID, .publicKey = publicKey};
    PKServerToPClientOrLodiServer reply;
    socklen_t len = sizeof(*pke_addr);

    printf("[Client] -> registerKey user=%u key=%u\n", userID, publicKey);
    sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr *)pke_addr, sizeof(*pke_addr));
    recvfrom(sockfd, &reply, sizeof(reply), 0, (struct sockaddr *)pke_addr, &len);
    printf("[Client] <- ackRegisterKey user=%u key=%u\n", reply.userID, reply.publicKey);
}

static void send_request(int sockfd, struct sockaddr_in *pke_addr, unsigned int userID)
{
    PClientToPKServer msg = {.messageType = requestKey, .userID = userID, .publicKey = 0};
    PKServerToPClientOrLodiServer reply;
    socklen_t len = sizeof(*pke_addr);

    printf("[Client] -> requestKey for user=%u\n", userID);
    sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr *)pke_addr, sizeof(*pke_addr));
    recvfrom(sockfd, &reply, sizeof(reply), 0, (struct sockaddr *)pke_addr, &len);
    printf("[Client] <- responsePublicKey user=%u key=%u\n", reply.userID, reply.publicKey);
}

static void do_login(unsigned int userID, unsigned int privateKey)
{
    // ---- make a separate socket for talking to Lodi server
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket(login)");
        exit(1);
    }

    struct sockaddr_in lodi_addr = {0};
    lodi_addr.sin_family = AF_INET;
    lodi_addr.sin_port = htons(SERVER_PORT_LODI);
    inet_pton(AF_INET, "127.0.0.1", &lodi_addr.sin_addr);

    PClientToLodiServer loginMsg = {0};
    loginMsg.messageType = login;
    loginMsg.userID = userID;
    loginMsg.recipientID = 0;

    // ---- timestamp + signature (DS = timestamp XOR privateKey)
    loginMsg.timestamp = (unsigned long)time(NULL);
    loginMsg.digitalSig = (loginMsg.timestamp ^ privateKey);

    printf("[Client] -> login user=%u ts=%lu DS=%lu\n",
           loginMsg.userID, loginMsg.timestamp, loginMsg.digitalSig);

    if (sendto(sock, &loginMsg, sizeof(loginMsg), 0,
               (struct sockaddr *)&lodi_addr, sizeof(lodi_addr)) < 0)
    {
        perror("sendto(login)");
        close(sock);
        return;
    }

    // ---- wait for ackLogin
    LodiServerToLodiClientAcks ack = {0};
    socklen_t l = sizeof(lodi_addr);
    ssize_t rn = recvfrom(sock, &ack, sizeof(ack), 0,
                          (struct sockaddr *)&lodi_addr, &l);
    if (rn < 0)
    {
        perror("[Client] recvfrom(ackLogin)");
        printf("[Client] No ackLogin received (first-factor probably failed)\n");
    }
    else if (ack.messageType == ackLogin)
    {
        printf("[Client] <- ackLogin for user=%u ✅\n", ack.userID);
    }
    else
    {
        printf("[Client] <- unexpected ack type=%d\n", ack.messageType);
    }

    close(sock);
}

int main(void)
{
    // ---- socket for talking to PKE
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in pke_addr = {0};
    pke_addr.sin_family = AF_INET;
    pke_addr.sin_port = htons(SERVER_PORT_PKE);
    inet_pton(AF_INET, "127.0.0.1", &pke_addr.sin_addr);

    // Demo keys (public == private for our XOR demo)
    unsigned int userID = 10;
    unsigned int publicKey = 12345;
    unsigned int privateKey = 12345;

    // 1) Register key
    send_register(sockfd, &pke_addr, userID, publicKey);

    // 2) Optional: request key checks
    send_request(sockfd, &pke_addr, userID);
    send_request(sockfd, &pke_addr, 77);

    close(sockfd);

    // 3) First-factor login to Lodi server
    do_login(userID, privateKey);

    return 0;
}
