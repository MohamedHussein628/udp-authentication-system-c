// lodi_server.c
#include "common.h"

int main(void)
{
    // ---- Lodi server socket (listening for client login)
    int lodi_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (lodi_sock < 0)
    {
        perror("socket(lodi)");
        exit(1);
    }

    struct sockaddr_in lodi_addr = {0}, client_addr = {0};
    socklen_t client_len = sizeof(client_addr);

    lodi_addr.sin_family = AF_INET;
    lodi_addr.sin_addr.s_addr = INADDR_ANY;
    lodi_addr.sin_port = htons(SERVER_PORT_LODI);

    if (bind(lodi_sock, (struct sockaddr *)&lodi_addr, sizeof(lodi_addr)) < 0)
    {
        perror("bind(lodi)");
        exit(1);
    }

    // ---- PKE server address (to request public key)
    int pke_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (pke_sock < 0)
    {
        perror("socket(pke)");
        exit(1);
    }

    struct sockaddr_in pke_addr = {0};
    pke_addr.sin_family = AF_INET;
    pke_addr.sin_port = htons(SERVER_PORT_PKE);
    inet_pton(AF_INET, "127.0.0.1", &pke_addr.sin_addr);

    printf("[Lodi] Server running on UDP %d …\n", SERVER_PORT_LODI);

    while (1)
    {
        // 1) Receive login from client
        PClientToLodiServer loginMsg;
        ssize_t n = recvfrom(lodi_sock, &loginMsg, sizeof(loginMsg), 0,
                             (struct sockaddr *)&client_addr, &client_len);
        if (n < 0)
        {
            perror("recvfrom(login)");
            continue;
        }

        if (loginMsg.messageType != login)
        {
            printf("[Lodi] Ignored non-login message type=%d\n", loginMsg.messageType);
            continue;
        }

        printf("[Lodi] login request: user=%u ts=%lu DS=%lu\n",
               loginMsg.userID, loginMsg.timestamp, loginMsg.digitalSig);

        // 2) Ask PKE for public key
        PClientToPKServer req = {.messageType = requestKey,
                                 .userID = loginMsg.userID,
                                 .publicKey = 0};
        if (sendto(pke_sock, &req, sizeof(req), 0,
                   (struct sockaddr *)&pke_addr, sizeof(pke_addr)) < 0)
        {
            perror("sendto(PKE requestKey)");
            continue;
        }

        PKServerToPClientOrLodiServer keyReply;
        socklen_t pke_len = sizeof(pke_addr);
        if (recvfrom(pke_sock, &keyReply, sizeof(keyReply), 0,
                     (struct sockaddr *)&pke_addr, &pke_len) < 0)
        {
            perror("recvfrom(PKE response)");
            continue;
        }

        if (keyReply.messageType != responsePublicKey)
        {
            printf("[Lodi] Unexpected PKE msg type=%d\n", keyReply.messageType);
            continue;
        }

        unsigned int publicKey = keyReply.publicKey;
        printf("[Lodi] PKE returned publicKey=%u for user=%u\n",
               publicKey, keyReply.userID);

        if (publicKey == 0)
        {
            printf("[Lodi] ERROR: No public key registered for user=%u\n", loginMsg.userID);
            continue; // authentication fails
        }

        // 3) Verify DS (DS ^ publicKey) must equal timestamp
        unsigned long recovered = (loginMsg.digitalSig ^ publicKey);
        int ok = (recovered == loginMsg.timestamp);

        if (ok)
        {
            printf("[Lodi] First-factor OK for user=%u ✅\n", loginMsg.userID);

            // 4) Send ackLogin back to client
            LodiServerToLodiClientAcks ack = {.messageType = ackLogin,
                                              .userID = loginMsg.userID};
            if (sendto(lodi_sock, &ack, sizeof(ack), 0,
                       (struct sockaddr *)&client_addr, client_len) < 0)
            {
                perror("sendto(ackLogin)");
            }
            else
            {
                printf("[Lodi] Sent ackLogin to client\n");
            }
        }
        else
        {
            printf("[Lodi] First-factor FAILED for user=%u ❌ (recovered=%lu vs ts=%lu)\n",
                   loginMsg.userID, recovered, loginMsg.timestamp);
            // per spec: send corresponding error message; minimal flow = just log
            // (You could add an error datagram here if you want.)
        }
    }

    close(pke_sock);
    close(lodi_sock);
    return 0;
}
