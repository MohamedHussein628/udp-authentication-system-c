// tfa_client.c
#include "common.h"

int main(void)
{
    unsigned int userID = 10;        // same demo user
    unsigned int privateKey = 12345; // matches PKE’s publicKey for demo

    // ---- socket to talk to TFA server
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in tfa_addr = {0};
    tfa_addr.sin_family = AF_INET;
    tfa_addr.sin_port = htons(SERVER_PORT_TFA);
    inet_pton(AF_INET, "127.0.0.1", &tfa_addr.sin_addr);

    // ---- build registerTFA: DS = timestamp XOR privateKey
    TFAClientOrLodiServerToTFAServer reg = {0};
    reg.messageType = registerTFA;
    reg.userID = userID;
    reg.timestamp = (unsigned long)time(NULL);
    reg.digitalSig = (reg.timestamp ^ privateKey);

    printf("[TFA-Client] -> registerTFA user=%u ts=%lu DS=%lu\n",
           reg.userID, reg.timestamp, reg.digitalSig);

    if (sendto(sock, &reg, sizeof(reg), 0,
               (struct sockaddr *)&tfa_addr, sizeof(tfa_addr)) < 0)
    {
        perror("sendto(registerTFA)");
        close(sock);
        return 1;
    }

    // ---- wait for confirmTFA
    TFAServerToTFAClient conf = {0};
    socklen_t alen = sizeof(tfa_addr);
    ssize_t rn = recvfrom(sock, &conf, sizeof(conf), 0,
                          (struct sockaddr *)&tfa_addr, &alen);
    if (rn < 0)
    {
        perror("recvfrom(confirmTFA)");
        close(sock);
        return 1;
    }

    if (conf.messageType == confirmTFA && conf.userID == userID)
    {
        printf("[TFA-Client] <- confirmTFA for user=%u ✅\n", conf.userID);
    }
    else
    {
        printf("[TFA-Client] <- unexpected message type=%d user=%u\n",
               conf.messageType, conf.userID);
    }

    // ---- send ackRegTFA to complete handshake
    TFAClientOrLodiServerToTFAServer ack = {0};
    ack.messageType = ackRegTFA;
    ack.userID = userID;
    ack.timestamp = 0;
    ack.digitalSig = 0;

    printf("[TFA-Client] -> ackRegTFA user=%u\n", userID);
    if (sendto(sock, &ack, sizeof(ack), 0,
               (struct sockaddr *)&tfa_addr, sizeof(tfa_addr)) < 0)
    {
        perror("sendto(ackRegTFA)");
    }

    close(sock);
    return 0;
}
