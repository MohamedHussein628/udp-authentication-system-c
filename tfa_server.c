// tfa_server.c
#include "common.h"

#define MAX_USERS 1000

typedef struct
{
    int inUse;
    struct sockaddr_in addr; // where to push later
} TFARegistration;

static TFARegistration tfaTable[MAX_USERS];

int main(void)
{
    // ---- TFA server socket (listening for clients & Lodi server later)
    int tfa_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (tfa_sock < 0)
    {
        perror("socket(tfa)");
        exit(1);
    }

    struct sockaddr_in tfa_addr = {0}, client_addr = {0};
    socklen_t client_len = sizeof(client_addr);

    tfa_addr.sin_family = AF_INET;
    tfa_addr.sin_addr.s_addr = INADDR_ANY;
    tfa_addr.sin_port = htons(SERVER_PORT_TFA);
    if (bind(tfa_sock, (struct sockaddr *)&tfa_addr, sizeof(tfa_addr)) < 0)
    {
        perror("bind(tfa)");
        exit(1);
    }

    // ---- PKE server socket/address
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

    memset(tfaTable, 0, sizeof(tfaTable));
    printf("[TFA] Server running on UDP %d …\n", SERVER_PORT_TFA);

    while (1)
    {
        TFAClientOrLodiServerToTFAServer in;
        ssize_t n = recvfrom(tfa_sock, &in, sizeof(in), 0,
                             (struct sockaddr *)&client_addr, &client_len);
        if (n < 0)
        {
            perror("recvfrom(TFA)");
            continue;
        }

        if (in.messageType == registerTFA)
        {
            printf("[TFA] registerTFA from user=%u ts=%lu DS=%lu\n",
                   in.userID, in.timestamp, in.digitalSig);

            // 1) Ask PKE for public key
            PClientToPKServer req = {.messageType = requestKey, .userID = in.userID, .publicKey = 0};
            if (sendto(pke_sock, &req, sizeof(req), 0,
                       (struct sockaddr *)&pke_addr, sizeof(pke_addr)) < 0)
            {
                perror("sendto(PKE requestKey)");
                continue;
            }

            PKServerToPClientOrLodiServer keyReply;
            socklen_t plen = sizeof(pke_addr);
            if (recvfrom(pke_sock, &keyReply, sizeof(keyReply), 0,
                         (struct sockaddr *)&pke_addr, &plen) < 0)
            {
                perror("recvfrom(PKE response)");
                continue;
            }
            if (keyReply.messageType != responsePublicKey)
            {
                printf("[TFA] Unexpected PKE reply type=%d\n", keyReply.messageType);
                continue;
            }
            unsigned int publicKey = keyReply.publicKey;
            printf("[TFA] PKE returned publicKey=%u for user=%u\n", publicKey, keyReply.userID);
            if (publicKey == 0)
            {
                printf("[TFA] ERROR: user=%u has no registered public key\n", in.userID);
                continue; // fail auth
            }

            // 2) Verify signature: DS ^ publicKey == timestamp
            unsigned long recovered = (in.digitalSig ^ publicKey);
            int ok = (recovered == in.timestamp);

            if (!ok)
            {
                printf("[TFA] Registration signature FAILED for user=%u (recovered=%lu vs ts=%lu)\n",
                       in.userID, recovered, in.timestamp);
                continue;
            }

            // 3) Store client address for pushes later
            if (in.userID < MAX_USERS)
            {
                tfaTable[in.userID].inUse = 1;
                tfaTable[in.userID].addr = client_addr;
            }
            printf("[TFA] Registration OK for user=%u ✅ (stored addr for pushes)\n", in.userID);

            // 4) Send confirmTFA to client
            TFAServerToTFAClient out = {.messageType = confirmTFA, .userID = in.userID};
            if (sendto(tfa_sock, &out, sizeof(out), 0,
                       (struct sockaddr *)&client_addr, client_len) < 0)
            {
                perror("sendto(confirmTFA)");
                continue;
            }

            // 5) Expect ackRegTFA to complete handshake
            TFAClientOrLodiServerToTFAServer ackIn;
            socklen_t tmp = sizeof(client_addr);
            ssize_t rn = recvfrom(tfa_sock, &ackIn, sizeof(ackIn), 0,
                                  (struct sockaddr *)&client_addr, &tmp);
            if (rn < 0)
            {
                perror("recvfrom(ackRegTFA)");
                continue;
            }
            if (ackIn.messageType == ackRegTFA && ackIn.userID == in.userID)
            {
                printf("[TFA] Completed registration (ackRegTFA) for user=%u ✅\n", in.userID);
            }
            else
            {
                printf("[TFA] Unexpected message after confirmTFA: type=%d user=%u\n",
                       ackIn.messageType, ackIn.userID);
            }
        }
        else
        {
            // (Later: handle requestAuth from Lodi, etc.)
            printf("[TFA] Ignored messageType=%d (registration only in this step)\n", in.messageType);
        }
    }

    close(pke_sock);
    close(tfa_sock);
    return 0;
}
