// common.h
#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/socket.h>

#define SERVER_PORT_PKE 5000
#define SERVER_PORT_TFA 5001
#define SERVER_PORT_LODI 5002
#define BUF_SIZE 1024

// Message types
enum PKE_MessageType
{
    registerKey = 1,
    requestKey
};
enum PKE_ServerMessageType
{
    ackRegisterKey,
    responsePublicKey
};
enum Lodi_MessageType
{
    login
};
enum Lodi_AckType
{
    ackLogin
};
enum TFA_ClientToServerType
{
    registerTFA,
    ackRegTFA,
    ackPushTFA,
    requestAuth
};
enum TFA_ServerToClientType
{
    confirmTFA,
    pushTFA
};
enum TFA_ServerToLodiType
{
    responseAuth
};

// Define message structs
typedef struct
{
    enum PKE_MessageType messageType;
    unsigned int userID;
    unsigned int publicKey;
} PClientToPKServer;

typedef struct
{
    enum PKE_ServerMessageType messageType;
    unsigned int userID;
    unsigned int publicKey;
} PKServerToPClientOrLodiServer;

typedef struct
{
    enum Lodi_MessageType messageType;
    unsigned int userID;
    unsigned int recipientID;
    unsigned long timestamp;
    unsigned long digitalSig;
} PClientToLodiServer;

typedef struct
{
    enum Lodi_AckType messageType;
    unsigned int userID;
} LodiServerToLodiClientAcks;

typedef struct
{
    enum TFA_ClientToServerType messageType;
    unsigned int userID;
    unsigned long timestamp;
    unsigned long digitalSig;
} TFAClientOrLodiServerToTFAServer;

typedef struct
{
    enum TFA_ServerToClientType messageType;
    unsigned int userID;
} TFAServerToTFAClient;

typedef struct
{
    enum TFA_ServerToLodiType messageType;
    unsigned int userID;
} TFAServerToLodiServer;

#endif
