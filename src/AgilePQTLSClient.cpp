//
//  AgilePQTLSClient.cpp
//  Fordo
//
//  Created by Sergio Fernandez on 11/18/16.
//  Copyright © 2016 ASCI Inc. All rights reserved.
//

#include "azure_c_shared_utility/AgilePQTLSClient.h"


#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Constructor for the FrodoClient, a subclass of EchoClientConnection. Initializes an  * @param address address of the OAUServer to connect to.
 */
AgilePQTLSClient::AgilePQTLSClient()
{ 
	bDoneWithNegotiation = false; 
	//DCMKDT = new ECA_Serial(17);
	//DCMSend = new ECA_Serial(17);
	//DCMRecv = new ECA_Serial(17);
}

int AgilePQTLSClient::connect(const char *address, int port){
#ifdef _WIN32
	WSADATA wsaData;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;
	int iResult;
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		//	return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;


	// Resolve the server address and port
	char sport[8];
	sprintf(sport, "%d", port);
	iResult = getaddrinfo(address, sport, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		clientSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (clientSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}

		// Connect to server.
		iResult = ::connect(clientSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(clientSocket);
			clientSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (clientSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}
	return 0;
#else
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0){
        assert(0);
    }
    struct hostent *server = gethostbyname(address);
    
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *) server->h_addr,
          (char *) &server_addr.sin_addr.s_addr,server->h_length);
    server_addr.sin_port = htons(port);
    
    
    // char *some_addr = inet_ntoa(client_addr.sin_addr); // return the IP
   // printf("connect to %s:%d\n", address,port); // prints "10.0.0.1"
    
    int rv = ::connect(clientSocket,(struct sockaddr *) &server_addr, sizeof(server_addr));
    if(rv<0){
        printf("Client could not connect %s:%d rv=%d\n",address,port,rv);
        clientSocket=0;
        return rv;
    }
    
    printf("Cconnected %s:%d\n",address,port);
    
    return rv;
#endif   
}
size_t AgilePQTLSClient::read( void  *buffer, size_t len){
#ifdef _WIN32
	size_t iResult = recv(clientSocket, (char *)buffer, len, 0);
	int nError = WSAGetLastError();
	if (nError != WSAEWOULDBLOCK&&nError != 0) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(clientSocket);
		WSACleanup();
		return 0;
}
#else
    size_t iResult = ::read(clientSocket,buffer,len);
#endif
	if (iResult > 1600)
		return 0;

    unsigned char *pBuf=(unsigned char *)buffer;
	//pBuf=pBob.decode((unsigned char *)buffer, iResult);
   for(size_t i=0;i<iResult;i++){ //Here is where we will do the decoding
    *(pBuf+i) ^=1;
  }
    return iResult;
}
size_t AgilePQTLSClient::write(const void   *buffer, size_t len){
    unsigned char *pBuf=(unsigned char *)buffer;
	for (size_t i = 0; i<len; i++) { //Here is where we will do the decoding
		*(pBuf + i) ^= 1;
	}
	//pBuf = pBob.encode((unsigned char*)buffer, len);
#ifdef _WIN32
	size_t iResult = send(clientSocket, (char *)buffer,len, 0);
#else
	size_t iResult::write(clientSocket, buffer, len);
#endif
	if (iResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(clientSocket);
		WSACleanup();
	}
	return iResult;
}

bool  AgilePQTLSClient::negotiate(){
	if (bDoneWithNegotiation) {
		return true;
	}
	//pBob.startNegotiation(clientSocket);
	//while (pBob.Negotiate() == false);
	 
	//u_long iMode = 1;
//	ioctlsocket(clientSocket, FIONBIO, &iMode);


//	setUp(pBob.getSecret());
	
    unsigned char bobPublic[1024];
    for(int i=0;i<1024;i++){ //Here is where we will do the decoding
        bobPublic[i]=(unsigned char)i;
    }

#ifdef _WIN32
	size_t iResult = send(clientSocket, (char *)bobPublic, sizeof(bobPublic), 0);
#else
	size_t iResult::write(clientSocket, bobPublic, sizeof(bobPublic));
#endif
   
    if(iResult == sizeof(bobPublic)){
        unsigned char alicePublic[1024];
#ifdef _WIN32
		 iResult = recv(clientSocket, (char *)alicePublic, sizeof(alicePublic), 0);
		if (iResult == SOCKET_ERROR) {
			printf("Negotiation failed reciving alice key error: %d\n", WSAGetLastError());
			closesocket(clientSocket);
			WSACleanup();
			return false;
		}
#else
		 iResult = ::read(clientSocket, alicePublic, sizeof(alicePublic));
#endif

        if(iResult == sizeof(alicePublic)){
			bDoneWithNegotiation = true;
			printf("Negotiation sucess reciving alice key error: %d\n", WSAGetLastError());

            return true;
        }
    }
	
	
    return true;
}

#ifdef __cplusplus
}
#endif

