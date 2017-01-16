//
//  AgilePQTLSClient.hpp
//  AgilePQTLSClient
//
//  Created by Sergio Fernandez on 11/11/16.
//  Copyright © 2016 ASCI Inc. All rights reserved.
//

#ifndef AgilePQTLSClient_hpp
#define AgilePQTLSClient_hpp


#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#else
#include <unistd.h>
#include <netdb.h>
//#include <iostream>
//#include <fstream>
#include <sys/stat.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

//#include "AgilePQ\SPRNG.hpp"
//#include "AgilePQ\ECA_Int_KDT.h"

//#include "AgilePQ\ECA_Serial.hpp"
//#include "Fordo\Bob.h"

class  AgilePQTLSClient  {
	bool bDoneWithNegotiation;
	unsigned char * createPRNGTable(unsigned int size);

   
#ifdef _WIN32
	SOCKET clientSocket = INVALID_SOCKET;
#else
	int clientSocket;
    struct sockaddr_in server_addr;

#endif    
//	ECA_Serial * DCMKDT;

//	ECA_Serial * DCMSend;
//	ECA_Serial * DCMRecv;

//	PRNG prng;
//	MyRnd trng;

	bool bRunning;
//	void setUp(unsigned char* sharedSecret);

     public:
		 AgilePQTLSClient();
    int connect(const char *address, int port);
    size_t read(  void   *buffer, size_t len);
    size_t write( const void  *buffer, size_t len);
#ifdef _WIN32
	int close() { 
		bDoneWithNegotiation = false;
		return closesocket(clientSocket); 
	}
#else
	int close() { return ::close(clientSocket); }
#endif
     bool negotiate(); //May be called multiple times to finish the negotiation
	//Bob pBob;

	
};




#endif /* AgilePQTLSClient_hpp */
#ifdef __cplusplus
}
#endif
