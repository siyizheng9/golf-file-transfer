#ifndef SERVER_H
#define SERVER_H

#include "service.h"

#define LISTENQ 5

int create_service(int serverport);
int create_service_6(int serverport);

int get_client_socket(int listenfd, int listenfd_6, client_profile* ptr_client_profile);
bool server_handshake(int clientfd);
void handle_client_request(client_profile* ptr_client_profile);

#endif