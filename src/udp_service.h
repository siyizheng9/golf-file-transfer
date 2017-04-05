#ifndef UDP_SERVICE_H
#define UDP_SERVICE_H

#include "udp.h"

void udp_send_ack(int fd, uint32_t seq , uint32_t window_size);

char* udp_download_file(int connfd, const char* file_path, int* file_length);

bool handle_udp_download_request(int connfd, char* file_data_buf, int file_size);

void* download_speed(void* parm);

bool parse_client_pkt(E_Packet pkt_in, udp_srv_stat* srv_state, struct sockaddr* cliaddr);

bool parse_server_pkt(E_Packet* pkt_in, struct sockaddr* serverad, int* file_size);

int create_udp_socket(int connfd);

char* udp_recv_file(int fd, int file_size);

int udp_close(int clientfd);

int create_udp_socket_6(int connfd);

bool udp_send_file(int clientfd, char* file_data_buf, int file_size);


#endif