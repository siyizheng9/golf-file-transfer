#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <netinet/in.h>

#define CLIENT_CONFIG_FILE "client.config"
#define SERVER_CONFIG_FILE "server.config"


#define DEFAULTADDR "127.0.0.1"
#define DEFAULTPORT "12000"
#define DEFAULTPOORT_LENGTH 10

#define PACKET_TYPE_HELLO	1
#define PACKET_TYPE_END 	2

#define PACKET_TYPE_COMMAND_UPLOAD	3
#define PACKET_TYPE_COMMAND_DOWNLOAD	4

#define PACKET_TYPE_DATA_BEGINNING	5
#define PACKET_TYPE_DATA 	6
#define PACKET_TYPE_DATA_ENDING	7	

#define PACKET_TYPE_COMMAND_ACCEPT	8
#define PACKET_TYPE_COMMAND_DENY	9

#define PACKET_TYPE_COMMAND_DOWNLOAD_UDP 10
#define PACKET_TYPE_COMMAND_UPLOAD_UDP 11

#define PACKET_TYPE_COMMAND_LS 12
#define PACKET_TYPE_COMMAND_PWD 13
#define PACKET_TYPE_COMMAND_CD 14
#define PACKET_TYPE_COMMAND_MD 15
#define PACKET_TYPE_COMMAND_DEL 16

#define TCP_PAYLOAD_SIZE	1250
#define BASE_PACKET_TYPE_SIZE 1
#define BASE_PACKET_PAYLOAD_LENGTH_SIZE 4
#define BASE_PACKET_SIZE	5
#define EXTEND_PACKET_SIZE	1255

typedef int bool;
#define true 1
#define false 0

typedef struct Base_Packet B_Packet;
typedef struct Extend_Packet E_Packet;

/* TCP data packet structure */

struct Base_Packet
{
	
	uint8_t pkt_type;
	
	uint32_t payload_length;
};

struct Extend_Packet
{
	B_Packet header;
	
	char payload[TCP_PAYLOAD_SIZE];
	
};

bool tcp_send_pkt(int connfd, E_Packet* a_e_pkt);

bool tcp_recv_pkt(int connfd, E_Packet* a_e_pkt);

B_Packet* B_Packet_create(uint8_t pkt_type, uint32_t payload_length);

E_Packet* E_Packet_create(B_Packet header, char* payload);

bool b_pkt_serialize(B_Packet a_b_pkt, char* result_buf);

bool b_pkt_deserialize(char* b_pkt_buf, B_Packet* a_b_pkt);

bool e_pkt_serialize(E_Packet* a_e_pkt, char* result_buf);

bool e_pkt_deserialize(char* e_pkt_buf, E_Packet* a_e_pkt);

void server_log(char* record);

void E_Packet_destroy(E_Packet* a_e_pkt);

void B_Packet_destroy(B_Packet* a_b_pkt);

uint8_t E_Packet_getType(E_Packet* a_e_pkt);

void E_Packet_setType(E_Packet* a_e_pkt, uint8_t pkt_type);

uint32_t E_Packet_getPayloadLength(E_Packet* a_e_pkt);

void E_Packet_setPayloadLength(E_Packet* a_e_pkt, uint32_t payload_length);

void E_Packet_clear(E_Packet* a_e_pkt);

void E_Packet_print(E_Packet* a_e_pkt);

/*
read file into buf and return pointer to the buf
set p_file_length
 */
char* read_file(char* file_path, int* p_file_length);

/*
write file into the path and return bool value
 */
bool write_file(char* file_path, char* data, int file_length);

/*
receive file
return file buffer
set file_length
 */
char* tcp_recv_file(int connfd, int* file_length);
/*
send file
 */
bool tcp_send_file(int connfd, char* file_buf, int file_length);

void prepend(char* s, const char* t);
bool send_upload_request(int connfd, char* file_path);
bool get_server_config(int fd, int* max_w, int* ss_t);
bool get_client_config(int fd, int* max_w);
void print_ipaddr_pair(struct sockaddr* src, struct sockaddr* dst, bool isIPv4);
void write_log(char* message);

#endif