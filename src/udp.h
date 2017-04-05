#ifndef UDP_H
#define UDP_H

#include <pthread.h>
#include <stdint.h>
#include "common.h"

#define CLIENT_DEFAULT_WINDOW_SIZE 10

#define CONGESTION_SLOW_START 0
#define CONGESTION_AVOIDANCE 1

#define UDP_DEFAULT_SSTHRESH 20
#define UDP_DEFAULT_MAX_WINDOW_SIZE 10
#define WINDOW_STATE_SLOW_START 0
#define WINDOW_STATE_AVOIDANCE 1

#define MSG_TYPE_DATA_START 1
#define MSG_TYPE_DATA 2
#define MSG_TYPE_DATA_FIN 3
#define MSG_TYPE_DATA_FIN_ACK 4
#define MSG_TYPE_DATA_FIN_ACK_ACK 5
#define MSG_TYPE_FILE_NAME 6
#define MSG_TYPE_CONNECTION_PORT 7
#define MSG_TYPE_ACKNOWLEDGEMENT 8


#define UDP_MSG_PAYLOAD_SIZE 512
#define UDP_MSG_HEADER_SIZE 14
#define UDP_MSG_TOTAL_SIZE 526

typedef struct Header  udp_header;
typedef struct Message  udp_msg;

typedef struct udp_server_state_struct udp_srv_stat;
typedef struct udp_client_state_struct udp_cli_stat;
typedef struct udp_window_slot_node node;

struct Header {
	uint8_t msg_type;
	uint32_t seq;
	uint8_t window_size;
	uint32_t ts;
	uint32_t payload_length;
};

struct Message {

	udp_header header;
	char payload[UDP_MSG_PAYLOAD_SIZE];
};

struct udp_window_slot_node {
	udp_msg msg;
	node*	next;
};

struct udp_server_state_struct {
	uint32_t	window_size;
	//node*		window_start;
	node*		window_end;
	uint32_t	window_free_slot;
	uint32_t	max_windows_size;
	uint32_t	slow_start_threshold;
	uint32_t	expected_ack;
	uint32_t	client_window_size;
	uint32_t	state;
	uint32_t	num_acks;
	uint32_t	num_dup_acks;
	uint32_t	last_dup_ack;
	node* 		window_slots;

};

struct udp_client_state_struct {
	uint32_t	window_size;
	uint32_t	window_start;
	uint32_t	window_end;
	uint32_t	window_free_slot;
	bool*		window_valid_slot;
	uint32_t	expected_seq;
	udp_msg*	window_slots;
	pthread_mutex_t window_lock;
};

bool init_srv_state(udp_srv_stat* srv_state);
void print_srv_state(udp_srv_stat* srv_state);
int init_cli_state(udp_cli_stat* cli_state);
bool cli_state_destroy(udp_cli_stat* cli_state);
bool srv_state_destroy(udp_srv_stat* srv_state);
bool udp_msg_serialize(udp_msg* msg, char* result_buf);
bool udp_msg_deserialize(udp_msg* msg, char* result_buf);
void udp_msg_init(udp_msg* msg);
void udp_msg_setType(udp_msg* msg, uint8_t msg_type);
void udp_msg_setSeq(udp_msg* msg, uint32_t seq);
void udp_msg_setTs(udp_msg* msg, uint32_t ts);
void udp_msg_set_PayLoadLength(udp_msg* msg, uint32_t length);
void udp_msg_set_windowSize(udp_msg* msg, uint8_t window_size);
uint8_t udp_msg_getType(udp_msg* msg);
uint32_t udp_msg_getSeq(udp_msg* msg);
uint32_t udp_msg_getTs(udp_msg* msg);
uint8_t udp_msg_get_windowSize(udp_msg* msg);
uint32_t udp_msg_get_PaylaodLength(udp_msg* msg);
void udp_msg_print(udp_msg* msg);

#endif