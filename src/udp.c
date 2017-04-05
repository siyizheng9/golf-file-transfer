#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "common.h"
#include "udp.h"


bool init_srv_state(udp_srv_stat* srv_state)
{

	/* Initialize server state structure parameters */
	srv_state->max_windows_size = UDP_DEFAULT_MAX_WINDOW_SIZE;
	srv_state->window_size = 1;
	//srv_state->window_start = 0;
	srv_state->window_end = NULL;
	srv_state->window_free_slot = srv_state->window_size;
	srv_state->slow_start_threshold = UDP_DEFAULT_SSTHRESH;
	srv_state->expected_ack = 1;
	srv_state->num_acks = 0;
	srv_state->num_dup_acks = 0;
	srv_state->last_dup_ack = 0;
	srv_state->state = WINDOW_STATE_SLOW_START;
	srv_state->window_slots = NULL;
	
	// get directory and port from config file
	int fd;
	int max_w, ss_t;
    if ((fd = open(SERVER_CONFIG_FILE, O_RDONLY)) < 0) {
        printf("Open server config file error\n");
    }
  	else if ( get_server_config(fd, &max_w, &ss_t) == false) {
        printf("Error: failed to get max_windows_size and slow_start_threshold\n");
    } else {
    	srv_state->max_windows_size = max_w;
    	srv_state->slow_start_threshold = ss_t;

    	printf("get from server config file max_windows_size:%d slow_start_threshold:%d\n"
    	,srv_state->max_windows_size, srv_state->slow_start_threshold);
    }

	return true;
}

int init_cli_state(udp_cli_stat* cli_state)
{	
	int n;

	memset(cli_state, 0 ,sizeof(udp_cli_stat));
	cli_state->window_size = CLIENT_DEFAULT_WINDOW_SIZE;
	cli_state->window_start = 0;
	cli_state->window_end = 0;
	cli_state->expected_seq = 0;
	cli_state->window_free_slot = cli_state->window_size;
	pthread_mutex_init(&cli_state->window_lock, NULL);

	// get receive window size from config file
	int fd;
	int recv_w;
    if ((fd = open(CLIENT_CONFIG_FILE, O_RDONLY)) < 0) {
        printf("Open client config file error\n");
    }
  	else if ( get_client_config(fd, &recv_w) == false) {
        printf("Error: failed to get receive window_size\n");
    } else {
    	cli_state->window_size = recv_w;
    	cli_state->window_free_slot = recv_w;
    	printf("get from client config file receive window_size:%d\n"
    			,cli_state->window_size);
    }
    //

	cli_state->window_slots = 
		(udp_msg*)malloc(cli_state->window_size * sizeof(udp_msg));
	if(cli_state->window_slots == NULL){
		printf("init_cli_state: failed to malloc for window_slots\n");
		return -1;
	}

	memset(cli_state->window_slots, 0, cli_state->window_size * sizeof(udp_msg));

	cli_state->window_valid_slot = 
		(bool*)malloc(cli_state->window_size * sizeof(bool));
	if(cli_state->window_valid_slot == NULL) {
		printf("init_cli_state: failed to malloc for window_valid_slot");
		return -1;
	}

	for(n = 0; n < cli_state->window_size; n++) {

		cli_state->window_valid_slot[n] = false;
	}

	return 0;

}

bool srv_state_destroy(udp_srv_stat* srv_state)
{
	node* n = srv_state->window_slots;
	node* ptr;
	while(n != NULL){
		ptr = n;
		n = n->next;
		free(ptr);
	}
	srv_state->window_slots = NULL;
	return true;
}

bool cli_state_destroy(udp_cli_stat* cli_state)
{

	if(cli_state->window_slots != NULL) 
		free(cli_state->window_slots);

	if(cli_state->window_valid_slot != NULL)
		free(cli_state->window_valid_slot);

	return true;

}

void print_srv_state(udp_srv_stat* srv_state)
{
	printf("srv_state:\n");
	printf("window_size: %d\n", srv_state->window_size);
	if(srv_state->window_slots != NULL){
		printf("window_start: %d\n", srv_state->window_slots->msg.header.seq);
		printf("window_end: %d\n", srv_state->window_end->msg.header.seq);
	} else {
		printf("window is empty\n");
	}
	
	printf("window_free_slot: %d\n", srv_state->window_free_slot);
	printf("max_windows_size: %d\n", srv_state->max_windows_size);
	printf("slow_start_threshold: %d\n", srv_state->slow_start_threshold);
	printf("expected_ack: %d\n", srv_state->expected_ack);
	printf("client_window_size: %d\n", srv_state->client_window_size);
	printf("state: %d\n", srv_state->state);
	printf("num_acks: %d\n", srv_state->num_acks );
	printf("num_dup_acks: %d\n", srv_state->num_dup_acks);
	printf("last_dup_ack: %d\n", srv_state->last_dup_ack);

}

bool udp_msg_serialize(udp_msg* msg, char* result_buf)
{
	if(msg == NULL || result_buf == NULL)
		return false;

	result_buf[0] = msg->header.msg_type;
	uint32_t* p = (uint32_t*) (result_buf + 1);
	*p = htonl(msg->header.seq);
	result_buf[5] = msg->header.window_size;
	p = (uint32_t*) (result_buf + 6);
	*p = htonl(msg->header.ts);
	p = (uint32_t*) (result_buf + 10);
	*p = htonl(msg->header.payload_length);

	memcpy(&result_buf[UDP_MSG_HEADER_SIZE], msg->payload,
			UDP_MSG_PAYLOAD_SIZE);

	return true;


}

bool udp_msg_deserialize(udp_msg* msg, char* result_buf)
{
	if(msg == NULL || result_buf == NULL)
	{
		return false;
	}
	msg->header.msg_type = result_buf[0];
	uint32_t* p = (uint32_t*) (result_buf + 1);
	msg->header.seq = ntohl(*p);
	msg->header.window_size = result_buf[5];
	p = (uint32_t*) (result_buf + 6);
	msg->header.ts = ntohl(*p);
	p = (uint32_t*) (result_buf + 10);
	msg->header.payload_length = ntohl(*p);

	memcpy(msg->payload, result_buf + UDP_MSG_HEADER_SIZE
			, UDP_MSG_PAYLOAD_SIZE);

	return true;
}

void udp_msg_init(udp_msg* msg)
{
	msg->header.msg_type = 0;
	msg->header.seq = 0;
	msg->header.ts = 0;
	msg->header.window_size = 0;
	msg->header.payload_length = 0;

	memset(msg->payload, 0, UDP_MSG_PAYLOAD_SIZE);
}


void udp_msg_setType(udp_msg* msg, uint8_t msg_type)
{
	msg->header.msg_type = msg_type;
}

void udp_msg_setSeq(udp_msg* msg, uint32_t seq)
{
	msg->header.seq = seq;
}

void udp_msg_setTs(udp_msg* msg, uint32_t ts)
{
	msg->header.ts = ts;
}

void udp_msg_set_PayLoadLength(udp_msg* msg, uint32_t length)
{
	msg->header.payload_length = length;
}

void udp_msg_set_windowSize(udp_msg* msg, uint8_t window_size)
{
	msg->header.window_size = window_size;
}

uint8_t udp_msg_getType(udp_msg* msg)
{
	return msg->header.msg_type;
}

uint32_t udp_msg_getSeq(udp_msg* msg)
{
	return msg->header.seq;
}

uint32_t udp_msg_getTs(udp_msg* msg)
{
	return msg->header.ts;
}

uint8_t udp_msg_get_windowSize(udp_msg* msg)
{
	return msg->header.window_size;
}

uint32_t udp_msg_get_PaylaodLength(udp_msg* msg)
{
	return msg->header.payload_length;
}

void udp_msg_print(udp_msg* msg)
{
	uint8_t msg_type = msg->header.msg_type;
	uint32_t ts = msg->header.ts;
	uint8_t seq = msg->header.seq;
	uint8_t window_size = msg->header.window_size;
	uint32_t payload_length = msg->header.payload_length;

	char payload_buf[UDP_MSG_PAYLOAD_SIZE];

	memcpy(payload_buf, msg->payload, payload_length);
 	payload_buf[payload_length] = '\0';

 	printf("msg type:%d\nmsg ts:%d\nmsg seq:%d\nmsg win size:%d\n"
 		"msg payload length:%d\n",msg_type,ts,seq,window_size,payload_length);
 	printf("msg payload:\n%s\n", payload_buf);

}
