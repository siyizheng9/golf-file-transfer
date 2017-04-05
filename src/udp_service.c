#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <stdlib.h>
#include <sys/time.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include "common.h"
#include "rtt.h"
#include "udp.h"
#include "udp_service.h"

static struct rtt_info rttinfo;
static int rttinit = 0;
static sigjmp_buf jmpbuf;
extern bool isIPv4;
int pkt_sent_count = 0;
int pkt_recv_count = 0;
udp_srv_stat srv_state;
udp_cli_stat cli_state;

/*calculate dowload rate */
//int last_offset;
//struct timeval start_t, end_t;
/*calculate dowload rate */

static void signal_alarm_handler(int signo)
{
	siglongjmp(jmpbuf, 1);
}

static void start_timer(uint32_t interval)
{
	struct itimerval timer;

	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = 0;
	timer.it_value.tv_sec = interval / 1000;
	timer.it_value.tv_usec = (interval % 1000)*1000;
	#ifdef DEBUG
	printf("interval %d settimer sec %d usec %d\n"
	 		, interval, interval / 1000, (interval % 1000)*1000);
	#endif
	setitimer(ITIMER_REAL, &timer, 0);
}

static void stop_timer(void)
{
	struct itimerval timer;

    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, 0);
}
/*
extract client port number and client window size 
data formate in the payload: window_size;port_number
@param pkt_in = received E_Packet pkt from client
@param srv_state = structure used to store server state
@cliaddr = client address information
*/
bool parse_client_pkt(E_Packet pkt_in, udp_srv_stat* srv_state, struct sockaddr* cliaddr)
{
 	uint32_t payload_length = E_Packet_getPayloadLength(&pkt_in);

 	char payload_buf[payload_length];
 	memcpy(payload_buf, pkt_in.payload, payload_length);
 	payload_buf[payload_length] = '\0';

 	char *token;
 	token = strtok(payload_buf, ";");
 	int client_port = atoi(token);

 	if(client_port == 0){
 		printf("parse_client_pkt invalid client_window_size\n");
 		return false;
 	} else {
 		if(isIPv4)
 			((struct sockaddr_in*)cliaddr)->sin_port = htons(client_port);
 		else
 			((struct sockaddr_in6*)cliaddr)->sin6_port = htons(client_port);
 	}

 	token = strtok(NULL, ";");
 	int client_window_size = atoi(token);

 	if(client_window_size == 0){
 		printf("parse_client_pkt invalid client port\n");
 		return false;
 	} else {
 		srv_state->client_window_size = client_window_size;
 	}

 	return true;
}

bool parse_server_pkt(E_Packet* pkt_in, struct sockaddr* serverad, int* file_size)
{
	uint32_t payload_length = E_Packet_getPayloadLength(pkt_in);

	char payload_buf[payload_length];
	memcpy(payload_buf, pkt_in->payload, payload_length);
	payload_buf[payload_length] = '\0';

	char *token;
	token = strtok(payload_buf, ";");
	int server_port = atoi(token);

	if(server_port == 0){
		printf("parse_server_pkt invalid server_port\n");
 		return false;
	} else {
		if(isIPv4)
			((struct sockaddr_in*)serverad)->sin_port = htons(server_port);
		else
			((struct sockaddr_in6*)serverad)->sin6_port = htons(server_port);
	}

	token = strtok(NULL, ";");
	int size = atoi(token);

	if(size == 0){
		printf("parse_server_pkt invalid file size\n");
		return false;
	} else {
		*file_size = size;
	}

	return true;
}
/*
create a udp socket to communicate with the client
return a udp socket
@param connfd = tcp socket used communicate with client
 */
int create_udp_socket(int connfd) {
	struct sockaddr_in localad;
	socklen_t size = sizeof(localad);

	int client_socket;

	if (getsockname(connfd, (struct sockaddr *) &localad, &size) < 0) {
        perror("create_client_socket getsockname");
        return -1;
    }

    if ((client_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("create_client_socket socket");
        return -1;
    }

    localad.sin_port = htons(0);

    if (bind(client_socket, (struct sockaddr *) &localad,
            sizeof(localad)) < 0) {
            perror("create_client_socket bind");
            return -1;
        }

    return client_socket;

}

int create_udp_socket_6(int connfd)
{
	struct sockaddr_in6 localad;
	socklen_t size = sizeof(localad);

	int client_socket;

	if (getsockname(connfd, (struct sockaddr *) &localad, &size) < 0) {
        perror("create_client_socket_6 getsockname");
        return -1;
    }

    if ((client_socket = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        perror("create_client_socket _6socket");
        return -1;
    }

    localad.sin6_port = htons(0);

    if (bind(client_socket, (struct sockaddr *) &localad,
            sizeof(localad)) < 0) {
            perror("create_client_socket_6 bind");
            return -1;
        }

    return client_socket;

}


int udp_send_msg (int clientfd, udp_msg* msg )
{
	int bytes_sent;
	char send_buf[UDP_MSG_TOTAL_SIZE];

	if(!udp_msg_serialize(msg, send_buf)){
		printf("udp_send_data_packet:serialize failed\n");
		return -1;
	}

	bytes_sent = sendto(clientfd, send_buf, UDP_MSG_TOTAL_SIZE
						,0, NULL ,0);

	if(bytes_sent < 0){
		perror("udp_send_data_packet: sendto failed :");
	}
	#ifdef DEBUG
	printf("udp_send_msg: seq %d\n", udp_msg_getSeq(msg));
	#endif
	pkt_sent_count++;
	//udp_msg_print(msg);

	return bytes_sent;

}

int udp_receive_msg(int clientfd, udp_msg* msg)
{
	int bytes_received;
	char receive_buf[UDP_MSG_TOTAL_SIZE];

	bytes_received = recvfrom(clientfd, receive_buf, UDP_MSG_TOTAL_SIZE, 
							   0, NULL, 0);
	if(bytes_received < 0){
		perror("udp_receive_msg: recvfrom failed ");
		printf("clientfd:%d\n", clientfd);
		return bytes_received;
	}

	udp_msg_deserialize(msg, receive_buf);
	#ifdef DEBUG
	printf("udp_receive_msg: seq %d\n", udp_msg_getSeq(msg));
	#endif
	pkt_recv_count++;
	//udp_msg_print(msg);

	return bytes_received;
}

void resend_first_unacked_msg(int clientfd)
{
	udp_msg* ptr;

	assert(srv_state.window_slots != NULL);

	ptr = &(srv_state.window_slots->msg);
	udp_send_msg(clientfd, ptr);
}

int add_msg_to_window(udp_msg* msg)
{
	/*if(udp_msg_getSeq(msg) == 2)
		printf("breakpoint");*/

	node* ptr = NULL;

	ptr = (node*) malloc(sizeof(node));
	memcpy(&(ptr->msg), msg, sizeof(udp_msg));
	ptr->next = NULL;

	if(srv_state.window_end != NULL) {
		srv_state.window_end->next = ptr;
		srv_state.window_end = ptr;
	} else {
		srv_state.window_slots = ptr;
		srv_state.window_end = ptr;
	}
	#ifdef DEBUG
	printf("add seq %d to window\n", udp_msg_getSeq(msg));
	#endif
	srv_state.window_free_slot--;

	return 0;
}

int num_of_msg_to_send(void)
{
	if(srv_state.client_window_size > srv_state.window_free_slot)
		return srv_state.window_free_slot;
	else
		return srv_state.client_window_size;
}

static void print_window (void)
{
    node* n = srv_state.window_slots;

    if(srv_state.window_slots == NULL){
    	printf("print_window:window is empty\n");
    	return;
    }
    	
    printf("start %d end %d size %d\n", 
           srv_state.window_slots->msg.header.seq, 
           srv_state.window_end->msg.header.seq,
            srv_state.window_size);

    for (; n != NULL; n = n->next) {
        printf("seq %d\n", n->msg.header.seq);
    }
    printf("\n");
}


static void print_client_window (void)
{
    int n;

    printf("start %d end %d window_size %d free_slots %d\n", 
           cli_state.window_start, cli_state.window_end, cli_state.window_size,
           cli_state.window_free_slot);

    for (n = 0; n < cli_state.window_size; n++) {
        printf("seq %d valid %d %d\n", cli_state.window_slots[n].header.seq, cli_state.window_valid_slot[n], n);
    }
    printf("\n");
}


void udp_handle_received_ack(uint32_t received_ack, int* remain_acks)
{
	int number_received_acks = received_ack - srv_state.expected_ack + 1;

	int n;
	node* ptr;
	uint32_t start_seq, last_seq;
	//end = srv_state.window_end->msg.header.seq;
	//start = srv_state.window_start;
	

	/*if(end == 0){
		end = srv_state.window_size - 1;
	} else {
		end--;
	}*/

	start_seq = srv_state.window_slots->msg.header.seq;
	last_seq = srv_state.window_end->msg.header.seq;
	
	/* Recieved a single ack */
	if( number_received_acks == 1){
		#ifdef DEBUG
		printf("a single ack received.\n");
		#endif
		srv_state.window_free_slot++;
		srv_state.num_acks++;
		//srv_state.window_start = (start + 1) % srv_state.window_size;
		ptr = srv_state.window_slots;
		srv_state.window_slots = srv_state.window_slots->next;
		free(ptr);
		*remain_acks = *remain_acks - 1;
		srv_state.expected_ack += 1;
		if(srv_state.window_slots == NULL)
		srv_state.window_end = NULL;
		return;
	}

	/* Several msgs in the congeston window are acked  */
	if((start_seq + number_received_acks) <= (last_seq + 1)) {
		#ifdef DEBUG
		printf("cummulative ack received\n");
		#endif
		for(n = 0; n < number_received_acks; n++) {
			srv_state.window_free_slot++;
			srv_state.num_acks++;
			ptr = srv_state.window_slots;
			srv_state.window_slots = srv_state.window_slots->next;
			free(ptr);
			*remain_acks = *remain_acks - 1;
			srv_state.expected_ack += 1;
		}
		if(srv_state.window_slots == NULL)
		srv_state.window_end = NULL;
		return;
	}

	/* Received ack larger than the msgs in the window */
	if(received_ack >= (last_seq + 1)) {
		#ifdef DEBUG
		printf("cumulative acke received: larger than the msgs in the window\n");
		#endif
		while(1) {
			if( srv_state.window_slots == NULL ) {
				break;
			}
			srv_state.window_free_slot++;
			srv_state.num_acks++;
			*remain_acks = *remain_acks - 1;
			srv_state.expected_ack += 1;
			ptr = srv_state.window_slots;
			srv_state.window_slots = srv_state.window_slots->next;
			free(ptr);
		}
		srv_state.window_end = NULL;
		return;
	}

}

void updata_window_size (uint32_t number_received_acks)
{
	int origin = srv_state.window_size;

	if(srv_state.state == CONGESTION_SLOW_START) {
		if(srv_state.window_size < srv_state.max_windows_size){

			srv_state.window_size += number_received_acks;

			if(srv_state.window_size > srv_state.max_windows_size){
				srv_state.window_size = srv_state.max_windows_size;
		
			}
		}
	}else {
		if(srv_state.num_acks >= srv_state.window_size) {
			if(srv_state.window_size < srv_state.max_windows_size){
				srv_state.window_size += number_received_acks;
				if(srv_state.window_size > srv_state.max_windows_size){
				srv_state.window_size = srv_state.max_windows_size;
				}
			}
			srv_state.num_acks = 0;
		}
	}

	srv_state.window_free_slot += srv_state.window_size - origin;

	if(srv_state.state == CONGESTION_SLOW_START &&
		srv_state.window_size > srv_state.slow_start_threshold){
		#ifdef DEBUG
		printf("switch to congestion avoidance mode\n");
		#endif
		srv_state.state = CONGESTION_AVOIDANCE;
	}
}
/*
shrink the window size and update srv_state parameter after packet lost.
 */
static void update_window_after_timeout(int new_window_size, int new_ss_thresh,
										int new_state, int* offset,
										int* bytes_remaining,
										int* current_sequence_number, int* remain_acks)
{
	#ifdef DEBUG
	printf("\nbefore update_window_after_timeout:\n");
	printf("remain_acks:%d current_seq:%d free_slots:%d bytes_remaining:%d offset:%d\n", 
		*remain_acks, *current_sequence_number, srv_state.window_free_slot,
		*bytes_remaining, *offset);
	print_window();
	#endif

	assert(srv_state.window_slots != NULL);

	int n = 0, old_window_size;
	node* ptr = srv_state.window_slots;
	node* ptr_b = NULL;
	*remain_acks = 0;
	*current_sequence_number = srv_state.window_slots->msg.header.seq;
	/* 
	shrink window, update remain_acks, bytes_remaining, current_sequence_number
	offset.
	*/
	for(n = 0; ptr != NULL; ptr = ptr->next){
		if(n < new_window_size){
			
			if(n == new_window_size - 1){
				srv_state.window_end = ptr;
			}
			n++;
			(*remain_acks)++;
			(*current_sequence_number)++;
			continue;
		}
		if(ptr_b != NULL)
			free(ptr_b);

		ptr_b = ptr;
		*bytes_remaining += ptr_b->msg.header.payload_length;
		*offset -= ptr_b->msg.header.payload_length;


	}
	srv_state.window_end->next = NULL;
	if(ptr_b != NULL)
		free(ptr_b);

	/*update window parameters */
	if(n == new_window_size){
		srv_state.window_free_slot = 0;
	} else {
		srv_state.window_free_slot = new_window_size - (n + 1);
	}
	old_window_size = srv_state.window_size;
	srv_state.slow_start_threshold = new_ss_thresh;
	srv_state.window_size = new_window_size;
	srv_state.num_acks = 0;
	srv_state.num_dup_acks = 0;
	srv_state.state = new_state;

	if (new_state == WINDOW_STATE_SLOW_START) {
		#ifdef DEBUG
        printf("ENTERED SLOW START PHASE\n");
        #endif
    } else {
    	#ifdef DEBUG
        printf("ENTERED CONGESTION AVOIDANCE PHASE\n");
        #endif
    }
    #ifdef DEBUG
    printf("shrinking congestion window from %d to %d. new ss_thresh: %d\n", 
           old_window_size, srv_state.window_size, srv_state.slow_start_threshold);
	#endif

	#ifdef DEBUG
	printf("\nafter update_window_after_timeout:\n");
	printf("remain_acks:%d current_seq:%d free_slots:%d bytes_remaining:%d offset:%d\n", 
		*remain_acks, *current_sequence_number, srv_state.window_free_slot,
		*bytes_remaining, *offset);
	print_window();
	#endif

}
/*
update window before update window size
 */
bool update_window_valid_ack(void)
{
	/*int n, source_index, dest_index;
	udp_msg** new_windows;

	new_windows = (udp_msg**) malloc(srv_state.max_windows_size *
							sizeof(udp_msg*));
	if(!new_windows){
		printf("update_window_valid_ack: failed to malloc memory\n");
		return false;
	}

	memset(new_windows, 0, srv_state.max_windows_size * sizeof(udp_msg*));

	for(n = 0; n < srv_state.max_windows_size; n++){
		new_windows[n] = (udp_msg*) malloc(sizeof(udp_msg));
		if(!new_windows[n]){
			printf("update_window_valid_ack: failed to malloc data memory\n");
			return false;
		}
		memset(new_windows[n], 0, sizeof(udp_msg));
	}

	source_index = srv_state.window_start;
	dest_index = 0;
//	printf("line 373\n");
	while(source_index != srv_state.window_end){
		memcpy(new_windows[dest_index], srv_state.window_slots[source_index],
				sizeof(udp_msg));
		source_index = (source_index + 1) % srv_state.window_size;
		dest_index = (dest_index + 1) % srv_state.window_size;
	}
//	printf("line 380\n");
	for(n = 0; n < srv_state.max_windows_size; n++){
		if(srv_state.window_slots[n]){
			free(srv_state.window_slots[n]);
		}
	}
//	printf("line 386\n");
	free(srv_state.window_slots);
	srv_state.window_slots = new_windows;
//	printf("line 389\n");
	srv_state.window_start = 0;
	srv_state.window_end = dest_index;
*/
	return true;
}

/*
send file to client by udp 
@param srv_state = server state structure
@param clientfd = connection to client
@param file_data_buf = buffer storing file data
@param file_size = file size in bytes
 */
bool udp_send_file(int clientfd, char* file_data_buf, int file_size)
{
	 /* Register for SIGALRM to handle timeouts */
    signal(SIGALRM, signal_alarm_handler);

    int current_seq = 0, return_value;
    int bytes_remaining = file_size;
    udp_msg msg_send, msg_recv;
    bool isResend, isTimeout;
    uint32_t num_msgs_to_send, num_slots_remaining;
    int n, payload_length;
    int offset = 0;
    int remain_acks = 0, slow_start_threshold, number_received_acks;
    #ifdef CLIENT
    pthread_t tid;
    int* param[2];
	param[0] = &offset;
	param[1] = &file_size;
	#endif
	pkt_sent_count = 0;

    if (rttinit == 0) {
        rtt_init(&rttinfo);
        rttinit = 1;
        rtt_d_flag = 1;
    }

    /* calculate dowload rate */
	#ifdef CLIENT
	if (pthread_create(&tid, NULL, &download_speed, &param) != 0) {
            perror("download seepd pthread_create");
            return false;
        }
    #endif
	/* calculate dowload rate */


    while(bytes_remaining || remain_acks) {
    	isTimeout = false;
    	isResend = false;

    	//find out how many packets can be sent
    	num_msgs_to_send = num_of_msg_to_send();

    	num_slots_remaining = (int)ceil( (double)bytes_remaining / UDP_MSG_PAYLOAD_SIZE );
    	num_msgs_to_send = num_msgs_to_send > num_slots_remaining ? num_slots_remaining : num_msgs_to_send;
    	#ifdef DEBUG
    	printf("num_msgs_to_send:%d window_free_slot %d num_slots_remaining %d\n",
    		num_msgs_to_send, srv_state.window_free_slot, num_slots_remaining);
    	#endif

    	rtt_newpack(&rttinfo);

    	//start sending packets
    	for(n = 0; n < num_msgs_to_send; n++) {
    		udp_msg_init(&msg_send);
    		udp_msg_setType(&msg_send, MSG_TYPE_DATA);
    		udp_msg_setTs(&msg_send, rtt_ts(&rttinfo));
    		udp_msg_setSeq(&msg_send, current_seq);
    		current_seq++;
    		udp_msg_set_windowSize(&msg_send, 0);

    		payload_length = (bytes_remaining >= UDP_MSG_PAYLOAD_SIZE) ? UDP_MSG_PAYLOAD_SIZE :
    							bytes_remaining;
    		memcpy(msg_send.payload, file_data_buf + offset, payload_length);
    		offset += payload_length;
    		udp_msg_set_PayLoadLength(&msg_send, payload_length);
    		bytes_remaining -= payload_length;
    		remain_acks++;
    
    		if(add_msg_to_window(&msg_send) != 0) {
    			printf("add_msg_to_window:error\n");
    		}

    		if(udp_send_msg(clientfd, &msg_send) < 0){
    			printf("udp_send_file: udp_send_msg error.\n");
    			#ifdef CLIENT
    			pthread_cancel(tid);
    			#endif
    			printf("\n");
    			return false;
    		}

    	}

		send_again:

		if(isTimeout) {

			resend_first_unacked_msg(clientfd);

			if(srv_state.window_size > 1) {
				slow_start_threshold = srv_state.window_size / 2;
				update_window_after_timeout(slow_start_threshold,
											slow_start_threshold,
											WINDOW_STATE_SLOW_START,
											&offset, &bytes_remaining,
											&current_seq, &remain_acks);
			}
			isResend = true;

			isTimeout = false;
		}

		start_timer(rtt_start(&rttinfo));

		if (sigsetjmp(jmpbuf, 1) != 0) {
			if (rtt_timeout(&rttinfo) < 0 ) {
				printf("udp_send_file: no ack from client. give up.\n");
				rttinit = 0;
				return false;
			}
			#ifdef DEBUG
			printf("udp_send_file: timed out. resending\n");
			#endif
			isTimeout = true;
			goto send_again;
		}

		udp_msg_init(&msg_recv);

		return_value = udp_receive_msg(clientfd, &msg_recv);
		if(return_value < 0){
			printf("udp_send_file: udp_receive_msg failed.\n");
			#ifdef CLIENT
			pthread_cancel(tid);
			#endif
			printf("\n");
			return false;
		}
		// check received ack number
		if(udp_msg_getSeq(&msg_recv) < srv_state.expected_ack) {

			srv_state.num_dup_acks++;
			if (srv_state.num_dup_acks == 3) {

				stop_timer();

				srv_state.num_dup_acks = 0;

				if (srv_state.last_dup_ack != udp_msg_getSeq(&msg_recv)){
					#ifdef DEBUG
					printf("udp_send_file: received duplicate ack %d (expected %d)"
							" client window %d. resending\n",udp_msg_getSeq(&msg_recv),
							srv_state.expected_ack, udp_msg_get_windowSize(&msg_recv));
					#endif
					// fast retransmit
					resend_first_unacked_msg(clientfd);
					isResend = true;
					srv_state.num_dup_acks = 0;
					srv_state.last_dup_ack = udp_msg_getSeq(&msg_recv);

					// reduce window size to threshold.
					if (srv_state.window_size > 1) {
						slow_start_threshold = srv_state.window_size / 2;
						update_window_after_timeout(slow_start_threshold,
													slow_start_threshold,
													WINDOW_STATE_AVOIDANCE,
													&offset, &bytes_remaining,
													&current_seq, &remain_acks);

					}
					isResend = true;
				}
			}

			goto send_again;
		}

		stop_timer();

		#ifdef DEBUG
		printf("udp_send_file: received valid ack %d expected_ack %d "
				"client window %d remain_acks %d\n", udp_msg_getSeq(&msg_recv),
				srv_state.expected_ack, udp_msg_get_windowSize(&msg_recv), remain_acks);
		#endif
		number_received_acks = udp_msg_getSeq(&msg_recv) - srv_state.expected_ack + 1;

		#ifdef DEBUG
		printf("\nbefore udp_handle_received_ack:\n");
		print_window();
		#endif
		udp_handle_received_ack(udp_msg_getSeq(&msg_recv), &remain_acks);
		#ifdef DEBUG
		printf("\nafter udp_handle_received_ack:\n");
		print_window();
		#endif
		srv_state.client_window_size = udp_msg_get_windowSize(&msg_recv);

		/*#ifdef DEBUG
		printf("*************************************\n");
		printf("\nbefore update_window_valid_ack:\n");
		print_window();
		print_srv_state(&srv_state);
		#endif*/

		//update_window_valid_ack();
		//printf("line 535\n");
		/*#ifdef DEBUG
		printf("*****\n");
		printf("\nafter update_window_valid_ack:\n");
		print_window();
		printf("*number_received_acks:%d\n", number_received_acks);
		#endif*/

		updata_window_size(number_received_acks);

		// #ifdef DEBUG
		// printf("\nafter updata_window_size:\n");
		// print_window();
		// print_srv_state(&srv_state);
		// printf("*************************************\n");
		// #endif

		if (srv_state.client_window_size == 0) {
			printf("client window_size %d\n", 0);
			srv_state.client_window_size = 1;
			sleep(1);
			//goto send_again;
			
		}

		if(isResend == false) {
			
			rtt_stop(&rttinfo, rtt_ts(&rttinfo) - udp_msg_getTs(&msg_recv));
		}

    }
   
   	#ifdef CLIENT
	pthread_join(tid, NULL);
	#endif

	return true;
	
}

int udp_close(int clientfd)
{
	//int bytes_received;
	udp_msg msg_send, msg_recv;

	udp_msg_init(&msg_send);
	udp_msg_setType(&msg_send, MSG_TYPE_DATA_FIN);

send_again:
	
	udp_send_msg(clientfd, &msg_send);

	start_timer(5 * 1000);

	if (sigsetjmp(jmpbuf, 1) != 0) {
        printf("udp_close: failed to receive ack for fin. retransmitting.\n");
        goto send_again;
    }

    udp_receive_msg(clientfd, &msg_recv);

    if(udp_msg_getType(&msg_recv) == MSG_TYPE_DATA_FIN_ACK){

    	stop_timer();

	    printf("udp_close: received ack for FIN message\n");

	    udp_msg_init(&msg_send);
		udp_msg_setType(&msg_send, MSG_TYPE_DATA_FIN_ACK_ACK);
		udp_send_msg(clientfd, &msg_send);

	    close(clientfd);

	    return 0;

    } else {
    	goto send_again;
    }

    

}

int add_data_to_window(udp_msg* msg_recv)
{
	udp_msg* ptr = NULL;
	int start = 0, end = 0;
	int ack_to_send = -1;
	int free_slot = 0;
	int received_seq = udp_msg_getSeq(msg_recv);

	if(cli_state.window_free_slot == 0) {
		return cli_state.expected_seq;
	}

	if(received_seq == cli_state.expected_seq) {

		cli_state.window_valid_slot[cli_state.window_end] = true;

		ptr = &(cli_state.window_slots[cli_state.window_end]);
		memcpy(ptr, msg_recv, sizeof(udp_msg));

		cli_state.window_end = (cli_state.window_end + 1) % cli_state.window_size;
		end = cli_state.window_end;
		start = cli_state.window_start;
		cli_state.window_free_slot--;

		ack_to_send = received_seq + 1;

		for(; end != start; ) {
			if(cli_state.window_valid_slot[end] == true) {
				ptr = cli_state.window_slots + end;
				ack_to_send = udp_msg_getSeq(ptr) + 1;
				end = (end + 1) % cli_state.window_size;
			} else {
				break;
			}
		}

		cli_state.window_end = end;
		cli_state.expected_seq = ack_to_send;

	} else {										//cli_state.window_free_slot??

		if(received_seq - cli_state.expected_seq < cli_state.window_size) {

			ack_to_send = cli_state.expected_seq;

			free_slot = (cli_state.window_end +
						(received_seq - cli_state.expected_seq)) %
						cli_state.window_size;
			// duplicate seq received
			if(cli_state.window_valid_slot[free_slot] == true)
				return ack_to_send;

			cli_state.window_valid_slot[free_slot] = true;
			ptr = cli_state.window_slots+free_slot;
			memcpy(ptr, msg_recv, sizeof(udp_msg));
			cli_state.window_free_slot--;	
		} else {
			ack_to_send = cli_state.expected_seq;
		}
	}

	return ack_to_send;

}

int udp_process_msg(int fd, udp_msg* msg_recv)
{
	int ack_to_send;
	uint32_t received_seq = udp_msg_getSeq(msg_recv);

	if((received_seq == cli_state.expected_seq) ||
		(received_seq > cli_state.expected_seq)) {

		if(cli_state.window_free_slot == 0) {
			return 0;
		}

		ack_to_send = add_data_to_window(msg_recv);

	} else {

		ack_to_send = cli_state.expected_seq;
	}

	//printf("received seq: %d\n", received_seq);
	udp_send_ack(fd, ack_to_send, cli_state.window_free_slot);

	return 0;


}

int udp_client_read_window(char* file_buf ,int offset){
	int n = 0, index = 0, num_packets = 0;
	int bytes_read = 0;
	udp_msg* ptr;

	if(file_buf == NULL){
		return 0;
	}

	if(cli_state.window_valid_slot[cli_state.window_start] == 0){
		return 0;
	}

	index = cli_state.window_start;
	if(cli_state.window_end > cli_state.window_start) {
		num_packets = cli_state.window_end - cli_state.window_start;
	} else {
		num_packets = cli_state.window_size - (cli_state.window_start - cli_state.window_end);

	}
	for(n = 0; n < num_packets; n++) {
		ptr = cli_state.window_slots + index;
		bytes_read += (ptr->header.payload_length);
		memcpy(file_buf + offset, ptr->payload, ptr->header.payload_length);
		offset += bytes_read;
		cli_state.window_free_slot++;
		cli_state.window_valid_slot[index] = false;
		index = (index + 1) % cli_state.window_size;

	}

	cli_state.window_start = index;

	return bytes_read;
}

void udp_send_ack(int fd, uint32_t seq , uint32_t window_size)
{
	udp_msg msg_send;
	#ifdef DEBUG
	printf("udp_send_ack: sending ack %d window_size %d \n",
			seq, window_size);
	#endif
	udp_msg_init(&msg_send);
	udp_msg_setSeq(&msg_send, seq);
	udp_msg_set_windowSize(&msg_send, window_size);
	udp_msg_setType(&msg_send, MSG_TYPE_ACKNOWLEDGEMENT);
	udp_msg_set_PayLoadLength(&msg_send, 0);

	if(udp_send_msg(fd, &msg_send) < 0) {
		printf("udp_send_ack: error.\n");
	}
}

void* download_speed(void* parm)
{
	//pthread_detach(pthread_self());

	double secs_used;
	double rate;
	double percentage;
	int bytes_received;
	int** param = (int**)parm;
	int* offset = param[0];
	int* file_size = param[1];
	int last_offset = *offset;
	struct timeval start_t, end_t;
	gettimeofday(&start_t, NULL);
	gettimeofday(&end_t, NULL);

	/* calculate total time */
	struct timeval start, end;
	gettimeofday(&start, NULL);
	/* 						*/
	for(;;){
		sleep(1);
		bytes_received = *offset - last_offset;
		//in case some slots are returned back
		if(bytes_received < 0)
			bytes_received = 0;

		gettimeofday(&end_t, NULL);
		secs_used = (end_t.tv_sec - start_t.tv_sec);
		secs_used += (end_t.tv_usec - start_t.tv_usec) / 1000000.0;

		rate = bytes_received / secs_used;
		rate = rate / 1024;
		percentage = (double)*offset / *file_size * 100;
		printf("\r                                               ");
		printf("\r%d/%d (%.1f%%) speed: %.1f KB/s ", *offset, *file_size, percentage, rate);
		fflush(stdout);

		if(*offset >= *file_size){
			printf("\n");
			break;
		}

		gettimeofday(&start_t, NULL);
		last_offset = *offset;
	}

	gettimeofday(&end, NULL);
	secs_used = (end.tv_sec - start.tv_sec);
    secs_used += (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("\nreceived pkts: %d, received bytes: %d, time elapsed: %.2f sec,\naverage transfer rate: %.2f KB/s\n",pkt_recv_count, *offset, secs_used, ((*file_size/1024)/secs_used));

	pthread_exit(0);

}

char* udp_recv_file(int fd, int file_size) 
{
	int bytes_received;
	udp_msg msg_recv, msg_send;
	//int bytes_remaining = file_size;
	char* file_buf = NULL;
	bool isFIN = false;
	int offset = 0;
	#ifdef CLIENT
	int* param[2];
	param[0] = &offset;
	param[1] = &file_size;
	pthread_t tid;
	#endif
	pkt_recv_count = 0;
	/*calculate dowload rate */
	#ifdef CLIENT
	if (pthread_create(&tid, NULL, &download_speed, &param) != 0) {
            perror("download seepd pthread_create");
            return NULL;
        }
    #endif
	/*calculate dowload rate */

	signal(SIGALRM, signal_alarm_handler);

	file_buf = (char*)malloc(file_size);

	if(file_buf == NULL){
		printf("udp_recv_file: faile to malloc memeory for file_buf");
		#ifdef CLIENT
		pthread_cancel(tid);
		#endif
		printf("\n");
		return NULL;
	}

	//random drop
	#ifdef DEBUGDROP
		int r;
		time_t t;
		srand((unsigned) time(&t));
		//
	#endif

	while(true) {

		udp_msg_init(&msg_recv);

		if(isFIN) {
			// time to wait after FIN message received
			start_timer(10 * 1000);

		} else {
			// time to wait for response 
			start_timer(8 * 1000);
		}
		
		if(sigsetjmp(jmpbuf, 1) != 0) {

			if(isFIN) {
				printf("udp_recv_file: received fin.\n");
			} else {
				printf("udp_recv_file: cannot get response from the server.\n");
				#ifdef CLIENT
				pthread_cancel(tid);
				#endif
				printf("\n");
				free(file_buf);
				return NULL;
			}

			break;
		}


//read_again:
		//
		
		//
		bytes_received = udp_receive_msg(fd, &msg_recv);
		if(bytes_received <= 0) {

			printf("udp_recv_file: udp_receive_msg error.\n");

			break;
		}

		stop_timer();

		//random drop
		#ifdef DEBUGDROP
		r = rand();
		srand((unsigned) time(&t));
	//	printf("r: %d\n",r );
		if((r % 10) >= 7 ){
			printf("random drop\n");
			continue;
		}
		#endif
		

		if(udp_msg_getType(&msg_recv) == MSG_TYPE_DATA_FIN){
			
			isFIN = true;
			printf("FIN msg received.\n");
			//udp_send_ack(fd, 0, 0);
			udp_msg_init(&msg_send);
			udp_msg_setType(&msg_send, MSG_TYPE_DATA_FIN_ACK);
			udp_msg_set_PayLoadLength(&msg_send, 0);

			if(udp_send_msg(fd, &msg_send) < 0) {
				printf("udp_send_ack: sending MSG_TYPE_DATA_FIN_ACK error.\n");
			}

		} else if(udp_msg_getType(&msg_recv) == MSG_TYPE_DATA) {

			udp_process_msg(fd, &msg_recv);

		} else if(udp_msg_getType(&msg_recv) == MSG_TYPE_DATA_FIN_ACK_ACK) {

			printf("udp_recv_file:msg_ack_ack received.\n");
			break;

		} 
		else {

			printf("udp_recv_file: invalid msg received.\n");
			break;
		}

		#ifdef DEBUG
		print_client_window();
		printf("\nread from window\n");
		#endif
		
		offset += udp_client_read_window(file_buf, offset);

		#ifdef DEBUG
		print_client_window();
		#endif
	}

	//printf("line 802.\n");
	#ifdef CLIENT
	pthread_join(tid, NULL);
	#endif

	return file_buf;
	//printf("line 804.\n");
	//return NULL;
}
/*
send udp port number to client and proceed to udp file transfer
@param connfd=tcp socket 
@param cliaddr=client address information
@param file_data_buf=file data buffer
@param file_size=file data size in bytes
 */
bool handle_udp_download_request(int connfd, char* file_data_buf, int file_size) {
	int client_socket;
	struct sockaddr_storage localad, cliaddr;
	struct sockaddr_storage* ptr_localad = &localad;
	struct sockaddr_storage* ptr_clientad = &cliaddr;
	char send_buf[100];
	int return_value;
	E_Packet pkt_out;
	E_Packet pkt_in;

	if(!init_srv_state(&srv_state)){
		printf("failed to initialize server state structure.\n");
		return false;
	}
	if(isIPv4){
		client_socket = create_udp_socket(connfd);
		if(client_socket == -1){
			printf("failed to create udp socket\n");
			return false;
		}
	}
	else {
		client_socket = create_udp_socket_6(connfd);
		if(client_socket == -1){
			printf("failed to create udp socket\n");
			return false;
		}
	}
	
	/* Send server port num and file size to the client */
	socklen_t size = sizeof(localad);
	if (getsockname(client_socket, (struct sockaddr *) &localad, &size) < 0) {
        perror("handle_udp_download_request getsockname");
        return false;
    }
    if(isIPv4){
    	sprintf(send_buf, "%d;%d", ntohs(((struct sockaddr_in*)ptr_localad)->sin_port), file_size);
    }
    else {
   		sprintf(send_buf, "%d;%d", ntohs(((struct sockaddr_in6*)ptr_localad)->sin6_port), file_size);

    }

    memset(&pkt_out, 0, sizeof(pkt_out));
    E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_ACCEPT);
    E_Packet_setPayloadLength(&pkt_out, strlen(send_buf));
    memcpy(pkt_out.payload, send_buf, strlen(send_buf));

    /* send server udp port number and file size to client */
    if(!tcp_send_pkt(connfd, &pkt_out)) {
    	printf("handle_udp_download_request: failed to send socket port to client\n");
    	return false;
    }

    /* Receive port and window size from client*/
    if(!tcp_recv_pkt(connfd, &pkt_in))
		{
    		printf("handle_udp_download_request: failed to receive socket port from client\n");
			return false;
		}
	/* Extract port number and window size from pkt_in */
	size = sizeof(cliaddr);
	if (getpeername(connfd, (struct sockaddr *) &cliaddr, &size) < 0) {
        perror("handle_udp_download_request getpeername failed.\n");
        return false;
	}

	if(!parse_client_pkt(pkt_in, &srv_state, (struct sockaddr *)&cliaddr)){
		printf("failed to parse pkt\n");
		return false;
	}

	/* Connect to the client with udp*/
	if(isIPv4){
		return_value = connect(client_socket, (struct sockaddr *)&cliaddr,
                  sizeof(struct sockaddr));
	} 
	else {
		return_value = connect(client_socket, (struct sockaddr *)&cliaddr,
                  sizeof(struct sockaddr_in6));
	}
	

	if (return_value != 0) {
        perror("handle_udp_download_request() connect:\n");
        return false;
    }

    print_ipaddr_pair((struct sockaddr*)ptr_localad, (struct sockaddr*)ptr_clientad, isIPv4);

    printf("client_socket:%d\n", client_socket);

	if(udp_send_file(client_socket, file_data_buf, file_size) == false){
		printf("handle_udp_download_request: failed to send file\n");
		return false;
	} else {
		printf("handle_udp_download_request: file sent, now go to udp close.\n");
	}

	udp_close(client_socket);
	printf("pkts sent:%d\n", pkt_sent_count);
	
	return true;
}

char* udp_download_file(int connfd, const char* file_path, int* file_length)
{
	int server_socket;
	struct sockaddr_storage localad, serverad;
	struct sockaddr_storage* ptr_localad = &localad;
	struct sockaddr_storage* ptr_serverad = &serverad;
	char send_buf[100];
	int file_size;
	char* file_buf;
	int return_value;
	socklen_t size;
	E_Packet pkt_out;
	E_Packet pkt_in;

	/* Send file path to the client */
	memset(&pkt_out, 0, sizeof(pkt_out));
	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DOWNLOAD_UDP);
	E_Packet_setPayloadLength(&pkt_out, strlen(file_path));
	memcpy(pkt_out.payload, file_path, strlen(file_path));

	printf("send request for file %s\n", file_path);

	if(!tcp_send_pkt(connfd, &pkt_out)) {
    	printf("udp_download_file: failed to send file_path to the server.\n");
    	return NULL;
    }

    /* Receive response from the server*/
    if(!tcp_recv_pkt(connfd, &pkt_in))
		{
    		printf("udp_download_file: failed to receive response from the server\n");
			return NULL;
		}

	if(E_Packet_getType(&pkt_in) == PACKET_TYPE_COMMAND_ACCEPT){
		/*extract server port number and flie size from pkt_in */
		size = sizeof(serverad);
		if (getpeername(connfd, (struct sockaddr *) &serverad, &size) < 0) {
	        perror("udp_download_file getpeername failed.\n");
	        return NULL;
   		 }

		if(parse_server_pkt(&pkt_in, (struct sockaddr*)&serverad, &file_size) == false){
			return NULL;
		}
	} else {
		printf("udp_download_file:request failed.\n");
		return NULL;
	}
	/*send local udp port and window size to the server */
	if(init_cli_state(&cli_state) == -1){
		printf("failed to initialize client state structure.\n");
		return NULL;
	}
	if(isIPv4){
		server_socket = create_udp_socket(connfd);
		if(server_socket == -1){
			printf("failed to create udp socket.\n");
			return NULL;
		}

	} else {
		server_socket = create_udp_socket_6(connfd);
		if(server_socket == -1){
			printf("failed to create_udp_socket_6.\n");
			return NULL;
		}

	}
	

	size = sizeof(localad);
	if (getsockname(server_socket, (struct sockaddr *) &localad, &size) < 0) {
        perror("udp_download_file getsockname failed.\n");
        return NULL;
    }
    if(isIPv4){
    	sprintf(send_buf, "%d;%d", ntohs(((struct sockaddr_in*)ptr_localad)->sin_port), cli_state.window_size);
    } else {
    	sprintf(send_buf, "%d;%d", ntohs(((struct sockaddr_in6*)ptr_localad)->sin6_port), cli_state.window_size);

    }	

    memset(&pkt_out, 0, sizeof(pkt_out));
    E_Packet_setType(&pkt_out, PACKET_TYPE_DATA);
    E_Packet_setPayloadLength(&pkt_out, strlen(send_buf));
    memcpy(pkt_out.payload, send_buf, strlen(send_buf));

    if(!tcp_send_pkt(connfd, &pkt_out)) {
    	printf("udp_download_file: failed to send udp port and window size to the server\n");
    	return NULL;
    }

    /* Connect to the server with udp */
    if(isIPv4){
    	return_value = connect(server_socket, (struct sockaddr *)&serverad,
                  sizeof(struct sockaddr));
    } else {
    	return_value = connect(server_socket, (struct sockaddr *)&serverad,
                  sizeof(struct sockaddr_in6));
    }
    

	if (return_value != 0) {
        printf("udp_download_file: failed to connect to the client\n");
        return NULL;
    }

    print_ipaddr_pair((struct sockaddr*)ptr_localad, (struct sockaddr*)ptr_serverad, isIPv4);
    
    printf("server_socket:%d\n", server_socket);


    if((file_buf = udp_recv_file(server_socket, file_size)) == NULL) {
    	printf("udp_download_file: failed to recv file\n");
    	return NULL;
    } else {
    	printf("udp_download_file: file recieved\n");
    }
    
    cli_state_destroy(&cli_state);
    *file_length = file_size;
	return file_buf;

}

