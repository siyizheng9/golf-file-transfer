
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include "common.h"
#include "udp_service.h"

int logfd = -1;
bool isIPv4 = true;
int tcp_pkt_sent_count = 0;
int tcp_pkt_recv_count = 0;

bool tcp_send_pkt(int connfd, E_Packet* a_e_pkt)
{
	char buf[EXTEND_PACKET_SIZE];
	int count, bytes_sent;

	if( !e_pkt_serialize(a_e_pkt, buf) )
	{
		printf("pkt serialize failed\n");
		return false;
	}

	for(count = 0; count < EXTEND_PACKET_SIZE;)
	{
		if((bytes_sent = send(connfd, buf + count, EXTEND_PACKET_SIZE - count, 0)) == -1)
		{
			perror("tcp_send_pkt()");
			return false;
		}

		count += bytes_sent;
		#ifdef DEBUG
		printf("tcp_send_pkt: %d bytes sent, %d bytes remaining\n"
				,count, EXTEND_PACKET_SIZE - count);
		#endif
	}
	//printf("sending finished\n");
	return true;

}

char* read_file(char* file_path, int* p_file_length)
{
	char* buf = NULL;
	FILE* fp;

	if((fp = fopen(file_path, "r")) == NULL)
	{
		perror("fopen:");
		return NULL;
	}
	//get file size
	fseek(fp, 0, SEEK_END);
	*p_file_length = ftell(fp);
	rewind(fp);

	if(((buf = calloc(*p_file_length, sizeof(char)))) == NULL)
	{
		fclose(fp);

		printf("read_file: failed to alloc buffer\n");
	}

	if(fread(buf, sizeof(char), *p_file_length, fp) != *p_file_length)
	{
		perror("fread:");
		fclose(fp);
		free(buf);
		buf = NULL;
		return NULL;
	}
	
	fclose(fp);

	return buf;

}

bool write_file(char* file_path, char* data, int file_length)
{
	FILE* fp;

	if((fp = fopen(file_path, "w")) == NULL)
	{
		perror("fopen:");
		return false;
	}

	if(fwrite(data, sizeof(char), file_length, fp) == -1)
	{
		perror("write_file:");
		fclose(fp);

		return false;
	}
	fclose(fp);
	return true;

}

bool tcp_recv_pkt(int connfd, E_Packet* a_e_pkt)
{
	char buf[EXTEND_PACKET_SIZE];
	int count, bytes_rev;

	for(count = 0; count < EXTEND_PACKET_SIZE;)
	{
		if((bytes_rev = recv(connfd, buf + count, EXTEND_PACKET_SIZE - count, 0)) == -1)
		{
			perror("tcp_recv_pkt()");
			return false;
		} else if( bytes_rev == 0){

			printf("tcp_recv_pkt: %d bytes recv\n", bytes_rev);
			return false;
		}

		count += bytes_rev;
		#ifdef DEBUG
		printf("tcp_recv_pkt: %d bytes recv, %d bytes remaining\n"
				,count , EXTEND_PACKET_SIZE - count);
		#endif
	}
	e_pkt_deserialize(buf, a_e_pkt);

	return true;
}
/* failed creation will return null */
B_Packet* B_Packet_create(uint8_t pkt_type, uint32_t payload_length)
{
	
	B_Packet *p_b_pkt;
	
	p_b_pkt = malloc(sizeof(B_Packet));

	if(p_b_pkt != NULL)
	{
		p_b_pkt->pkt_type = pkt_type;
		
		p_b_pkt->payload_length = payload_length;
	}

	return p_b_pkt;
}

/* failed creation will return null */
E_Packet* E_Packet_create(B_Packet header, char* payload)
{
	E_Packet *p_e_pkt;

	p_e_pkt = malloc(sizeof(E_Packet));

	if(p_e_pkt != NULL)
	{
		p_e_pkt->header = header;

		if(payload != NULL)
			strcpy(p_e_pkt->payload, payload);

	}

	return p_e_pkt;
}

bool b_pkt_serialize(B_Packet a_b_pkt, char* result_buf)
{
	if(result_buf == NULL)
		return false;

	result_buf[0] = a_b_pkt.pkt_type;
	uint32_t* p = (uint32_t*) (result_buf + BASE_PACKET_TYPE_SIZE);
	*p = htonl(a_b_pkt.payload_length);
	//result_buf[BASE_PACKET_SIZE] = '\0';
	//
	//printf("after b_pkt_serialize:\n");


	return true;
	
}

bool b_pkt_deserialize(char* b_pkt_buf, B_Packet* a_b_pkt)
{
	if(b_pkt_buf == NULL)
		return false;

	a_b_pkt->pkt_type = b_pkt_buf[0];
	uint32_t* p = (uint32_t*) (b_pkt_buf + BASE_PACKET_TYPE_SIZE);
	a_b_pkt->payload_length = ntohl(*p);

	return true;

}


bool e_pkt_serialize(E_Packet* a_e_pkt, char* result_buf)
{
	if(a_e_pkt == NULL || result_buf == NULL)
		return false;

	char b_pkt_buf[BASE_PACKET_SIZE];

	if(!b_pkt_serialize(a_e_pkt->header, b_pkt_buf))
		return false;

	memcpy(result_buf, b_pkt_buf, BASE_PACKET_SIZE);
	memcpy(&result_buf[BASE_PACKET_SIZE], a_e_pkt->payload,
			TCP_PAYLOAD_SIZE);

	return true;

}

bool e_pkt_deserialize(char* e_pkt_buf, E_Packet* a_e_pkt)
{
	if(e_pkt_buf == NULL || a_e_pkt == NULL)
		return false;

	if(!b_pkt_deserialize(e_pkt_buf, &(a_e_pkt->header)) )
		return false;

	memcpy(a_e_pkt->payload, e_pkt_buf + BASE_PACKET_SIZE
			, TCP_PAYLOAD_SIZE);

	return true;

}

bool tcp_send_file(int connfd, char* file_buf, int file_length)
{
	E_Packet pkt_out;
	//count sent data size
	int count, remain_size, sent_size;
	#ifdef CLIENT
	int* param[2];
	param[0] = &count;
	param[1] = &file_length;
	pthread_t tid;
	#endif
	/* send file size to the peer */

	memset(&pkt_out, 0, sizeof(pkt_out));

	printf("tcp_send_file: file size %d bytes\n", file_length);

	E_Packet_setType(&pkt_out, PACKET_TYPE_DATA_BEGINNING);
	E_Packet_setPayloadLength(&pkt_out, file_length);

	if(!tcp_send_pkt(connfd, &pkt_out))
		return false;

	/*calculate dowload rate */
	#ifdef CLIENT
	if (pthread_create(&tid, NULL, &download_speed, &param) != 0) {
            perror("download seepd pthread_create");
            //return NULL;
        }
    #endif
	/*calculate dowload rate */

	/* Start sending file*/
	E_Packet_setType(&pkt_out, PACKET_TYPE_DATA);

	for(count = 0; count < file_length; count += TCP_PAYLOAD_SIZE)
	{
		memset(&pkt_out.payload, 0, sizeof(pkt_out.payload));

		remain_size = file_length - count;

		if(remain_size < TCP_PAYLOAD_SIZE)
		{
			E_Packet_setPayloadLength(&pkt_out, remain_size);
			sent_size = remain_size;
		}
		else
		{
			E_Packet_setPayloadLength(&pkt_out, TCP_PAYLOAD_SIZE);
			sent_size = TCP_PAYLOAD_SIZE;

		}

		memcpy(pkt_out.payload, file_buf + count, sent_size);

		if(!tcp_send_pkt(connfd, &pkt_out))
			return false;

	}
	#ifdef CLIENT
	pthread_join(tid, NULL);
	#endif
	
	E_Packet_setType(&pkt_out, PACKET_TYPE_DATA_ENDING);
	E_Packet_setPayloadLength(&pkt_out, 0);
	memset(&pkt_out.payload, 0, sizeof(pkt_out.payload));
	return tcp_send_pkt(connfd, &pkt_out);

}

bool send_upload_request(int connfd, char* file_path){
	E_Packet pkt_out;
	E_Packet pkt_in;

	/* Send file path to the client */
	memset(&pkt_out, 0, sizeof(pkt_out));
	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_UPLOAD);
	E_Packet_setPayloadLength(&pkt_out, strlen(file_path));
	memcpy(pkt_out.payload, file_path, strlen(file_path));

	printf("send upload request for file %s\n", file_path);

	if(!tcp_send_pkt(connfd, &pkt_out)) {
    	printf("send_upload_request: failed to send file_path to the server.\n");
    	return false;
    }

    /* Receive response from the server*/
    if(!tcp_recv_pkt(connfd, &pkt_in))
		{
    		printf("send_upload_request: failed to get response from the server\n");
			return false;
		}

	if(E_Packet_getType(&pkt_in) == PACKET_TYPE_COMMAND_ACCEPT){

		return true;

	} else {

		printf("send_upload_request:request failed.\n");
		return false;
	}

}

char* tcp_recv_file(int connfd, int* file_length)
{
	E_Packet pkt_in;
	char* rev_buf = NULL;
	int count = 0;
	int recv_size;
	#ifdef CLIENT
	pthread_t tid;
	int* param[2];
	param[0] = &count;
	param[1] = file_length;
	#endif

	/* Receive file size from peer*/
	memset(&pkt_in, 0, sizeof(pkt_in));

	if(!tcp_recv_pkt(connfd, &pkt_in))
		return NULL;

	if(E_Packet_getType(&pkt_in) == PACKET_TYPE_DATA_BEGINNING)
	{
		*file_length = E_Packet_getPayloadLength(&pkt_in);

		printf("tcp_recv_pkt: file size %d bytes\n", *file_length);
	}
	else
	{
		return NULL;
	}

	if((rev_buf = calloc(*file_length, sizeof(char))) == NULL)
		{
			*file_length = 0;

			printf("tcp_recv_pkt: calloc() failed");
			return NULL;
		}

	/*calculate dowload rate */
	#ifdef CLIENT
	if (pthread_create(&tid, NULL, &download_speed, &param) != 0) {
            perror("download seepd pthread_create");
            //return NULL;
        }
    #endif

	for(count = 0, recv_size = 0; count < *file_length; count += recv_size)
	{
		if(!tcp_recv_pkt(connfd, &pkt_in))
		{
			free(rev_buf);
			return NULL;
		}

		recv_size = E_Packet_getPayloadLength(&pkt_in);
		
		memcpy(rev_buf + count, pkt_in.payload, recv_size);
		#ifdef DEBUG
		printf("tcp_recv_file:%d bytes received %d bytes remaining\n"
				, count, *file_length - count);
		#endif
	}

	if(!tcp_recv_pkt(connfd, &pkt_in))
		{
			free(rev_buf);
			return NULL;
		}

	#ifdef CLIENT
//	printf("pthread_join start\n");
	pthread_join(tid, NULL);
//	printf("pthread_join end\n");
	#endif

	if(E_Packet_getType(&pkt_in) != PACKET_TYPE_DATA_ENDING)
		return NULL;
	else
		return rev_buf;


}

void server_log(char* record)
{
	printf("server:%s\n", record);

}

void E_Packet_destroy(E_Packet* a_e_pkt)
{
	if(a_e_pkt != NULL)
		free(a_e_pkt);
}

void B_Packet_destroy(B_Packet* a_b_pkt)
{
	if(a_b_pkt != NULL)
		free(a_b_pkt);
}


uint8_t E_Packet_getType(E_Packet* a_e_pkt)
{
	return a_e_pkt->header.pkt_type;
}

void E_Packet_setType(E_Packet* a_e_pkt, uint8_t pkt_type)
{
	a_e_pkt->header.pkt_type = pkt_type;
}

uint32_t E_Packet_getPayloadLength(E_Packet* a_e_pkt)
{
	return (a_e_pkt->header).payload_length;
}

void E_Packet_setPayloadLength(E_Packet* a_e_pkt, uint32_t payload_length)
{
	(a_e_pkt->header).payload_length = payload_length;
}

void E_Packet_clear(E_Packet* a_e_pkt)
{
	memset(a_e_pkt, 0, sizeof(E_Packet) );
}

void E_Packet_print(E_Packet* p_e_pkt)
{
	uint8_t pkt_type = E_Packet_getType(p_e_pkt);
 	uint32_t payload_length = E_Packet_getPayloadLength(p_e_pkt);

 	char payload_buf[payload_length];
 	memcpy(payload_buf, p_e_pkt->payload, payload_length);
 	payload_buf[payload_length] = '\0';

	printf("pkt_type:%d, payload_length:%d\n", pkt_type, payload_length);
 	printf("payload:%s\n",payload_buf);

}

void prepend(char* s, const char* t)
{
    size_t len = strlen(t);
    size_t i;

    memmove(s + len, s, strlen(s) + 1);

    for (i = 0; i < len; ++i)
    {
        s[i] = t[i];
    }
}

/*
read one line from a file
return bytes read in this line
@param fd file descriptor
@param buf buffer to store the line
 */
int readline(int fd, char** buf)
{
	int n;
	int length = 0;
	char line[100];
	char character;

	for(;;) {
		if((n = read(fd, &character, 1)) < 0) {
			perror("readlien() read:");
			return -1;
		} else if (n == 0) {
			break; // end of the file
		} else if (character == '\n')  { // end of the line
			line[length] = '\0';
			length++;
			break;
		} else {
			if (length == 100) {
				return -1;
			}

			line[length] = character;
			length++;
		}
	}
	// malloc memory for buf
	*buf = (char*) malloc(length);
	if(*buf == NULL) {
		perror("readlien() malloc");
		return -1;
	}

	for(n = 0; n < length; n++) {
		(*buf)[n] = line[n];
	}
	assert(n == length);
	return length;
}
/*
get server working directory path and server port from config file
@param fd config file descriptor
@param dir_path place to hold the directory path
@param port place to hold the server port
return false if any error happened
 */
bool get_server_config(int fd, int* max_w, int* ss_t)
{
	char* line;
//	int n, length;
	char* token;
	char* ptr;

	//reposition file offset
	if(lseek(fd, 0, SEEK_SET) == -1) {
		perror("get_server_config() lseek:");
		return false;
	}

	while(readline(fd, &line) > 0) {
		if (line[0] == '#' || line[0] == '\0') {
			free(line);
			continue;
		}

		token = strtok(line, "=");

		if(token == NULL) {
			printf("get_server_config() error invalid argument.");
			free(line);
			return false;
		}

		if((ptr = strchr(token,' ')) != NULL)
			*ptr = '\0';

		printf("token[%s]\n",token);

		if(strcmp(token, "max_windows_size") == 0){
			token = strtok(NULL, "=");
			if(atoi(token) > 0)
				*max_w = atoi(token);
			free(line);
			continue;

		} else if(strcmp(token, "slow_start_threshold") == 0){
			token = strtok(NULL, "=");
			if(atoi(token) > 0)
				*ss_t = atoi(token);
			free(line);
			continue;
		} else {
			printf("get_server_config() error invalid argument.");
			free(line);
			return false;
		}
	}

	if(line != NULL)
		free(line);
	
	return true;
}

bool get_client_config(int fd, int* recv_w)
{
	char* line;
//	int n, length;
	char* token;
	char* ptr;

	//reposition file offset
	if(lseek(fd, 0, SEEK_SET) == -1) {
		perror("get_client_config() lseek:");
		return false;
	}

	while(readline(fd, &line) > 0) {
		if (line[0] == '#' || line[0] == '\0') {
			free(line);
			continue;
		}

		token = strtok(line, "=");

		if(token == NULL) {
			printf("get_client_config() error invalid argument.");
			free(line);
			return false;
		}

		if((ptr = strchr(token,' ')) != NULL)
			*ptr = '\0';

		printf("token[%s]\n",token);

		if(strcmp(token, "receive_windows_size") == 0){
			token = strtok(NULL, "=");
			if(atoi(token) > 0)
				*recv_w = atoi(token);
			free(line);
			continue;
		} else {
			printf("get_client_config() error invalid argument.");
			free(line);
			return false;
		}
	}
	if(line != NULL)
		free(line);
	
	return true;
}

void print_ipaddr_pair(struct sockaddr* src, struct sockaddr* dst, bool isIPv4)
{
	char buff[INET6_ADDRSTRLEN];

	if(isIPv4) {

    	printf("UDP %s : %d", inet_ntop( AF_INET, &(((struct sockaddr_in*)src)->sin_addr)
    		, buff, sizeof(buff) ), ntohs(((struct sockaddr_in*)src)->sin_port));

    	printf(" to %s : %d\n", inet_ntop( AF_INET, &(((struct sockaddr_in*)dst)->sin_addr)
    		, buff, sizeof(buff) ), ntohs(((struct sockaddr_in*)dst)->sin_port));
    } else {
    	printf("UDP %s : %d", inet_ntop( AF_INET6, &(((struct sockaddr_in6*)src)->sin6_addr)
    		, buff, sizeof(buff) ), ntohs(((struct sockaddr_in6*)src)->sin6_port));

    	printf(" to %s : %d\n", inet_ntop( AF_INET6, &(((struct sockaddr_in6*)dst)->sin6_addr)
    		, buff, sizeof(buff) ), ntohs(((struct sockaddr_in6*)dst)->sin6_port));
    
    }

}

void write_log(char* message)
{
	time_t t_now;
	char time_str[35];
	char buffer[300];

	time(&t_now);
	ctime_r(&t_now, time_str);

	time_str[strlen(time_str) - 1] = '\0';

	sprintf(buffer, "[%s] [pid %d] %s\n", time_str, getpid(), message);

	write(logfd, buffer, strlen(buffer));

}
