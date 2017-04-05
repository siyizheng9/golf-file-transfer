#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <limits.h>
#include <libgen.h>
#include "common.h"
#include "client.h"
#include "udp_service.h"
#include "udp.h"

extern udp_srv_stat srv_state;
extern int pkt_sent_count;
extern bool isIPv4;
//extern udp_cli_stat cli_state;

int main(int argc, char *argv[])
{
	//init_cli_state(&cli_state);
	//return 0;

	int connfd;
	char hostaddr[INET6_ADDRSTRLEN];
	char hostport[DEFAULTPOORT_LENGTH];
	int opt;
	bool is_addr = false;
	bool is_port = false;

	while((opt = getopt(argc, argv, "i:p:")) != -1) {
        switch (opt) {
            case 'i': /* server ip address */ 

                if(strlen(optarg) > INET6_ADDRSTRLEN) {

                    printf("Invalid ip address.\n");
                    return -1;

                } else {

                    strcpy(hostaddr, optarg);
                    is_addr = true;
                }
                break;
            case 'p':/* server port numer */
                if (atoi(optarg) < 1024 || strlen(optarg) > DEFAULTPOORT_LENGTH) {
                    printf("invalid port number\n");
                    return -1;
                } else {

                	strcpy(hostport, optarg);
                    is_port = true;
                }
                break;
            default:
                printf("[Usage] %s [-i server ip address] [-p server port]\n",argv[0]);

        }
    }
	if (is_port == false) { // server port not specified, use default port 12000

		strcpy(hostport, DEFAULTPORT);
        printf("using default port %s\n", hostport);

	}

	if (is_addr == false) { // server ip address not specified, use default address 
		
		strcpy(hostaddr, DEFAULTADDR);
		printf("using default address: %s\n", hostaddr);

	}

	connfd = socket_connect(hostaddr, hostport);

	if(connfd == -1){
		printf("failed to connect to the server.\n");
		return -1;
	}

	if(clien_handshake(connfd) == false){
		printf("handshake failed.\n");
		close(connfd);
		return -1;
	}

	handle_user_input(connfd);

	/*printf("**\nstart tcp test\n**\n");
	tcp_file_test(connfd);
	printf("**\nend tcp test\n**\n");

	printf("**\nstart udp test\n**\n");
	udp_file_test(connfd);
	printf("**\nend udp test\n**\n");
*/
	close(connfd);

	return 1;
}


void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family ==AF_INET) {
		return &(((struct sockaddr_in*)sa)-> sin_addr);
		isIPv4 = true;
	}
	isIPv4 = false;
	return &(((struct sockaddr_in6*)sa)-> sin6_addr);
}

// create and return a connected socket
int socket_connect( char* hostaddr, char* port)
{

	struct addrinfo hints, *servinfo, *p;
	char s[INET6_ADDRSTRLEN];
	int sockfd, rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(hostaddr, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return -1;
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socekt");
			continue;
		}
        printf("sockfd:%d\n",sockfd);

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1){
			close(sockfd);
			perror("client:connect");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return -1;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);

	printf("client: connect to %s\n", s);

	freeaddrinfo(servinfo);

	return sockfd;

}

// test tcp_pkt transmission 
bool clien_handshake(int connfd)
{
    E_Packet pkt_in, pkt_out;

    /* send hello to client */
    memset(&pkt_out, 0, sizeof(pkt_out));
    E_Packet_setType(&pkt_out, PACKET_TYPE_HELLO);
    E_Packet_setPayloadLength(&pkt_out, 0);

    /* Receive response from the client */
    if(!tcp_recv_pkt(connfd, &pkt_in))
        {
            printf("handshake: failed.\n");
            return false;
        }

    if(E_Packet_getType(&pkt_in) != PACKET_TYPE_HELLO){

        printf("handshake: failed.\n");
        return false;

    } 
    /* send hello to the server */
    if(!tcp_send_pkt(connfd, &pkt_out)) {
        printf("clien_handshake: failed to send hello to the server.\n");
        return false;
    }

    printf("clien_handshake finished\n");

    return true;

}

void handle_user_input(int connfd)
{
	
	char input_buf[USER_COMMAND_SIZE];
	char* c_ptr;
	char* arguments[USER_COMMAND_NUMBER];
	int arg_num;
	int n;
	bool quit_flag = false;

	while(quit_flag == false){
		//get user input
		printf("\n> ");
		memset(input_buf, 0, sizeof(input_buf));
		fgets(input_buf, sizeof(input_buf), stdin);
		if((c_ptr = strrchr(input_buf, '\n')) != NULL) //remove newline
				*c_ptr = '\0';
		#ifdef DEBUG
		printf("handle_user_cmd: user input '%s'\n", input_buf);
		#endif
		arg_num = parse_input(input_buf, arguments);

		if(arg_num == 0)
			continue;

		handle_cmd(connfd, arguments, arg_num, &quit_flag);

		for(n = 0; n < arg_num; n++){
			free(arguments[n]);
		}

		arg_num = 0;


	}

}

bool handle_cmd(int connfd, char** arguments, int arg_num, bool* quit_flag)
{
	E_Packet pkt_out, pkt_in;
	E_Packet_clear(&pkt_out);
	E_Packet_clear(&pkt_in);
	//char* recv_buf;

	if(strcmp(arguments[0], "help") == 0){
		printf("\nls\n  show the content of the current directory.\n");
		printf("\npwd\n  show path of  current directory.\n");
		printf("\ncd <dir>\n  changes working directory\n");
		printf("\nget <file> [tcp|udp]\n  downloads a file with specified protocol, use tcp by default\n");
		printf("\nput <file> [tcp|udp]\n  uploads a file with specified protocol, use tcp by default\n");
		printf("\nhelp\n  displays help message.\n");
		printf("\nquit\n  exit this program.\n");
		return true;
	}
	else if(strcmp(arguments[0],"quit") == 0) {

		E_Packet_setType(&pkt_out, PACKET_TYPE_END);
		E_Packet_setPayloadLength(&pkt_out, 0);
		tcp_send_pkt(connfd, &pkt_out);

		*quit_flag = true;
		return true;
	}
	else if(strcmp(arguments[0],"ls") == 0) {

		E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_LS);
		E_Packet_setPayloadLength(&pkt_out, 0);
		tcp_send_pkt(connfd, &pkt_out);

		if(!tcp_recv_pkt(connfd, &pkt_in)){
			printf("handle_cmd: failed to get response from the server\n");
			return false;
		}

		if(E_Packet_getType(&pkt_in) == PACKET_TYPE_COMMAND_ACCEPT){
			printf("%s",pkt_in.payload);
			return true;
		} else {
			printf("ls command denied\n");
			return false;
		}

	}
	else if(strcmp(arguments[0],"pwd") == 0) {

		E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_PWD);
		E_Packet_setPayloadLength(&pkt_out, 0);
		tcp_send_pkt(connfd, &pkt_out);

		if(!tcp_recv_pkt(connfd, &pkt_in)){
			printf("handle_cmd: failed to get response from the server\n");
			return false;
		}

		if(E_Packet_getType(&pkt_in) == PACKET_TYPE_COMMAND_ACCEPT){
			printf("%s",pkt_in.payload);
			return true;
		} else {
			printf("pwd command denied\n");
			return false;
		}
	}
	else if(strcmp(arguments[0],"cd") == 0) {

		if(arg_num == 1 ){
			printf("No directory specified.\n");
			return false;
		} 

		E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_CD);
		E_Packet_setPayloadLength(&pkt_out, strlen(arguments[1]));
		strcpy(pkt_out.payload, arguments[1]);
		tcp_send_pkt(connfd, &pkt_out);

		if(!tcp_recv_pkt(connfd, &pkt_in)){
			printf("handle_cmd: failed to get response from the server\n");
			return false;
		}

		if(E_Packet_getType(&pkt_in) == PACKET_TYPE_COMMAND_ACCEPT){
			return true;
		} else {
			printf("cd command denied\n");
			return false;
		}
	}
	else if(strcmp(arguments[0],"md") == 0) {

		E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_MD);
		E_Packet_setPayloadLength(&pkt_out, strlen(arguments[1]));
		strcpy(pkt_out.payload, arguments[1]);
		tcp_send_pkt(connfd, &pkt_out);

		if(!tcp_recv_pkt(connfd, &pkt_in)){
			printf("handle_cmd: failed to get response from the server\n");
			return false;
		}

		if(E_Packet_getType(&pkt_in) == PACKET_TYPE_COMMAND_ACCEPT){
			return true;
		} else {
			printf("md command denied\n");
			return false;
		}
	}
	else if(strcmp(arguments[0],"del") == 0) {

		E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DEL);
		E_Packet_setPayloadLength(&pkt_out, strlen(arguments[1]));
		strcpy(pkt_out.payload, arguments[1]);
		tcp_send_pkt(connfd, &pkt_out);

		if(!tcp_recv_pkt(connfd, &pkt_in)){
			printf("handle_cmd: failed to get response from the server\n");
			return false;
		}

		if(E_Packet_getType(&pkt_in) == PACKET_TYPE_COMMAND_ACCEPT){
			return true;
		} else {
			printf("del command denied\n");
			return false;
		}
	}
	else if(strcmp(arguments[0],"put") == 0) {

		if(arg_num == 1 ){
			printf("No file specified.\n");
			return false;
		} 
		else if (arg_num == 2){

			if(handle_tcp_upload(connfd, arguments[1]) == true){
				printf("'%s' uploaded\n", arguments[1]);
				return true;
			} else {
				printf("failed to upload file tcp '%s'\n", arguments[1]);
				return false;
			}

		} else {

			if(strcmp(arguments[2],"udp") == 0) {

				if(handle_udp_upload(connfd, arguments[1]) == true) {
					printf("'%s' uploaded", arguments[1]);
					return true;
				} else {
					printf("failed to upload file udp'%s'\n", arguments[1]);
					return false;
				}

			} else {

				if(handle_tcp_upload(connfd, arguments[1]) == true){
					printf("'%s' uploaded", arguments[1]);
					return true;
				} else {
					printf("failed to upload file tcp'%s'\n", arguments[1]);
					return false;
				}
			}


		}
	}
	else if(strcmp(arguments[0],"get") == 0) {

		if(arg_num == 1 ){
			printf("No file specified.\n");
			return false;
		} 
		else if (arg_num == 2){

			if(handle_tcp_download(connfd, arguments[1]) == true){
				printf("'%s' downloaded", arguments[1]);
				return true;
			} else {
				printf("failed to download file '%s'\n", arguments[1]);
				return false;
			}

		} else {

			if(strcmp(arguments[2],"udp") == 0) {

				if(handle_udp_download(connfd, arguments[1]) == true) {
					printf("'%s' downloaded\n", arguments[1]);
					return true;
				} else {
					printf("failed to dowload file '%s'\n", arguments[1]);
					return false;
				}
				
			} else {

				if(handle_tcp_download(connfd, arguments[1]) == true){
					printf("'%s' downloaded", arguments[1]);
					return true;
				} else {
					printf("failed to dowload file '%s'\n", arguments[1]);
					return false;
				}
			}


		}
	} else {
		printf("Invalid command '%s'\n",arguments[0]);
		return false;
	}
}

int parse_input(char* input_buf,char** arguments)
{
	char* argument = NULL;
	int arg_num = 0;
	char* buf;
	int n;

	buf = malloc(strlen(input_buf) + 1);
	if(buf == NULL)
		return 0;

	strcpy(buf, input_buf);

	argument = strtok(buf, " ");
	if(argument == NULL){
		free(buf);
		return 0;
	}

	arguments[arg_num] = (char*)malloc(strlen(argument) + 1);
	strcpy(arguments[arg_num], argument);
	arg_num++;

	while ((argument = strtok(NULL, " ")) != NULL ){
		arguments[arg_num] = (char*)malloc(strlen(argument) + 1);
		strcpy(arguments[arg_num], argument);
		arg_num++;
	}
	#ifdef DEBUG
	for(n = 0; n < arg_num; n++)
	printf("parse_input(): argv[%d]='%s', addr=%p\n", n, arguments[n], arguments[n]);
	#endif
	free(buf);
	return arg_num;


}

bool handle_tcp_upload(int connfd, char* file_path)
{
	char* filename;
	int file_length;
	char* file_buf = NULL;

	filename = basename(file_path);


	//free(filename);

	file_buf = read_file(file_path, &file_length);
	if(file_buf == NULL){
		printf("read_file error.\n");
		return false;
	}

	if(send_upload_request(connfd, filename) == false){
		printf("failed to send request\n");
		return false;
	}


	if(tcp_send_file(connfd, file_buf, file_length) == false){
		printf("tcp_file_test:failed to send the file");
		free(file_buf);
		return false;
	}
	
	free(file_buf);
	return true;

}

bool handle_tcp_download(int connfd, char* file_path)
{
	E_Packet pkt_in, pkt_out;
	char* file_buf = NULL;
	//char* filename;
	char filename[NAME_MAX];
	int file_length;

	/* Send file path to the client */
	memset(&pkt_out, 0, sizeof(pkt_out));
	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DOWNLOAD);
	E_Packet_setPayloadLength(&pkt_out, strlen(file_path));
	memcpy(pkt_out.payload, file_path, strlen(file_path));

	printf("send download request for file %s\n", file_path);

	if(!tcp_send_pkt(connfd, &pkt_out)) {
    	printf("handle_tcp_download: failed to send file_path to the server.\n");
    	return false;
    }

     /* Receive response from the server*/
    if(!tcp_recv_pkt(connfd, &pkt_in)){
    		printf("handle_tcp_download: failed to get response from the server\n");
			return false;
	}

	if(E_Packet_getType(&pkt_in) != PACKET_TYPE_COMMAND_ACCEPT){

		printf("handle_tcp_download:request failed.\n");
		return false;
	}

	file_buf = tcp_recv_file(connfd, &file_length);
	if(file_buf == NULL){
		printf("failed to recieve file.\n");
		return false;
	}

	//filename = basename(file_path);
	strcpy(filename, basename(file_path));
	prepend(filename, "client_received_");
    write_file(filename, file_buf, file_length);
    free(file_buf);

    printf("client received file tcp\n");
    return true;


}

bool handle_udp_download(int connfd, char* file_path)
{
	char* file_buf;
	int file_length;
	char filename[NAME_MAX];

	file_buf = udp_download_file(connfd, file_path, &file_length);
    if(file_buf == NULL){
    	printf("failed to receive the file.\n");
    	return false;
    }

    strcpy(filename, basename(file_path));
    prepend(filename, "client_udp_received_");
    write_file(filename, file_buf, file_length);
    free(file_buf);
    printf("client received file udp\n");
    return true;
}

bool handle_udp_upload(int connfd, char* file_path)
{
	E_Packet pkt_in, pkt_out;
	struct sockaddr_storage localad, serverad;
	struct sockaddr_storage* ptr_localad = &localad;
	struct sockaddr_storage* ptr_serverad = &serverad;
	int server_socket;
	int file_length;
	char send_buf[100];
	char* file_buf;
	int return_value;
	socklen_t size;
	char* filename;

	E_Packet_clear(&pkt_in);
	E_Packet_clear(&pkt_out);

	filename = basename(file_path);

	file_buf = read_file(file_path, &file_length);

    if(file_buf == NULL){
    	printf("handle_udp_upload: cannot read file\n");
    	return false;
    }

	if(!init_srv_state(&srv_state)){
		printf("failed to initialize server state structure.\n");
		return false;
	}

	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_UPLOAD_UDP);
	E_Packet_setPayloadLength(&pkt_out, strlen(filename));
	memcpy(pkt_out.payload, filename, strlen(filename));

	printf("send upload request for file %s\n", filename);

	if(!tcp_send_pkt(connfd, &pkt_out)) {
    	printf("handle_udp_upload: failed to send filename to the server.\n");
    	return false;
    }

       /* Receive response from the server*/
    if(!tcp_recv_pkt(connfd, &pkt_in))
		{
    		printf("handle_udp_upload: failed to get response from the server\n");
			return false;
		}
	/* extract server port and window size */
	if(E_Packet_getType(&pkt_in) == PACKET_TYPE_COMMAND_ACCEPT){

		/* Extract port number and window size from pkt_in */
		size = sizeof(serverad);
		if (getpeername(connfd, (struct sockaddr *) &serverad, &size) < 0) {
	        perror("handle_udp_upload getpeername failed.\n");
	        return false;
   		 }

		if(!parse_client_pkt(pkt_in, &srv_state, (struct sockaddr *)&serverad)){
			printf("failed to parse pkt\n");
			return false;
		}

	} else {
		printf("handle_udp_upload:request failed.\n");
		return false;
	}
	/* Send local port num and file size to the client */
	if(isIPv4){
		server_socket = create_udp_socket(connfd);
		if(server_socket == -1) {
			printf("failed to create udp socket\n");
			return false;
		}
	} else {
		server_socket = create_udp_socket_6(connfd);
		if(server_socket == -1){
			printf("failed to create_udp_socket_6\n");
			return false;
		}
	}
	

	size = sizeof(localad);
	if (getsockname(server_socket, (struct sockaddr *) &localad, &size) < 0) {
        perror("handle_udp_upload getsockname");
        return false;
    }

    if(isIPv4){
    	sprintf(send_buf, "%d;%d", ntohs(((struct sockaddr_in*)ptr_localad)->sin_port), file_length);
    } else {
    	sprintf(send_buf, "%d;%d", ntohs(((struct sockaddr_in6*)ptr_localad)->sin6_port), file_length);
    }

    memset(&pkt_out, 0, sizeof(pkt_out));
    E_Packet_setType(&pkt_out, PACKET_TYPE_DATA);
    E_Packet_setPayloadLength(&pkt_out, strlen(send_buf));
    memcpy(pkt_out.payload, send_buf, strlen(send_buf));
	
	/* send client udp port number and file size to server */
    if(!tcp_send_pkt(connfd, &pkt_out)) {
    	printf("handle_udp_upload: failed to send socket port to the server\n");
    	free(file_buf);
    	return false;
    }

   	/* Connect to the server with udp*/
   	if(isIPv4){
   		return_value = connect(server_socket, (struct sockaddr *)&serverad,
                  sizeof(struct sockaddr));

   	} else {
   		return_value = connect(server_socket, (struct sockaddr *)&serverad,
                  sizeof(struct sockaddr_in6));

   	}
	
	if (return_value != 0) {
        perror("handle_udp_upload() connect:\n");
        free(file_buf);
        return false;
    }


    print_ipaddr_pair((struct sockaddr*)ptr_localad, (struct sockaddr*) ptr_serverad, isIPv4);

    printf("server_socket:%d\n", server_socket);

	if(udp_send_file(server_socket, file_buf, file_length) == false){
		printf("handle_udp_upload: failed to send file\n");
		free(file_buf);
		return false;
	} else {
		printf("handle_udp_upload: file sent, now go to udp close.\n");
	}
	free(file_buf);
	udp_close(server_socket);
	printf("pkts sent:%d\n", pkt_sent_count);
	
	return true;


}
