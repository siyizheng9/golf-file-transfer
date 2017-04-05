#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include "service.h"
#include "udp_service.h"
#include "common.h"
extern int pkt_recv_count;
extern udp_cli_stat cli_state;
extern bool isIPv4;
char working_dir[PATH_MAX];
//service test
/*
int main(int argc, char const *argv[])
{
	int length;
	char* ptr;
	ptr = service_getDirContent("/Users/ZSY/Documents/workspace/golf/src", &length);
	printf("length:%d\n%s",length, ptr);
	printf("str length:%lu\n", strlen(ptr));
	return 0;
	char path[] = "/Users/ZSY/Documents/workspace/golf";
	char extension[] = "..";
	char buf[PATH_MAX];

	service_getNewPath(path, extension, buf);
	printf("%s\n", buf);

}
*/
/*
@param dir_path directory path to read
@param cotent_lengh length of the read return buff
return directory content in a char array
 */
char* service_getDirContent(char* dir_path, int* content_length)
{
	char* return_buf = NULL;
	int file_name_length = 0;
	int index = 0;
	DIR* dir_ptr;
	struct dirent *dir_info;
	int type_length = strlen("[D]");
	//char buf[500];
	if((dir_ptr = opendir(dir_path)) == NULL) {

		perror("service_getDirContent");
		return NULL;

	} else {

		while( (dir_info = readdir(dir_ptr)) ) {

			file_name_length = strlen(dir_info->d_name);

			if(dir_info->d_type == DT_DIR) {
				if((return_buf = realloc(return_buf, (index + type_length) * 
				sizeof(char))) == NULL) {
					closedir(dir_ptr);

					printf("service_getDirContent: failed to expend buffer");
					return NULL;
				}

				strcpy(&return_buf[index], "[D]");
				index += type_length;

			}

			if((return_buf = realloc(return_buf, (index + file_name_length + 1) * 
				sizeof(char))) == NULL) {
				closedir(dir_ptr);

				printf("service_getDirContent: failed to expend buffer");
				return NULL;
			}
			strcpy(&return_buf[index], dir_info->d_name);
			return_buf[index + file_name_length] = '\n';
			index += file_name_length + 1;

		}	
		closedir(dir_ptr);

		return_buf[index - 1] = '\0';
		*content_length = index;
		//printf("%s",buf);

	}
	return return_buf;
}
/*
@param path the base path
@param path extension
@result_buf buffer to hold the new path
return true if success otherwise false
 */
bool service_getNewPath(char* path, char* extension, char* result_buf)
{
	if(extension == NULL)
		return false;

	char temp_path[PATH_MAX];

	if(extension[0] == '/')
		strcpy(result_buf, extension);
	else 
	{
		int index = strlen(path);

		strcpy(temp_path, path);

		temp_path[index] = '/';

		strcpy(temp_path + index + 1, extension);
	}

	realpath(temp_path, result_buf);

	return true;

}

void handle_command_ls(client_profile* ptr_client_profile)
{
	char* buffer = NULL;
	int length = 0;
	int clientfd = ptr_client_profile->clientfd;
	E_Packet pkt_out;
	E_Packet_clear(&pkt_out);

	buffer = service_getDirContent(ptr_client_profile->root_path, &length);

	if(buffer != NULL) {
		E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_ACCEPT);
		E_Packet_setPayloadLength(&pkt_out, length);

		memcpy(pkt_out.payload, buffer, length);

		tcp_send_pkt(clientfd, &pkt_out);
		write_log("[Info] command ls accepted.");

		free(buffer);
	} else {
		E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DENY);
		E_Packet_setPayloadLength(&pkt_out, length);

		memcpy(pkt_out.payload, buffer, length);

		tcp_send_pkt(clientfd, &pkt_out);
		write_log("[Error] command ls denied.");
	}
	
}

void handle_command_cd(E_Packet* pkt_in, client_profile* ptr_client_profile)
{
//	char* buffer = NULL;
//	int length = 0;
	int clientfd = ptr_client_profile->clientfd;
	E_Packet pkt_out;
	E_Packet_clear(&pkt_out);

	char extension[PATH_MAX];
	char result_path[PATH_MAX];
	int temp_char;

	memset(&extension, 0, sizeof(extension));

	memcpy(extension, pkt_in->payload, E_Packet_getPayloadLength(pkt_in));
    extension[E_Packet_getPayloadLength(pkt_in)] = '\0';

    service_getNewPath(ptr_client_profile->root_path, extension, result_path);
    /* compare result path with working dir */
    temp_char = result_path[strlen(working_dir)];
    result_path[strlen(working_dir)] = '\0';
    if(strcmp(result_path, working_dir) != 0) {

    	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DENY);
    	tcp_send_pkt(clientfd, &pkt_out);
    	write_log("[Error] command cd denied.");
    	return;
    }
    result_path[strlen(working_dir)] = temp_char;
    /* compare result path with working dir */

    if(permission_test(result_path, PERMISSION_X_OK) 
            && stat_test(result_path, S_IFMT,S_IFDIR )){

    	strcpy(ptr_client_profile->root_path, result_path);

    	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_ACCEPT);
    	tcp_send_pkt(clientfd, &pkt_out);
    	write_log("[Info] command cd accepted.");
    	return;

    } else {
    	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DENY);
    	tcp_send_pkt(clientfd, &pkt_out);
    	write_log("[Error] command cd denied.");
    	return;
    }


}

void handle_command_pwd(client_profile* ptr_client_profile)
{
	char current_path[PATH_MAX];
	E_Packet pkt_out;
	E_Packet_clear(&pkt_out);
	int clientfd = ptr_client_profile->clientfd;

	strcpy(current_path, ptr_client_profile->root_path + strlen(working_dir));
	if(strlen(current_path) == 0)
		strcpy(current_path, "/");

	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_ACCEPT);
	E_Packet_setPayloadLength(&pkt_out, strlen(current_path));

	strcpy(pkt_out.payload, current_path);

	tcp_send_pkt(clientfd, &pkt_out);
}

void handle_command_md(E_Packet* pkt_in, client_profile* ptr_client_profile)
{
	E_Packet pkt_out;
	E_Packet_clear(&pkt_out);
	int clientfd = ptr_client_profile->clientfd;

	char extension[PATH_MAX];
	char result_path[PATH_MAX];
	int temp_char;

	memset(&extension, 0, sizeof(extension));

	memcpy(extension, pkt_in->payload, E_Packet_getPayloadLength(pkt_in));
    extension[E_Packet_getPayloadLength(pkt_in)] = '\0';

    service_getNewPath(ptr_client_profile->root_path, extension, result_path);
    /* compare result path with working dir */
    temp_char = result_path[strlen(working_dir)];
    result_path[strlen(working_dir)] = '\0';
    if(strcmp(result_path, working_dir) != 0) {

    	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DENY);
    	tcp_send_pkt(clientfd, &pkt_out);
    	write_log("[Error] command md denied.");
    	return;
    }
    result_path[strlen(working_dir)] = temp_char;
    /* compare result path with working dir */

    int status;

	status = mkdir(result_path, 0700);

	if(status == 0) {
		E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_ACCEPT);
		tcp_send_pkt(clientfd, &pkt_out);
		write_log("[Info] command md accepted.");
		return;
	}	
    else {
    	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DENY);
    	tcp_send_pkt(clientfd, &pkt_out);
    	write_log("[Error] command md denied.");
    	return;
    }

}

void  handle_command_del(E_Packet* pkt_in, client_profile* ptr_client_profile)
{
	E_Packet pkt_out;
	E_Packet_clear(&pkt_out);
	int clientfd = ptr_client_profile->clientfd;

	char extension[PATH_MAX];
	char result_path[PATH_MAX];
	int temp_char;

	memset(&extension, 0, sizeof(extension));

	memcpy(extension, pkt_in->payload, E_Packet_getPayloadLength(pkt_in));
    extension[E_Packet_getPayloadLength(pkt_in)] = '\0';

    service_getNewPath(ptr_client_profile->root_path, extension, result_path);
    /* compare result path with working dir */
    temp_char = result_path[strlen(working_dir)];
    result_path[strlen(working_dir)] = '\0';
    if(strcmp(result_path, working_dir) != 0) {

    	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DENY);
    	tcp_send_pkt(clientfd, &pkt_out);
    	return;
    }
    result_path[strlen(working_dir)] = temp_char;
    /* compare result path with working dir */

    int status;

	status = remove(result_path);

	if(status == 0) {
		E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_ACCEPT);
		tcp_send_pkt(clientfd, &pkt_out);
		write_log("[Info] command del denied.");
		return;
	}	
    else {
    	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DENY);
    	tcp_send_pkt(clientfd, &pkt_out);
    	write_log("[Error] command del denied.");
    	return;
    }

}

void handle_command_upload(E_Packet* pkt_in, client_profile* ptr_client_profile)
{
	E_Packet pkt_out;
	char filename[NAME_MAX];
	char file_path[PATH_MAX];
	char* file_buf = NULL;
	int file_length;
	int clientfd = ptr_client_profile->clientfd;

	memcpy(filename, pkt_in->payload, E_Packet_getPayloadLength(pkt_in));
    filename[E_Packet_getPayloadLength(pkt_in)] = '\0';

    printf("requset for uploading file: %s\n", filename);

    memset(&pkt_out, 0, sizeof(pkt_out));
    E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_ACCEPT);
    if(!tcp_send_pkt(clientfd, &pkt_out)) {
        printf("handle_command_upload: failed to send response\n");
        write_log("[Error] tcp upload failed to send response.");
        return;
    }

    file_buf = tcp_recv_file(clientfd, &file_length);
    if(file_buf == NULL){
		printf("failed to recieve file.\n");
		write_log("[Error] tcp upload failed to recieve the file.");
		return;
	}
    prepend(filename, "server_received_");
    service_getNewPath(ptr_client_profile->root_path, filename, file_path);
    write_file(file_path, file_buf, file_length);
    free(file_buf);

    printf("server received file\n");
    write_log("[Info] tcp upload file received.");

}

void handle_command_download(E_Packet* pkt_in, client_profile* ptr_client_profile)
{
	char file_path[PATH_MAX];
	char* file_buf = NULL;
	int file_length;
	int clientfd = ptr_client_profile->clientfd;
	E_Packet pkt_out;
	E_Packet_clear(&pkt_out);

	memcpy(file_path, pkt_in->payload, E_Packet_getPayloadLength(pkt_in));
    file_path[E_Packet_getPayloadLength(pkt_in)] = '\0';

    service_getNewPath(ptr_client_profile->root_path, file_path, file_path);

    printf("requset for file: %s\n", file_path);

    file_buf = read_file(file_path, &file_length);

    if(file_buf == NULL){
    	printf("Invalid download request.\n");
    	write_log("[Error] tcp download invalid download request.");
    	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DENY);
    	tcp_send_pkt(clientfd, &pkt_out);
    	return;
    }

    E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_ACCEPT);

    if(!tcp_send_pkt(clientfd, &pkt_out)) {
    	printf("handle_command_download: failed to send accept to the client.\n");
    	free(file_buf);
    	return;
    }

    if(tcp_send_file(clientfd, file_buf, file_length) == false){
		printf("handle_command_download:failed to send the file");
		write_log("[Error] tcp download failed to send the file");
		free(file_buf);
		return;
	}

	free(file_buf);

	printf("server sent the file\n");
	write_log("[Info] tcp download server sent the file");

}

void handle_command_download_udp(E_Packet* pkt_in, client_profile* ptr_client_profile)
{
	char file_path[PATH_MAX];
	char* file_buf = NULL;
	int file_length;
	int clientfd = ptr_client_profile->clientfd;
	E_Packet pkt_out;


	memcpy(file_path, pkt_in->payload, E_Packet_getPayloadLength(pkt_in));
    file_path[E_Packet_getPayloadLength(pkt_in)] = '\0';

    service_getNewPath(ptr_client_profile->root_path, file_path, file_path);

    printf("requset for file: %s\n", file_path);

    file_buf = read_file(file_path, &file_length);

    if(file_buf == NULL){
    	printf("invalid download request.\n");
    	write_log("[Error] udp download invalid download request");
    	E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_DENY);
    	tcp_send_pkt(clientfd, &pkt_out);
    	return;
    }

    if(handle_udp_download_request(clientfd, file_buf, file_length) == false){
        printf("failed to send the file\n");
        write_log("[Error] udp download failed to send the file");
        free(file_buf);
        return;
    }

    free(file_buf);

    printf("server sent the file\n");
    write_log("[Info] udp download server sent the file");

}

void handle_command_upload_udp(E_Packet* pkt_in, client_profile* ptr_client_profile)
{
	char filename[NAME_MAX];
	char file_path[PATH_MAX];
	char send_buf[100];
	char* file_buf;
	int file_size;
	int client_socket;
	int return_value;
	socklen_t size;
	struct sockaddr_storage localad, clientad;
	struct sockaddr_storage* ptr_localad = &localad;
	struct sockaddr_storage* ptr_clientad = &clientad;
	int clientfd = ptr_client_profile->clientfd;
	//bool isIPv4 = ptr_client_profile->isIPv4;
	E_Packet pkt_out;


	memcpy(filename, pkt_in->payload, E_Packet_getPayloadLength(pkt_in));
    filename[E_Packet_getPayloadLength(pkt_in)] = '\0';

    printf("requset for uploading file by udp: %s\n", filename);

    /* send local udp port and window size to the client */
	if(init_cli_state(&cli_state) == -1){
		printf("failed to initialize client state structure.\n");
		return;
	}

	if(isIPv4){
	    client_socket = create_udp_socket(clientfd);
	    if(client_socket == - 1) {
	    	printf("failed to create_udp_socket.\n");
	    	return;
	    }
    } else {
    	client_socket = create_udp_socket_6(clientfd);
	    if(client_socket == - 1) {
	    	printf("failed to create_udp_socket_6.\n");
	    	return;
	    }
    }

    size = sizeof(localad);
    if (getsockname(client_socket, (struct sockaddr *) &localad, &size) < 0) {
        perror("handle_command_upload_udp getsockname failed.\n");
        return;
    }

    if(isIPv4){
    	sprintf(send_buf, "%d;%d", ntohs(((struct sockaddr_in*)ptr_localad)->sin_port), cli_state.window_size);
    } else {

    	sprintf(send_buf, "%d;%d", ntohs(((struct sockaddr_in6*)ptr_localad)->sin6_port), cli_state.window_size);

    }

    memset(&pkt_out, 0, sizeof(pkt_out));
    E_Packet_setType(&pkt_out, PACKET_TYPE_COMMAND_ACCEPT);
    E_Packet_setPayloadLength(&pkt_out, strlen(send_buf));
    memcpy(pkt_out.payload, send_buf, strlen(send_buf));

    if(!tcp_send_pkt(clientfd, &pkt_out)) {
    	printf("handle_command_upload_udp: failed to send udp port and window size to the server\n");
    	write_log("[Error] handle_command_upload_udp(): failed to send udp port and window size.");
    	return;
    }

     /* Receive udp port and file size from the client*/

    if(!tcp_recv_pkt(clientfd, pkt_in))
		{
    		printf("handle_command_upload_udp: failed to receive response from the server\n");
			return;
		}

	if(E_Packet_getType(pkt_in) == PACKET_TYPE_DATA){
		/*extract client port number and flie size from pkt_in */
		size = sizeof(clientad);
		if (getpeername(clientfd, (struct sockaddr *) &clientad, &size) < 0) {
	        perror("handle_command_upload_udp getpeername failed.\n");
	        return;
   		 }

		if(parse_server_pkt(pkt_in, (struct sockaddr *)&clientad, &file_size) == false){
			printf("failed to parse pkt_in.");
			write_log("[Error] handle_command_upload_udp(): failed to parse pkt_in.");
			return;
		}
	} else {
		printf("handle_command_upload_udp:request failed.\n");
		return;
	}

	/* Connect to the client with udp */
	if(isIPv4){
		return_value = connect(client_socket, (struct sockaddr *)&clientad,
                  sizeof(struct sockaddr));
	} else {
		return_value = connect(client_socket, (struct sockaddr *)&clientad,
                  sizeof(struct sockaddr_in6));
	}

	if (return_value != 0) {
		perror("handle_command_upload_udp() connect:\n");
		write_log("[Error] handle_command_upload_udp(): connect");
        return;
    }

    print_ipaddr_pair((struct sockaddr*)ptr_localad, (struct sockaddr*)ptr_clientad, isIPv4);

    printf("client_socket:%d\n", client_socket);

    if((file_buf = udp_recv_file(client_socket, file_size)) == NULL) {
    	printf("handle_command_upload_udp: failed to recv file");
    	write_log("[Error] udp upload failed to receive the file.");
    	return;
    } else {
    	printf("handle_command_upload_udp: file recieved\n");
    }

    prepend(filename, "server_udp_received_");
   	service_getNewPath(ptr_client_profile->root_path, filename, file_path);

   	write_file(file_path, file_buf, file_size);
   	free(file_buf);
   	cli_state_destroy(&cli_state);
    printf("server received file\n");
    write_log("[Info] udp upload server received the file");

}


char* extract_parameter(E_Packet* pkt_in)
{
	int payload_length = E_Packet_getPayloadLength(pkt_in);
	char* parameter = malloc(payload_length + 1);
	memcpy(parameter, pkt_in->payload, payload_length);
	parameter[payload_length] = '\0';

	return parameter;

}

bool permission_test(char* path, int permission)
{
	if(access(path, permission) != 0) {
           // perror("access:");
            return false;
        } else {

        	return true;
        }
}

bool stat_test(char* path, int test_mode, int result_mode)
{
	struct stat s;

	return (stat(path, &s) != -1) && ((s.st_mode & test_mode) == result_mode);
}
