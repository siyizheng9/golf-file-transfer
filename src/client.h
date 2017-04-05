#ifndef CLIENT_H
#define CLIENT_H

#define USER_COMMAND_SIZE 1024
#define USER_COMMAND_NUMBER 3


void *get_in_addr(struct sockaddr *sa);
int socket_connect( char* hostaddr, char* port);
bool clien_handshake(int connfd);
void handle_user_input(int connfd);
int parse_input(char* input_buf,char** arguments);
bool handle_cmd(int connfd, char** arguments, int arg_num, bool* quit_flag);
bool handle_tcp_upload(int connfd, char* file_path);
bool handle_tcp_download(int connfd, char* file_path);
bool handle_udp_download(int connfd, char* file_path);
bool handle_udp_upload(int connfd, char* file_path);
#endif