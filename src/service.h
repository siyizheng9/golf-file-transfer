#ifndef SERVICE_H
#define SERVICE_H
#include "common.h"
#include <limits.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define	PERMISSION_R_OK	4		/* Test for read permission.  */
#define	PERMISSION_W_OK	2		/* Test for write permission.  */
#define	PERMISSION_X_OK	1		/* Test for execute permission.  */
#define	PERMISSION_F_OK	0		/* Test for existence.  */

typedef struct Client_Profile client_profile;

struct Client_Profile
{
	int clientfd;
	struct sockaddr_in cliaddr;
	struct sockaddr_in6 cliaddr_6;
	bool isIPv4;
	char root_path[PATH_MAX];
};

char* service_getDirContent(char* dir_path, int* content_length);
bool service_getNewPath(char* path, char* extension, char* result_buf);
bool permission_test(char* path, int permission);
bool stat_test(char* path, int test_mode, int result_mode);
char* extract_parameter(E_Packet* pkt_in);
void handle_command_ls(client_profile* ptr_client_profile);
void handle_command_upload(E_Packet* pkt_in, client_profile* ptr_client_profile);
void handle_command_download(E_Packet* pkt_in, client_profile* ptr_client_profile);
void handle_command_download_udp(E_Packet* pkt_in, client_profile* ptr_client_profile);
void handle_command_upload_udp(E_Packet* pkt_in, client_profile* ptr_client_profile);
void handle_command_cd(E_Packet* pkt_in, client_profile* ptr_client_profile);
void handle_command_pwd(client_profile* ptr_client_profile);
void handle_command_md(E_Packet* pkt_in, client_profile* ptr_client_profile);
void handle_command_del(E_Packet* pkt_in, client_profile* ptr_client_profile);

#endif