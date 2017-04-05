#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include "common.h"
#include "server.h"
#include "udp_service.h"
#include "service.h"

extern int logfd;
extern char working_dir[PATH_MAX];
extern bool isIPv4;
//extern udp_srv_stat srv_state;

static void child_handler(int sig)
{
    pid_t pid;
    int stat;

    while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
        printf("child process %d terminated\n", pid);
    }

    return;
}

void sig_int(int signo)
{
    printf("terminated by signal %d\n", signo);
    return;
}

void daemonize(void)
{
    int pid, i;
    if(getppid() == 1)
        return;
    pid = fork();
    if(pid < 0)
        exit(EXIT_FAILURE);
    if(pid > 0)
        exit(EXIT_SUCCESS);

    if(setsid() < 0)
        exit(EXIT_FAILURE);

    for (i = getdtablesize(); i >= 0; --i)
            close(i); /* close all descriptors */

    /* handle standart I/O */
    i = open("/dev/null",O_RDWR); /* open stdin */
    dup(i); /* stdout */
    dup(i);  /* stderr */

}

int main(int argc, char *argv[])
{
 //   init_srv_state(&srv_state);
 //   return 0;
 //   daemonize();

    int clientfd, listenfd, listenfd_6;
//  struct sockaddr_in cliaddr;
    char serverport[DEFAULTPOORT_LENGTH];
    char dir_path[PATH_MAX];
    int child_pid;
    int opt;
    bool is_path = false;
    bool is_port = false;
    client_profile* ptr_client_profile;

    //initialize client_profile
    ptr_client_profile = malloc(sizeof(client_profile));
    memset(ptr_client_profile, 0, sizeof(client_profile));
    //extract user options from command line
    while((opt = getopt(argc, argv, "d:p:")) != -1) {
        switch (opt) {
            case 'd': /* working directory path */ 

                if(permission_test(optarg, PERMISSION_X_OK) 
                && stat_test(optarg, S_IFMT,S_IFDIR )) {

                    if(realpath(optarg, dir_path) != NULL ) {
                        printf("using path [%s] as working directory.\n", dir_path);
                        is_path = true;
                    }
                    else {
                        printf("invalid directory path\n");
                        return -1;
                    }

                } else {
                    printf("invalid directory path\n");
                    return -1;
                }
                break;
            case 'p':/* server port numer */
                if (atoi(optarg) < 1024 || strlen(optarg) > DEFAULTPOORT_LENGTH) {
                    printf("invalid port number\n");
                    return -1;
                } else {
                    strcpy(serverport, optarg);
                    is_port = true;
                }
                break;
            default:
                printf("[Usage] %s [-d directory path] [-p server port]\n",argv[0]);

        }
    }

    if(is_path == false) { // directory path not specified, use current path

        //get current directory
        realpath(".", dir_path);
        printf("using current path [%s] as working directory.\n", dir_path);

    }

    if(is_port == false) { // server port not specified, use port 12000

        strcpy(serverport, DEFAULTPORT);
        printf("using default port 12000\n");
    }
    
    if ((logfd = open("server.log", O_RDWR | O_APPEND | O_CREAT, 
        S_IRUSR | S_IWUSR)) < 0) {
        perror("main(): open or create log file error");
        return -1;
    }

    write_log("[Info] server start.");

    if((listenfd = create_service(atoi(serverport))) == -1) {
        printf("create service failed!\n");
        write_log("[Error] creating IPv4 service failed");
        free(ptr_client_profile);
        return -1;
    }

    if((listenfd_6 = create_service_6(atoi(serverport))) == -1) {
        printf("create_service_6 failed!\n");
        write_log("[Error] creating IPv6 service failed");
        //free(ptr_client_profile);
        //return -1;
    }

    strcpy(working_dir, dir_path);
    strcpy(ptr_client_profile->root_path, dir_path);

    /* Establish signal handler */
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    // sigemptyset(&sa2.sa_mask);
    sa.sa_flags = 0;
    // sa2.sa_flags = SA_RESETHAND;
    sa.sa_handler = child_handler;
    // sa2.sa_handler = sig_int;

    signal(SIGHUP,SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    if (sigaction(SIGCHLD, &sa, NULL) == -1)
        {
            perror("main(): sigaction");
            return -1;
        }

 /*   if (sigaction(SIGINT, &sa2, NULL) == -1)
        {
            perror("main(): sigaction");
            return -1;
        }*/


    while(true){
        
        clientfd = get_client_socket(listenfd, listenfd_6, ptr_client_profile);

        if(clientfd == -1){
            if (errno == EINTR) {
                continue;
            } else {
                printf("failed to get client socket.\n");
                write_log("[Error] failed to get client socket.");
                continue;
            }
        }

        ptr_client_profile->clientfd = clientfd;

        if((child_pid = fork()) == 0) {
            close(listenfd);

            if(server_handshake(clientfd))
                handle_client_request(ptr_client_profile);

            close(clientfd);
            free(ptr_client_profile);
            printf("client exit\n");
            write_log("[Info] client exit.");
            return 0;
        }
    }
    
    free(ptr_client_profile);
    close(listenfd);
    close(logfd);

	return 0;

}

bool server_handshake(int clientfd)
{
    E_Packet pkt_in, pkt_out;

    /* send hello to client */
    memset(&pkt_out, 0, sizeof(pkt_out));
    E_Packet_setType(&pkt_out, PACKET_TYPE_HELLO);
    E_Packet_setPayloadLength(&pkt_out, 0);

    if(!tcp_send_pkt(clientfd, &pkt_out)) {
        printf("send_hello: failed to send hello to the client.\n");
        return false;
    }

    /* Receive response from the client */
    if(!tcp_recv_pkt(clientfd, &pkt_in))
        {
            printf("handshake: failed.\n");
            return false;
        }

    if(E_Packet_getType(&pkt_in) == PACKET_TYPE_HELLO){
        printf("handshake finished\n");
        write_log("[Info] handshake finished.");
        return true;

    } else {

        printf("handshake: failed.\n");
        write_log("[Error] handshake failed");
        return false;
    }


}

void handle_client_request(client_profile* ptr_client_profile)
{
    E_Packet pkt_in, pkt_out;
    int pkt_type;
    int clientfd = ptr_client_profile->clientfd;
    E_Packet_clear(&pkt_in);
    E_Packet_clear(&pkt_out);

    while(tcp_recv_pkt(clientfd, &pkt_in)) {

        pkt_type = E_Packet_getType(&pkt_in);
        if(pkt_type == PACKET_TYPE_END)
            break;

        #ifdef DEBUG
        printf("handle_client_request: got command '%d' \n",E_Packet_getType(&pkt_in));
        #endif
        switch(pkt_type) {

            case PACKET_TYPE_COMMAND_LS:
            write_log("[Info] got command ls");
            handle_command_ls(ptr_client_profile);
            break;

            case PACKET_TYPE_COMMAND_CD:
            write_log("[Info] got command cd");
            handle_command_cd(&pkt_in, ptr_client_profile);
            break;

            case PACKET_TYPE_COMMAND_PWD:
            write_log("[Info] got command pwd");
            handle_command_pwd(ptr_client_profile);
            break;

            case PACKET_TYPE_COMMAND_MD:
            write_log("[Info] got command md");
            handle_command_md(&pkt_in, ptr_client_profile);
            break;

            case PACKET_TYPE_COMMAND_DEL:
            write_log("[Info] got command del");
            handle_command_del(&pkt_in, ptr_client_profile);
            break;

            case PACKET_TYPE_COMMAND_UPLOAD:
            write_log("[Info] got command upload");
            handle_command_upload(&pkt_in, ptr_client_profile);
            break;

            case PACKET_TYPE_COMMAND_DOWNLOAD:
            write_log("[Info] got command download");
            handle_command_download(&pkt_in, ptr_client_profile);
            break;

            case PACKET_TYPE_COMMAND_DOWNLOAD_UDP:
            write_log("[Info] got command udp download");
            handle_command_download_udp(&pkt_in, ptr_client_profile);
            break;

            case PACKET_TYPE_COMMAND_UPLOAD_UDP:
            write_log("[Info] got command udp upload");
            handle_command_upload_udp(&pkt_in, ptr_client_profile);
            break;
            #ifdef DEBUG
            default:
            printf("unknown command.\n");
            #endif
            write_log("unknown command");

        }

    }

}

int create_service(int serverport)
{
    int listenfd;
    struct sockaddr_in servaddr;

    // create socket for listening
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        write_log("[Error] create_service():socket");
        return -1;
    }
    printf("listenfd:%d\n", listenfd);

    // Pick a port and bind socket to it.
    // Accept connections from any address.
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    //inet_pton(AF_INET, SERVERADDR, &(servaddr.sin_addr));
    servaddr.sin_port = htons(serverport);

    if (bind(listenfd, (struct sockaddr *) &servaddr,
        sizeof(servaddr)) < 0) {
        write_log("[Error] create_service():bind");
        perror("bind");
        return -1;
    }

    // Set the socket to passive mode, with specified listen queue size
    if (listen(listenfd, LISTENQ) < 0) {
        write_log("[Error] create_service():listen");
        perror("listen");
        return -1;
    }

    return listenfd;
}

int create_service_6(int serverport)
{
    int listenfd;
    struct sockaddr_in6 servaddr;

    // create socket for listening
    if ((listenfd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
        write_log("[Error] create_service_6():socket");
        perror("socket_6");
        return -1;
    }
    printf("listenfd_6:%d\n", listenfd);

    // Pick a port and bind socket to it.
    // Accept connections from any address.
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_addr = in6addr_any;
    //inet_pton(AF_INET, SERVERADDR, &(servaddr.sin_addr));
    servaddr.sin6_port = htons(serverport);

    int on = 1;
    setsockopt(listenfd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));

    if (bind(listenfd, (struct sockaddr *) &servaddr,
        sizeof(servaddr)) < 0) {
        write_log("[Error] create_service_6():bind");
        perror("bind_6");
        return -1;
    }

    // Set the socket to passive mode, with specified listen queue size
    if (listen(listenfd, LISTENQ) < 0) {
        write_log("[Error] create_service_6():listen");
        perror("listen_6");
        return -1;
    }

    return listenfd;
}

int get_client_socket(int listenfd, int listenfd_6, client_profile* ptr_client_profile)
{
    int connfd;
    struct sockaddr_in cliaddr;
    struct sockaddr_in6 cliaddr_6;
    socklen_t length, length_6;
    char buff[INET6_ADDRSTRLEN];
    fd_set rset;
    int numfds, maxfd;
    length = sizeof(cliaddr);
    length_6 = sizeof(cliaddr_6);

    FD_ZERO(&rset);
    
    FD_SET(listenfd, &rset);
    maxfd = listenfd + 1;

    if (listenfd_6 >= 0){
        maxfd = listenfd_6 + 1;
        FD_SET(listenfd_6, &rset);
    }
    

    if ((numfds = select(maxfd, &rset, NULL, NULL, NULL)) < 0) {
            if (errno == EINTR) {
                return -1;
            } else {
                perror("select");
                write_log("[Error] get_client_socket():select");
                return -1;
            }
        }

    if (FD_ISSET(listenfd, &rset)) {

        if ((connfd = accept(listenfd, (struct sockaddr *) &cliaddr,
                                 &length)) < 0) {
                if (errno == EINTR) {
                return -1;
                } else {
                    perror("accept");
                    write_log("[Error] get_client_socket():accept");
                    return -1;
                }
            }
            printf("new clientfd:%d\n", connfd);
            printf("connection from %s, port %d\n",
                   inet_ntop( AF_INET, &cliaddr.sin_addr,
                   buff, sizeof(buff) ),
                   ntohs(cliaddr.sin_port));

        ptr_client_profile->cliaddr = cliaddr;
        ptr_client_profile->isIPv4 = true;
        isIPv4 = true;

        return connfd;

        
    } else {

        // wait for incoming connection
        // new socket fd will be used in return
        if ((connfd = accept(listenfd_6, (struct sockaddr *) &cliaddr_6,
                             &length_6)) < 0) {
            if (errno == EINTR) {
                return -1;
                } else {
                    write_log("[Error] get_client_socket():IPv6 accept");
                    perror("accept");
                    return -1;
                }
        }
        printf("connection from %s, port %d\n",
               inet_ntop(AF_INET6, &cliaddr_6.sin6_addr,
               buff, sizeof(buff)),
               ntohs(cliaddr_6.sin6_port));
       ptr_client_profile->cliaddr_6 = cliaddr_6;
       ptr_client_profile->isIPv4 = false;
       isIPv4 = false;
        return connfd;
    }
}
