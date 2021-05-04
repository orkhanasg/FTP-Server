#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "dir.h"
#include "usage.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <netdb.h>

#define BUFF_SIZE 256


int parse_command(char *);
int quit();
int pasv();
int retr(char *);
int nlst(char *);

int sockfd, newsockfd;
int pasvsockfd = -1;
int pasvnewsockfd = -1;
int pasv_called = 0;
char init_dir[BUFF_SIZE];
int logged_in = 0;


void terminate(int signum){
  close(sockfd);
  close(newsockfd);
  close(pasvsockfd);
  close(pasvnewsockfd);
}

void logout(){
  logged_in = 0;
}


int main(int argc, char **argv) {

    // This is the main program for the thread version of nc

    int port;
    struct sockaddr_in serv_addr, cli_addr;
    int clilen;
    char buffer[BUFF_SIZE];

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = terminate;
    sigaction(SIGTERM, &action, NULL);

    // Check the command line arguments
    if (argc != 2) {
      usage(argv[0]);
      return -1;
    }

    port = atoi(argv[1]);

    if (port < 1024 || port > 65535) {
      usage(argv[0]);
      return -1;
    }

    // Save the initial working directory
    getcwd(init_dir, BUFF_SIZE);

    printf("Socket created \n");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
      printf("error: Socket not created\n");
      exit(-1);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    printf("The socket created on port %d\n", port);
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      printf("error : binding\n");
      exit(-1);
    }

    while(1) {
      // Go to initial directory for each client.
      chdir(init_dir);

      printf("Bind succesfull\n");
      listen(sockfd, 5);

      printf("server: got connection\n");
      clilen = sizeof(cli_addr);
      newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
      if (newsockfd < 0) {
        printf("error : accept\n");
        continue;
      }

      printf("sending 220 FTP server ready.\n");
      if(send(newsockfd, "220 Service ready for new user.\n", 32, 0) < 0) {
        printf("error: sending 220\n");
        continue;
      }

      while (1) {
        printf("reading client message\n");
        bzero(buffer, BUFF_SIZE);
        if (recv(newsockfd, buffer, BUFF_SIZE - 1, 0) < 0 || strcmp(buffer, "") == 0) {
          printf("error: reading from socket\n");
          close(newsockfd);
          logout();
          break;
        }
        if (parse_command(buffer) == -1) { // QUIT returns -1
          break;
        }
      }
    }

    // printf("Printed %d directory entries\n", listFiles(1, "."));
    return 0;
}

// helper function that returns size of a given file

int fsize(FILE *fp){
    int prev=ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz=ftell(fp);
    fseek(fp,prev,SEEK_SET); 
    return sz;
}


int fdsend(int fd, char msg[]){
  char clon[BUFF_SIZE];
  char *p;
  strcpy(clon, msg);
  p = clon;
  p[strlen(p)-1] = 0;
  printf("sending-> %s\n", p);

  if (send(fd, msg, strlen(msg), 0) == -1){
    printf("error: send\n");
  }
}




// implementation of USER command, according to RFC 959


int user(int fd, char *username) {
  printf("called USER func\n");
  char msg[BUFF_SIZE];

  if (logged_in == 1) {
    strcpy(msg, "530 Already logged in. Can't change user when logged in.\n");
  } else {
    if (username == NULL || strcmp(username, "cs317") != 0){
      strcpy(msg, "530 Not logged in. This server is cs317 only.\n");
    }
    else {
      logged_in = 1;
      strcpy(msg, "230 User logged in, proceed.\n");
    }
  }

  fdsend(fd, msg);
  return 0;
}

// implementation of PASS command, according to RFC 959

int pass(int fd, char * pw) {
  printf("called PASS func\n");
  char msg[BUFF_SIZE];

  if (logged_in == 0) {
    strcpy(msg, "503 Bad sequence of commands. Login with USER first.\n");
  } else {
    strcpy(msg, "230 User logged in, proceed.\n");
  }

  fdsend(fd, msg);
  return 0;
}

int is_logged_in(){
  return logged_in;
}


// implementation of CWD command, according to RFC 959


int cwd(int fd, char *dir) {
  printf("called CWD func\n");
  char *f;
  char cpdir[BUFF_SIZE];
  char msg[BUFF_SIZE];

  if (dir == NULL){
    strcpy(msg, "550 Requested action not taken. Failed to change directory.\n");
  } else {
    strcpy(cpdir, dir);
    f = strtok(dir, "/\r\n");
    if (strcmp(f, "..") == 0 || strcmp(f, ".") == 0) {
      strcpy(msg, "550 Requested action not taken. Directory cannot start with ../ or ./\n");
      fdsend(fd, msg);
      return 0;
    }

    f = strtok(NULL, "/\r\n");

    while(f != NULL){
      if (strcmp(f, "..") == 0) {
        strcpy(msg, "550 Requested action not taken. Directory cannot contain ../\n");
        fdsend(fd, msg);
        return 0;
      }
      f = strtok(NULL, "/\n");
    }

    if (chdir(cpdir) == 0){
      strcpy(msg, "250 Requested file action okay, completed. Directory successfully changed.\n");
    } else {
      strcpy(msg, "550 Requested action not taken. Failed to change directory.\n");
    }
  }

  fdsend(fd, msg);
  return 0;
}

// implementation of CDUP command, according to RFC 959


int cdup(int fd, char init_dir[]) {
  printf("called CDUP func\n");
  char current_dir[BUFF_SIZE];
  char msg[BUFF_SIZE];

  getcwd(current_dir, BUFF_SIZE);
  if (strcmp(current_dir, init_dir) == 0){
    strcpy(msg, "550 Requested action not taken. Not permitted to access parent of root directory.\n");
  } else {
    if (chdir("..") == 0){
      strcpy(msg, "250 Requested file action okay, completed. Directory successfully changed.\n");
    } else {
      strcpy(msg, "550 Requested action not taken. Failed to change directory.\n");
    }
  }

  fdsend(fd, msg);
  return 0;
}

// implementation of TYPE command, according to RFC 959

int type(int fd, char *rept) {
  printf("info | server: called TYPE func\n");
  char msg[BUFF_SIZE];

  if (rept == NULL) {
    strcpy(msg, "501 Syntax error, unrecognised TYPE command.\n");
  } else if (strcasecmp(rept, "I") == 0) {
    strcpy(msg, "200 Command okay. Switching to Binary mode.\n");
  } else if (strcasecmp(rept, "A") == 0){
    strcpy(msg, "200 Command okay. Switching to ASCII mode.\n");
  } else {
    strcpy(msg, "501 Syntax error, unrecognised TYPE command.\n");
  }

  fdsend(fd, msg);
  return 0;
}

// implementation of MODE command, according to RFC 959

int mode(int fd, char *transm) {
  printf("called MODE func\n");
  char msg[BUFF_SIZE];

  if (transm == NULL){
    strcpy(msg, "501 Bad MODE command.\n");
  } else if (strcasecmp(transm, "S") == 0){
    strcpy(msg, "200 Command okay. Mode set to S.\n");
  } else if (strcasecmp(transm, "B") == 0){
    strcpy(msg, "504 MODE Block is not supported.\n");
  } else if (strcasecmp(transm, "C") == 0){
    strcpy(msg, "504 MODE Compressed is not supported.\n");
  } else {
    strcpy(msg, "501 Bad MODE command.\n");
  }

  fdsend(fd, msg);
  return 0;
}

// implementation of STRU command, according to RFC 959

int stru(int fd, char *filestrt) {
  printf("called STRU func\n");
  char msg[BUFF_SIZE];

  if (filestrt == NULL){
    strcpy(msg, "501 Bad STRU command.\n");
  } else if (strcasecmp(filestrt, "F") == 0){ // FILE
    strcpy(msg, "200 Command okay. Structure set to F.\n");
  } else if (strcasecmp(filestrt, "R") == 0){ // RECORD
    strcpy(msg, "504 STRU Record is not supported.\n");
  } else if (strcasecmp(filestrt, "P") == 0){ // PAGE
    strcpy(msg, "504 STRU Page is not supported.\n");
  } else {
    strcpy(msg, "501 Bad STRU command.\n");
  }

  fdsend(fd, msg);
  return 0;
}

// implementation of NLST command, according to RFC 959

int nlst(char *path) {
  printf("called NLST func\n");
  char dir[BUFF_SIZE];
  char msg[BUFF_SIZE];

  if (path != NULL){ // Respond with a 501 if the server gets an NLST with a parameter
    strcpy(msg, "501 NLST doesn't support argument.\n");
    fdsend(newsockfd, msg);
    return 0;
  }

  if (pasv_called == 0){
    strcpy(msg, "425 Data connection is not open. Use PASV first.\n");
    fdsend(newsockfd, msg);
  } else {
    while(pasvnewsockfd == -1); // client should be connected to PASV port

    if (pasvnewsockfd < 0){
      printf("error: NLST received timeout on data connection. returning ..\n");
      pasvnewsockfd = -1;
      return 0;
    }

    bzero(msg, sizeof msg);
    strcpy(msg, "150 File status okay; about to open data connection. Here comes the directory listing.\n");
    fdsend(newsockfd, msg);

    getcwd(dir, BUFF_SIZE);
    listFiles(pasvnewsockfd, dir);

    pasv_called = 0;
    close(pasvnewsockfd);
    close(pasvsockfd);
    pasvnewsockfd = -1;
    pasvsockfd = -1;

    bzero(msg, sizeof msg);
    strcpy(msg, "226 Directory send OK. Closing data connection. Requested file action successful.\n");
    fdsend(newsockfd, msg);
  }

  return 0;
}


// parsing through the given command

int parse_command(char *str) {
  char *cmd;
  char *arg;
  char msg[BUFF_SIZE];

  // Extract cmd and it's arg if exists
  if ((cmd = strtok(str, " \r\n")) != NULL){
    printf("cmd -> %s\n", cmd);
    if ((arg = strtok(NULL, " \r\n")) != NULL){
      printf("arg -> %s\n", arg);
    }
  }

  if (strcasecmp(cmd, "USER") == 0)
    return user(newsockfd, arg);

  else if (strcasecmp(cmd, "PASS") == 0)
    return pass(newsockfd, arg);

  else if (strcasecmp(cmd, "QUIT") == 0)
    return quit();

  else {
    if (is_logged_in() == 1) {
      if (strcasecmp(cmd, "CWD") == 0)
        return cwd(newsockfd, arg);

      else if (strcasecmp(cmd, "CDUP") == 0)
        return cdup(newsockfd, init_dir);

      else if (strcasecmp(cmd, "TYPE") == 0)
        return type(newsockfd, arg);

      else if (strcasecmp(cmd, "MODE") == 0)
        return mode(newsockfd, arg);

      else if (strcasecmp(cmd, "STRU") == 0)
        return stru(newsockfd, arg);

      else if (strcasecmp(cmd, "RETR") == 0)
        return retr(arg);

      else if (strcasecmp(cmd, "PASV") == 0)
        return pasv();

      else if (strcasecmp(cmd, "NLST") == 0 || strcasecmp(cmd, "LIST") == 0)
        return nlst(arg);

      else {
        strcpy(msg, "502 Command not implemented.\n");
        fdsend(newsockfd, msg);
        return 1;
      }
    } else {
      strcpy(msg, "503 Bad sequence of commands. Login with USER first.\n");
      fdsend(newsockfd, msg);
      return 0;
    }
  }
}


// helper function for PASV command, which is given as an argument in pthread_create().

void *pasv_connection(void *pasvsockfd){
  struct sockaddr_in pasv_cli_addr;
  int pasvclilen;
  int *psfd = ((int *) pasvsockfd);
  char msg[BUFF_SIZE];

  listen(*psfd, 5);
  printf("(PASV) started listening\n");

  fd_set rfds;
  struct timeval tv;
  int retval;
  FD_ZERO(&rfds);
  FD_SET(*psfd, &rfds);

  /* Wait up to 20 seconds. */
  tv.tv_sec = 20;
  tv.tv_usec = 0;
  retval = select(*psfd + 1, &rfds, NULL, NULL, &tv);
  if (retval == -1){
    printf("error: (PASV) error on select\n");
  } else if (retval){
      if (FD_ISSET(*psfd, &rfds)){
        printf("(PASV) accepting connections\n");
        pasvclilen = sizeof(pasv_cli_addr);
        pasvnewsockfd = accept(*psfd, (struct sockaddr *) &pasv_cli_addr, &pasvclilen);
        if (pasvnewsockfd < 0) {
          printf("error: (PASV) accept\n");
        }
        printf("(PASV) connection is established\n");
      }
  } else {
    printf("error: (PASV) timeout on dataconnection\n");
    pasv_called = 0;
    close(pasvnewsockfd);
    close(*psfd);
    pasvnewsockfd = -500; // for timeout
    *psfd = -1;
    strcpy(msg, "500 Timeout on data conection\n");
    fdsend(newsockfd, msg);
  }
}

// implementation of PASV command, according to RFC 959

int pasv() {
  printf("called PASV func\n");
  struct sockaddr_in pasv_serv_addr;
  int pasv_port;
  struct sockaddr_in sa;
  int sa_len;
  char msg[BUFF_SIZE];
  char addr[BUFF_SIZE];
  int ip1, ip2, ip3, ip4;
  char *token;
  pthread_t pasv_thread;

  int i;
  struct hostent *he;
  struct in_addr **addr_list;
  char hostname[BUFF_SIZE];


  printf("(PASV) opening socket\n");
  pasvsockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (pasvsockfd < 0) {
    printf("error: (PASV) opening socket\n");
    exit(-1);
  }

  bzero((char *) &pasv_serv_addr, sizeof(pasv_serv_addr));
  pasv_serv_addr.sin_family = AF_INET;
  pasv_serv_addr.sin_port = 0;
  pasv_serv_addr.sin_addr.s_addr = INADDR_ANY;

  printf("(PASV) binding to random port\n");
  if (bind(pasvsockfd, (struct sockaddr *) &pasv_serv_addr, sizeof(pasv_serv_addr)) < 0) {
    printf("error: (PASV) binding\n");
    exit(-1);
  }

  sa_len = sizeof(sa);
  getsockname(pasvsockfd, (struct sockaddr *) &sa, &sa_len);
  pasv_port = (int) ntohs(sa.sin_port);

  gethostname(hostname, sizeof hostname);
  if ((he = gethostbyname(hostname)) == NULL) {  // get the host info
        herror("gethostbyname");
        return 2;
  }

  printf("(PASV) official server name is: %s\n", he->h_name);
  addr_list = (struct in_addr **)he->h_addr_list;
  for(i = 0; addr_list[i] != NULL; i++) {
      strcpy(addr, inet_ntoa(*addr_list[i]));
  }

  printf("(PASV) bound to port %d\n", pasv_port);
  
  printf("(PASV) bound to address: %s\n", addr);

  token = strtok(addr, ".\r\n");
  if (token != NULL) {
    ip1 = atoi(token);
    token = strtok(NULL, ".\r\n");
  }
  if (token != NULL) {
    ip2 = atoi(token);
    token = strtok(NULL, ".\r\n");
  }
  if (token != NULL) {
    ip3 = atoi(token);
    token = strtok(NULL, ".\r\n");
  }
  if (token != NULL) {
    ip4 = atoi(token);
  }

  sprintf(msg, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d).\n", ip1, ip2, ip3, ip4, pasv_port / 256, pasv_port % 256);
  fdsend(newsockfd, msg);

  pasv_called = 1;

  if(pthread_create(&pasv_thread, NULL, pasv_connection, (void *) &pasvsockfd)) {
    printf("error: (PASV) creating thread\n");
    exit(-1);
  }

  return 0;
}



// implementation of RETR command, according to RFC 959

int retr(char *fname) {
  printf("called RETR func\n");
  char msg[BUFF_SIZE];
  int bytes_read;
  FILE *fs;
  int fs_block_size;
  char sdbuf[BUFF_SIZE * 2];
  int fs_total;

  if (pasv_called == 0){
    strcpy(msg, "425 Data connection is not open. Use PASV first.\n");
    fdsend(newsockfd, msg);
  } else{
    while(pasvnewsockfd == -1); // wait until client is connected to pasv port.

    if (pasvnewsockfd < 0){
      printf("error: RETR received timeout on data connection. returning ..\n");
      pasvnewsockfd = -1;
      return 0;
    }

    printf("(PASV) connection is established.\n");
    if (fname == NULL){
      bzero(msg, sizeof msg);
      strcpy(msg, "550 Requested action not taken. Failed to open file.\n");
      fdsend(newsockfd, msg);
    } else{
      if (access(fname, R_OK) != -1){
        // Read and send data
        fs = fopen(fname, "r");
        fs_total = fsize(fs);

        bzero(msg, sizeof msg);
        sprintf(msg, "150 File status okay; about to open data connection. Opening BINARY mode data connection for %s (%d bytes).\n", fname, fs_total);
        fdsend(newsockfd, msg);

        bzero(sdbuf, BUFF_SIZE * 2);
        while((fs_block_size = fread(sdbuf, sizeof(char), BUFF_SIZE * 2, fs)) > 0){
          printf("(PASV) fs_block_size: %d\n", fs_block_size);
          if (write(pasvnewsockfd, sdbuf, fs_block_size) < 0){
            printf("error: (PASV) sending data\n");
          }
          bzero(sdbuf, BUFF_SIZE * 2);
        }
        fclose(fs);

        pasv_called = 0;
        close(pasvnewsockfd);
        close(pasvsockfd);
        pasvnewsockfd = -1;
        pasvsockfd = -1;

        bzero(msg, sizeof msg);
        strcpy(msg, "226 Closing data connection. Transfer complete.\n");
        fdsend(newsockfd, msg);
      } else{
        bzero(msg, sizeof msg);
        strcpy(msg, "550 Requested action not taken. Failed to open file.\n");
        fdsend(newsockfd, msg);
      }
    }
  }
  return 0;
}


int quit() {
  printf("called QUIT func\n");
  logout();
  char msg[] = "221 Goodbye. Closing connection.\n";
  fdsend(newsockfd, msg);
  pasv_called = 0;
  pasvnewsockfd = -1;
  close(newsockfd);
  return -1;
}



