#include "tls.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

void handle_tls(TlsClient *client, int sockfd)
{
  int tls_state = tls_get_state(client);
  if (tls_state == TLS_WRITE_READY) {
    int read;
    struct TlsOutput to_send;
    to_send = tls_get_output_buffer(client);
    read = send(sockfd, to_send.buffer, to_send.len, 0);
    tls_write_done(client, read);
  }

  else if (tls_state == TLS_READ_READY) {
    int received;
    char buffer[4096];

    bzero(buffer, 4096);
    received = recv(sockfd, buffer, 4096, 0);
    tls_read_done(client, buffer, received);
  }
  return;
}

char *receive_tls(TlsClient *client, int sockfd)
{
  char buffer[4096];
  char *ret;

  bzero(buffer, 4096);
  int received = recv(sockfd, buffer, 4096, 0);
  tls_read_done(client, buffer, received);
  int msg_size = tls_received_appdata(client, buffer, 4096);
  if (msg_size == -1)
    {
      perror("tls_received_appdata error");
      return 0;
    }
  ret = malloc(msg_size + 1);
  memcpy(ret, buffer, msg_size);
  ret[msg_size + 1] = '\0';
  return ret;
}

int main()
{
  TlsServerConf *conf = tls_server_config("echo_client/certificates/cert/certificate.pem", "echo_client/certificates/csr/key.pem");
  TlsClient *client = tls_server(conf);

   int sockfd, newsockfd, portno, clilen;
   struct sockaddr_in serv_addr, cli_addr;

   sockfd = socket(AF_INET, SOCK_STREAM, 0);

   if (sockfd < 0) {
      perror("ERROR opening socket");
      exit(1);
   }

   bzero((char *) &serv_addr, sizeof(serv_addr));
   portno = 4433;

   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);

   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR on binding");
      exit(1);
   }

   listen(sockfd,1);
   clilen = sizeof(cli_addr);
   newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
   if (newsockfd < 0) {
      perror("ERROR on accept");
      exit(1);
   }
   handle_tls(client, newsockfd);
   int handshake_status = tls_do_handshake(client);
   printf("Handshake status: %d\n", handshake_status);

   while (handshake_status == TLS_HANDSHAKE_STOPPED) {
     handle_tls(client, newsockfd);
     handshake_status = tls_do_handshake(client);
     printf("Handshake status: %d\n", handshake_status);
   }

  if (handshake_status == TLS_HANDSHAKE_EOF) {
    perror ("TLS Eof");
    exit(errno);
  }
  char *recmsg;
  while (1)
    {
      recmsg = receive_tls(client, newsockfd);
      if (!recmsg)
	return 1;
      printf("RECEIVED FROM CLIENT ->%s\n", recmsg);
      tls_prepare_appdata(client, recmsg, strlen(recmsg));
      handle_tls(client, newsockfd);
      free(recmsg);
    }
  return 0;
}
