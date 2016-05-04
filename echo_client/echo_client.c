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
  ret = malloc(msg_size + 1);
  memcpy(ret, buffer, msg_size);
  ret[msg_size + 1] = '\0';
  return ret;
}

int get_socket(char *addr, int port) {
  int sockfd;
  struct sockaddr_in dest;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
    perror("Socket");
    exit(errno);
  }
  bzero(&dest, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(port);

  if ( inet_aton(addr, &dest.sin_addr.s_addr) == 0 ) {
    perror(addr);
    exit(errno);
  }

  if ( connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) != 0 ) {
    perror("Connect ");
    exit(errno);
  }

  return sockfd;
}

int main()
{
  TlsConf *conf = tls_client_config("echo_client/certificates/cert/certificate.pem", "echo_client/certificates/csr/key.pem");
  TlsClient *client = tls_client(conf, "localhost");


  int sockfd = get_socket("127.0.0.1", 4433);



  handle_tls(client, sockfd);
  int handshake_status = tls_do_handshake(client);
  printf("Handshake status: %d\n", handshake_status);

  while (handshake_status == TLS_HANDSHAKE_STOPPED) {
    handle_tls(client, sockfd);
    handshake_status = tls_do_handshake(client);
    printf("Handshake status: %d\n", handshake_status);
  }

  if (handshake_status == TLS_HANDSHAKE_EOF) {
    perror ("TLS Eof");
    exit(errno);
  }

  char * msg = "test";
  tls_prepare_appdata(client, msg, strlen(msg));
  handle_tls(client, sockfd);
  char *recmsg = receive_tls(client, sockfd);
  printf("RECEIVED ->%s<-\n", recmsg);
  free(recmsg);
  return 0;
}
