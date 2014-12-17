/* Truly trivial exploitable service. The server waits for client
 * request and echos the data it received, one character at a time. It
 * can be exploited in two phases: 1 buffer overflow to obtain a
 * suitable jump addres, and another one to inject the shellcode and
 * another one to inject the shellcode and divert the control
 * flow. Details can be found in the 00README.txt file.
 *
 * This code is made available under the GNU Public License version 2.
 *
 * (c) Herbert Bos, 2007
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h> /* gethostname() */
#include <netdb.h>  /* gethostbyname() */
#include <errno.h>
#include <signal.h>


int sockfd=0;

void wrapUp_int (int x)
{
  if (sockfd) close (sockfd);
  printf ("wrapUp INT: done\n");
  exit(1);
}

void wrapUp_segv (int x)
{
  if (sockfd) close (sockfd);
  printf ("wrapUp SEGV: done\n");
  exit(1);
}

void error(char *msg)
{
    perror(msg);
    exit(1);
}


int oops (int newsockfd)
{
  int len;
  char buf [56];
  int i,n;


  len = 56;
  bzero(buf,len);

  n = read (newsockfd, buf, 255); // overflow possible
  if (n < 0) error("ERROR reading from socket");

  // 'echo' the message  
  if (len>255) len = 255;
    printf ("Echoing %d characters\n", len);

  for (i=0; i<len; i++) {
    // pretty dumb svr: echos characters 1 at a time
    write(newsockfd, buf+i,1);
    if (n < 0) error("ERROR writing to socket");
  }
  
  return 0;
}

int main (int argc, char *argv[])
{
  int newsockfd, portno, clilen;
  struct sockaddr_in serv_addr, cli_addr;


  if (argc != 2) {
    fprintf (stderr, "usage: %s <portnumber>\n", argv[0]);       
    exit(1);
  }

  /* pressing CTRL-C and SEGV should be handled gracefully */
  signal(SIGINT, wrapUp_int);
  signal(SIGSEGV, wrapUp_segv);

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) 
    error("ERROR opening socket");
  bzero((char *) &serv_addr, sizeof(serv_addr));
  portno = atoi(argv[1]);
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portno);
  if (bind(sockfd, (struct sockaddr *) &serv_addr,
	   sizeof(serv_addr)) < 0) 
    error("ERROR on binding");

  listen(sockfd,5);
  clilen = sizeof(cli_addr);

  // start serving client requests
  while (1) {
    newsockfd = accept(sockfd, 
		       (struct sockaddr *) &cli_addr, 
		       &clilen);
    if (newsockfd < 0) 
      error("ERROR on accept");

    oops (newsockfd); // call the vulerable function
    printf ("returned\n");
    close (newsockfd);
  }
  printf ("done\n");
  return 0;
}
