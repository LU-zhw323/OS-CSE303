/**
 * text_client.cc
 *
 * Text_client is half of a client/server pair that shows how to send text to a
 * server and get a reply.
 */

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <string>
#include <sys/time.h>
#include <unistd.h>

/**
 * Display a help message to explain how the command-line parameters for this
 * program work
 *
 * @progname The name of the program
 */
void usage(char *progname) {
  printf("%s: Client half of a client/server echo program to demonstrate "
         "sending text over a network.\n",
         basename(progname));
  printf("  -s [string] Name of the server (probably 'localhost')\n");
  printf("  -p [int]    Port number of the server\n");
  printf("  -h          Print help (this message)\n");
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t {
  /** The name of the server to which the parent program will connect */
  std::string server_name = "";

  /** The port on which the program will connect to the above server */
  size_t port = 0;

  /** Is the user requesting a usage message? */
  bool usage = false;
};

/**
 * Parse the command-line arguments, and use them to populate the provided args
 * object.
 *
 * @param argc The number of command-line arguments passed to the program
 * @param argv The list of command-line arguments
 * @param args The struct into which the parsed args should go
 */
void parse_args(int argc, char **argv, arg_t &args) {
  long opt;
  while ((opt = getopt(argc, argv, "p:s:h")) != -1) {
    switch (opt) {
    case 's':
      args.server_name = std::string(optarg);
      break;
    case 'p':
      args.port = atoi(optarg);
      break;
    case 'h':
      args.usage = true;
      break;
    }
  }
}

void error_message_and_exit(std::size_t code, std::size_t err,
                            const char *prefix) {
  char buf[1024];
  fprintf(stderr, "%s %s\n", prefix, strerror_r(err, buf, sizeof(buf)));
  exit(code);
}


/**
 * Connect to a server so that we can have bidirectional communication on the
 * socket (represented by a file descriptor) that this function returns
 *
 * @param hostname The name of the server (ip or DNS) to connect to
 * @param port     The server's port that we should use
 */
int connect_to_server(std::string hostname, std::size_t port) {
  // figure out the IP address that we need to use and put it in a sockaddr_in
  struct hostent *host = gethostbyname(hostname.c_str());
  if (host == nullptr) {
    fprintf(stderr, "connect_to_server():DNS error %s\n", hstrerror(h_errno));
    exit(0);
  }
  sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr =
      inet_addr(inet_ntoa(*(struct in_addr *)*host->h_addr_list));
  addr.sin_port = htons(port);
  // create the socket and try to connect to it
  int sd = socket(AF_INET, SOCK_STREAM, 0);
  if (sd < 0) {
    error_message_and_exit(0, errno, "Error making client socket: ");
  }
  if (connect(sd, (sockaddr *)&addr, sizeof(addr)) < 0) {
    close(sd);
    error_message_and_exit(0, errno, "Error connecting socket to address: ");
  }
  return sd;
}


/**
 * Receive text from the keyboard (well, actually, stdin), send it to the
 * server, and then print whatever the server sends back.
 *
 * @param sd      The socket file descriptor to use for the echo operation
 * @param verbose Should stats be printed upon completion?
 */
void echo_client(int sd, bool verbose) {
  // vars for tracking connection duration, bytes transmitted
  size_t xmitBytes = 0;
  struct timeval start_time, end_time;
  if (verbose) {
    gettimeofday(&start_time, nullptr);
  }

  // string for holding user input that we send to the server
  std::string data;

  // read from stdin for as long as it isn't EOF, send to server, print reply
  while (true) {
    // Get the data.  We are using C++ streams (cin) instead of scanf, because
    // it's easier and more portable than doing it in C
    //
    // NB: this assumes that stdin hasn't been redirected from a socket
    printf("Client: ");
    getline(std::cin, data);
    if (std::cin.eof()) {
      break;
    }

    // When we send, we need to be ready for the possibility that not all the
    // data will transmit at once
    //
    // NB: it's usually *very bad* to save a pointer to the inside of a C++
    //     string, and it's especially bad to have a non-const pointer.  But in
    //     this code, it's OK.
    char *next_byte = (char *)data.c_str();
    std::size_t remain = data.length();
    while (remain) {
      // NB: send() with last parameter 0 is the same as write() syscall
      std::size_t sent = send(sd, next_byte, remain, 0);
      // NB: Sending 0 bytes means the server closed the socket, and we should
      //     crash.
      //
      // NB: Sending -1 bytes means an error.  If the error is EINTR, it's OK,
      //     try again.  Otherwise crash.
      if (sent <= 0) {
        if (errno != EINTR) {
          error_message_and_exit(0, errno, "Error in send(): ");
        }
      } else {
        next_byte += sent;
        remain -= sent;
      }
    }
    // update the transmission count
    xmitBytes += data.length();

    // Now it's time to receive data.
    //
    // Receiving is hard when we don't know how much data we are going to
    // receive.  Two workarounds are (1) receive until a certain token comes in
    // (such as newline), or (2) receive a fixed number of bytes.  Since we're
    // expecting back exactly what we sent, we can take strategy #2.
    //
    // NB: need an extra byte in the buffer, so we can null-terminate the string
    //     before printing it.
    char buf[data.length() + 1] = {0};
    remain = data.length();
    next_byte = buf;
    while (remain) {
      // NB: recv() with last parameter 0 is the same as read() syscall
      ssize_t rcd = recv(sd, next_byte, remain, 0);
      // NB: as above, 0 bytes received means server closed socket, and -1 means
      //     an error.  EINTR means try again, otherwise we will just crash.
      if (rcd <= 0) {
        if (errno != EINTR) {
          if (rcd == 0) {
            fprintf(stderr, "Error in recv(): EOF\n");
            exit(0);
          } else {
            error_message_and_exit(0, errno, "Error in recv(): ");
          }
        }
      } else {
        next_byte += rcd;
        remain -= rcd;
      }
    }
    // Print back the message from the server, and update the transmission count
    xmitBytes += data.length();
    printf("Server: %s\n", buf);
  }
  if (verbose) {
    gettimeofday(&end_time, nullptr);
    printf("Transmitted %ld bytes in %ld seconds\n", xmitBytes,
           (end_time.tv_sec - start_time.tv_sec));
  }
}














int main(int argc, char *argv[]) {
  // parse the command line arguments
  arg_t args;
  parse_args(argc, argv, args);
  if (args.usage) {
    usage(argv[0]);
    exit(0);
  }

  // Set up the client socket for communicating.  This will exit the program on
  // any error.
  int sd = connect_to_server(args.server_name, args.port);

  // Run the client code to interact with the server.  When it finishes, close
  // the socket.
  printf("Connected\n");
  echo_client(sd, true);
  // NB: ignore errors in close
  close(sd);
  return 0;
}