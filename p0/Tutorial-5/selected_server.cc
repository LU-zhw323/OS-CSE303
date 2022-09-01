
/**
 * select_server.cc
 *
 * Select_server is half of a client/server pair that demonstrates how a server
 * can use select() so that a single-threaded server can manage multiple client
 * connections.
 */

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <unistd.h>

/** Print a message to inform the user of how to use this program */
void usage(char *progname) {
  printf("%s: Server half of a client/server program to demonstrate the use of "
         "select().\n",
         basename(progname));
  printf("  -p [int]    Port number of the server\n");
  printf("  -h          Print help (this message)\n");
}

/**
 * In this program, the only useful argument is a port number. We store it in
 * the arg_t struct, which we populate via the get_args() function.
 */
struct arg_t {
  /** The port on which the program will listen for connections */
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
  while ((opt = getopt(argc, argv, "p:h")) != -1) {
    switch (opt) {
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
 * Create a server socket that we can use to listen for new incoming requests
 *
 * @param port The port on which the program should listen for new connections
 */
int create_server_socket(std::size_t port) {
  // A socket is just a kind of file descriptor.  We want our connections to use
  // IPV4 and TCP:
  int sd = socket(AF_INET, SOCK_STREAM, 0);
  if (sd < 0) {
    error_message_and_exit(0, errno, "Error making server socket: ");
  }
  // The default is that when the server crashes, the socket can't be used for a
  // few minutes.  This lets us re-use the socket immediately:
  int tmp = 1;
  if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(int)) < 0) {
    close(sd);
    error_message_and_exit(0, errno, "setsockopt(SO_REUSEADDR) failed: ");
  }

  // bind the socket to the server's address and the provided port, and then
  // start listening for connections
  sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(sd);
    error_message_and_exit(0, errno, "Error binding socket to local address: ");
  }
  if (listen(sd, 0) < 0) {
    close(sd);
    error_message_and_exit(0, errno, "Error listening on socket: ");
  }
  return sd;
}





/**
 * When a client sends a message, we use this to read from the client socket. As
 * in previous examples, we can get ourselves into some trouble if we don't know
 * how long the message is... in this case, we read up to 16 bytes at a time. In
 * a real program, we'd need to buffer each client's inputs so that we could
 * read a full message before processing it.
 *
 * @param sd The socket corresponding to the client who sent a message
 *
 * @returns True if the socket should remain open for future messages
 */
bool handle_client_input(int sd) {
  // Receive up to 16 bytes of data... save the last byte as '\0'
  char buf[17] = {0};
  ssize_t recd = read(sd, buf, sizeof(buf) - 1);

  // Handle errors
  if (recd < 0 && errno != EINTR) {
    error_message_and_exit(0, errno, "Error in read(): ");
    return false;
  }
  // EOF means the client closed the connection
  else if (recd == 0) {
    return false;
  }
  // Otherwise, print whatever data we received
  else {
    printf("Message from client %d: %s\n", sd, buf);
    return true;
  }
}














int main(int argc, char **argv) {
  // parse the command line arguments
  arg_t args;
  parse_args(argc, argv, args);
  if (args.usage) {
    usage(argv[0]);
    exit(0);
  }

  // Set up the server socket for listening.  This will exit the program on any
  // error.
  int serverSd = create_server_socket(args.port);

  // Initialize a set of active sockets, and add the listening socket to it
  fd_set active_sds;
  FD_ZERO(&active_sds);
  FD_SET(serverSd, &active_sds);

  while (true) {
    // wait for input to come in on any of the active sockets
    fd_set read_fd_set = active_sds;
    if (select(FD_SETSIZE, &read_fd_set, nullptr, nullptr, nullptr) < 0) {
      error_message_and_exit(0, errno, "Error calling select(): ");
    }

    // Go through all the sockets in active_sds that have pending input, and
    // process them.
    //
    // NB: FD_SETSIZE is a constant, defined as 1024 in Linux.  If your server
    //     might need to handle more than 1024 active connections using this
    //     technique, then you'll need to use poll() instead.
    for (int i = 0; i < FD_SETSIZE; ++i) {
      if (FD_ISSET(i, &read_fd_set)) {
        // if this socket is the server socket, it means we have a new incoming
        // connection that we need to add to the set.
        if (i == serverSd) {
          sockaddr_in clientname;
          socklen_t size = sizeof(clientname);
          int connSd = accept(serverSd, (struct sockaddr *)&clientname, &size);
          if (connSd < 0) {
            error_message_and_exit(0, errno,
                                   "Error accepting connection from client: ");
          }
          printf("Connected to %s:%d\n", inet_ntoa(clientname.sin_addr),
                 ntohs(clientname.sin_port));
          FD_SET(connSd, &active_sds);
        }
        // Otherwise the socket is already in the set, which means that a client
        // just sent data
        else {
          if (!handle_client_input(i)) {
            close(i);
            FD_CLR(i, &active_sds);
          }
        }
      }
    }
  }
}