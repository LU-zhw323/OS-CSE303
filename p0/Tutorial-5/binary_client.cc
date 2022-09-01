/**
 * Client side of the binary networking example.
 *
 * In our binary networking protocol, the client sends a number twice in a
 * single message, and the server increments the number and sends it back twice.
 * If the client sends a zero, it means the communication is over.  If the
 * client sends a -1, it means the server should shut down.
 */
#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <libgen.h>
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
  printf("%s: Client half of a client/server program to demonstrate "
         "sending binary data over a network.\n",
         basename(progname));
  printf("  -n [int]    The number of times to send integers\n");
  printf("  -s [string] Name of the server (probably 'localhost')\n");
  printf("  -p [int]    Port number of the server\n");
  printf("  -h          Print help (this message)\n");
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t {
  /** The name of the server to which the parent program will connect */
  std::string server_name = "";

  /** The port on which the program will connect to the above host */
  size_t port = 0;

  /** The number to count up to */
  int num = 0;

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
  while ((opt = getopt(argc, argv, "p:s:n:h")) != -1) {
    switch (opt) {
    case 's':
      args.server_name = std::string(optarg);
      break;
    case 'p':
      args.port = atoi(optarg);
      break;
    case 'n':
      args.num = atoi(optarg);
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
 * Send binary integers over the network, and expect to receive as a response
 * their incremented value.  Exit upon receiving last_num.
 *
 * @param sd       The socket file descriptor to use for the echo operation
 * @param last_num The last number to send and receive.
 */
void binary_client(int sd, int last_num) {
  // vars for tracking connection duration, round trips
  int round_trips = 0;
  struct timeval start_time, end_time;
  gettimeofday(&start_time, nullptr);

  // We'll use C streams (i.e., FILE*) instead of raw reads/writes.
  // We will also use binary I/O here, not text I/O.  Note that we still need to
  // handle errors.  Also note that FILE* is a bad choice for nonblocking I/O,
  // but we're not doing that yet :)
  FILE *socket = fdopen(sd, "r+b");

  // The initial data to send.  Note that -1 is a special case to close the
  // server
  int data[2] = {1, 1};
  if (last_num == -1) {
    data[0] = data[1] = -1;
  }

  while (true) {
    // For binary I/O, we count items, not bytes
    int num_remain = 2;
    int *next_xmit = data;

    // send the data
    printf("send: %d\n", data[0]);
    while (num_remain) {
      size_t sent = fwrite(next_xmit, sizeof(int), 2, socket);
      if (sent > 0) {
        // we sent *some* data, so prepare in case we need to send more
        num_remain -= sent;
        next_xmit += sent;
      } else if (feof(socket)) {
        // Remote end of socket was closed, so terminate
        fclose(socket);
        return;
      } else if (ferror(socket)) {
        // If the error wasn't EINTR, then terminate
        if (errno != EINTR) {
          perror("binary_client::fwrite()");
          clearerr(socket);
          fclose(socket);
          return;
        }
      }
    }

    // If we sent -1, don't wait for a response from the server
    if (data[0] == -1) {
      fclose(socket);
      return;
    }

    // If we sent 0, it means we're done, so exit gracefully
    if (data[0] == 0) {
      gettimeofday(&end_time, nullptr);
      printf("Completed %d increments in %ld seconds\n", round_trips,
             (end_time.tv_sec - start_time.tv_sec));
      fclose(socket);
      return;
    }

    // We need to receive data and then decide what to do with it
    num_remain = 2;
    next_xmit = data;
    while (num_remain) {
      size_t recd = fread(next_xmit, sizeof(int), 2, socket);
      if (recd > 0) {
        // we received *some* data, so prepare in case we need to receive more
        num_remain -= recd;
        next_xmit += recd;
      } else if (feof(socket)) {
        // Remote end of socket was closed, so terminate
        fclose(socket);
        return;
      } else if (ferror(socket)) {
        // If the error wasn't EINTR, then terminate
        if (errno != EINTR) {
          perror("binary_client::fread()");
          clearerr(socket);
          fclose(socket);
          return;
        }
      }
    }

    // report after receiving data, and check for termination condition
    assert(data[0] == data[1]);
    printf("recv: %d\n", data[0]);
    round_trips++;
    if (data[0] >= last_num) {
      data[0] = data[1] = 0;
    }
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
  // the socket
  printf("Connected\n");
  // NB: binary_client closes the connection before returning
  binary_client(sd, args.num);
  return 0;
}