#ifndef _DEFAULT_SOURCE
/* Expose legacy BSD-like network structs (struct icmp etc.) to headers when not
    already defined by compiler flags (e.g. -D_DEFAULT_SOURCE in Makefile). */
#define _DEFAULT_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <float.h>
#include <signal.h> 

#define SHORT_TTL_IF 1000
#define PING_MIN_USER_INTERVAL (0.2)
#define EXIT_FAILURE 1
#define EXIT_FAILURE_USAGE 64

#define exit_on_error(code, usage_msg, fmt, ...) do { \
    fprintf(stderr, "ft_ping: "); \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    fprintf(stderr, "\n"); \
    if (usage_msg) \
        fprintf(stderr, "Try 'ping --help' or 'ping --usage' for more information.\n"); \
    exit(code); \
} while(0)

typedef struct s_ping {
    bool        verbose;
    bool        help;
    bool        flood;
    bool        numeric_only;
    int         time_to_live;
    double      interval;
    size_t      count;
    char        *target;
} t_ping_flg;

typedef struct s_ping_context {
    struct sockaddr_in  addr;
    socklen_t           addr_len;
    char                ipv4[INET_ADDRSTRLEN];
    int                 sockfd;
    char                *icmp_buffer;
    size_t              payload_len;
    size_t              icmp_buffer_len;
    uint16_t            sequence;

} t_ping_context;

typedef struct s_ping_stats {
    double      rtt_min;
    double      rtt_avg;
    double      rtt_max;
    double      rtt_sum;
    size_t      received;
} t_ping_stats;

t_ping_flg flags = {
    .verbose = false,
    .help = false,
    .flood = false,
    .numeric_only = false,
    .count = 0,
    .time_to_live = 0,
    .interval = 1,
    .target = NULL
};

t_ping_stats stats = {
    .rtt_min = DBL_MAX,
    .rtt_avg = 0.0,
    .rtt_max = 0.0,
    .rtt_sum = 0.0,
    .received = 0
};

t_ping_context ctx = {0};


static struct option long_options[] = {
    {"verbose",         no_argument,        0, 'v'},
    {"help",            no_argument,        0, '?'},
    {"flood",           no_argument,        0, 'f'},
    {"numeric_only",    no_argument,        0, 'n'},
    {"interval",        required_argument,  0, 'i'},
    {"count",           required_argument,  0, 'c'},
    {"ttl",             required_argument,  0, SHORT_TTL_IF},
    {0, 0, 0, 0},
};

static void print_help(void)
{
    printf("Usage: ft_ping [OPTION...] HOST ...\n");
    printf("Send ICMP ECHO_REQUEST packets to network hosts.\n");

    printf("\n Options valid for all request types:\n\n");
    printf("  %-28s %s\n", "-c, --count=NUMBER",    "stop after sending NUMBER packets");
    printf("  %-28s %s\n", "-i, --interval=NUMBER", "wait NUMBER seconds between sending each packet");
    printf("  %-28s %s\n", "-n, --numeric",         "do not resolve host addresses");
    printf("  %-28s %s\n", "    --ttl=N",           "specify N as time-to-live");
    printf("  %-28s %s\n", "-v, --verbose",         "verbose output");

    printf("\n Options valid for --echo requests:\n\n");
    printf("  %-28s %s\n", "-f, --flood",           "flood ping (root only)");
    printf("  %-28s %s\n", "-?, --help",            "give this help list");

    printf("\n");
    printf("Mandatory or optional arguments to long options are also mandatory or optional\n");
    printf("for any corresponding short options.\n");
}

static void parse_args(int ac, char **av)
{
    int opt;

    opterr = 0;
    while (true)
    {
        char *endptr;
        opt = getopt_long(ac, av, "v?fnc:i:", long_options, NULL);
        if (opt == -1)
            break;
        switch (opt)
        {
            case 'v':
                flags.verbose = true;
                break;

            case 'f':
                if (flags.interval != 1)
                    exit_on_error(EXIT_FAILURE, false, "-f and -i incompatible options");
                flags.flood = true;
                flags.interval = 0;
                break;

            case 'n':
                flags.numeric_only = true;
                break;

            case '?':

                if (optopt != 0) 
                    exit_on_error(EXIT_FAILURE_USAGE, true, "invalid option -- '%c'", optopt);
                if (av[optind - 1] && av[optind - 1][0] == '-' && av[optind - 1][1] == '-')
                    exit_on_error(EXIT_FAILURE_USAGE, true, "unrecognized option '%s'", av[optind - 1]);

                print_help();
                exit(0);

                break;

            case 'i':
                if (flags.interval == 0)
                    exit_on_error(EXIT_FAILURE, false, "-f and -i incompatible options");
                errno = 0;
                flags.interval = strtod(optarg, &endptr);
                if (*endptr)
                    exit_on_error(EXIT_FAILURE_USAGE, true, "invalid value (`%s' near `%s')", optarg, endptr);
                if (flags.interval < PING_MIN_USER_INTERVAL)
                    exit_on_error(EXIT_FAILURE, false, "option value too small: %s", optarg);
                if (errno == ERANGE || flags.interval > INT_MAX)
                    exit_on_error(EXIT_FAILURE, false, "option value too big: %s", optarg);
                break;

            case 'c':
                long count = strtol(optarg, &endptr, 10);
                if (count < 0)
                    count = 0;
                if (*endptr)
                    exit_on_error(EXIT_FAILURE_USAGE, true, "invalid value (`%s' near `%s')", optarg, endptr);
                flags.count = (errno == ERANGE ? -1 : count);
            break;

            case SHORT_TTL_IF:
                errno = 0;
                unsigned long ttl = strtoul(optarg, &endptr, 10);
                if (*endptr)
                    exit_on_error(EXIT_FAILURE_USAGE, true, "invalid value (`%s' near `%s')", optarg, endptr);
                if (errno == ERANGE || ttl > 255)
                    exit_on_error(EXIT_FAILURE, false, "option value too big: %s", optarg);
                flags.time_to_live = (int)ttl;
            break;

            default:
                exit(64);
                break;
        }
    }
    if (optind < ac)
        flags.target = av[optind];
    else
        exit_on_error(EXIT_FAILURE_USAGE, true, "missing host operand");

}

void    resolve_dns(char *target)
{
    int ret_code;

    struct addrinfo *result;
    struct addrinfo hints = {
        .ai_family = AF_INET,       // Force ipv4 address
        .ai_socktype = SOCK_RAW,    // Raw socket required to build icmp headers
        .ai_protocol = IPPROTO_ICMP // Use icmp protocol
    };

    ret_code = getaddrinfo(target, NULL, &hints, &result);
    if (ret_code != 0)
    {
        if (ret_code == EAI_NONAME)
             exit_on_error(EXIT_FAILURE, false, "unknown host");
        else
            exit_on_error(EXIT_FAILURE, false, "getaddrinfo: %s\n",  gai_strerror(ret_code));
    }

    ctx.addr_len = result->ai_addrlen;

    memcpy(&ctx.addr, result->ai_addr, ctx.addr_len);
    freeaddrinfo(result);
    inet_ntop(AF_INET, &(ctx.addr.sin_addr), ctx.ipv4, INET_ADDRSTRLEN);
}

void setup_context(void)
{
    // Socket creation
    ctx.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ctx.sockfd < 0) {
        if (errno == EACCES || errno == EPERM)
            exit_on_error(EXIT_FAILURE_USAGE, false, "Raw socket need root privilege.");
        else
            exit_on_error(EXIT_FAILURE, false, "Cannot create the socket.");
    }
    // Socket option (ttl & timeout)
    if (flags.time_to_live > 0)
        setsockopt(ctx.sockfd, IPPROTO_IP, IP_TTL, &flags.time_to_live, sizeof(flags.time_to_live));
    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(ctx.sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    // ICMP data
    ctx.payload_len = 56;
    ctx.icmp_buffer_len = ctx.payload_len + ICMP_MINLEN;
    ctx.icmp_buffer = malloc(sizeof(char) * ctx.icmp_buffer_len);
    if (!ctx.icmp_buffer)
        exit_on_error(EXIT_FAILURE, false, "No space left on device");
}

uint16_t checksum(void *addr, size_t len) {
    uint16_t *word = addr;
    uint32_t result = 0;

    for (long unsigned int i = 0; i < len / sizeof(uint16_t); i++)
        result += *(word + i);
    if (len % 2 == 1)
        result += *((uint8_t *)addr + len - 1);
    
    result = (result >> 16) + (result & 0xffff);
    // for specific case
    result = (result >> 16) + (result & 0xffff);
    return ~result;
}


void fill_icmp_buffer(void)
{
    // fill payload data (only timestamp used actually)
    char *data_start = ctx.icmp_buffer + sizeof(struct icmp);
    gettimeofday((struct timeval *)data_start, NULL);
    int start_fill = sizeof(struct timeval);

    for (size_t i = start_fill; i < ctx.payload_len; i++)
        data_start[i] = i + '0';
    
    // fill icmp data
    struct icmp *imsg = (struct icmp *)ctx.icmp_buffer;
    imsg->icmp_type = ICMP_ECHO;
    imsg->icmp_id = htons(getpid());
    imsg->icmp_seq = htons(ctx.sequence);
    // imsg->icmp_code = 0;                    // Already 0 ( Normally needed for echo paaeut)
    imsg->icmp_cksum = checksum(ctx.icmp_buffer, ctx.icmp_buffer_len);
}

void finish_ping(void)
{
    printf("--- %s ping statistics ---\n", flags.target);
    
    int percent_loss = 0;
    if (ctx.sequence > 0)
        percent_loss = ((ctx.sequence - stats.received) * 100) / ctx.sequence;

    printf("%zu packets transmitted, %zu packets received, %d%% packet loss\n", 
        (size_t)ctx.sequence, 
        stats.received, 
        percent_loss);

    if (stats.received > 0)
    {
        stats.rtt_avg = stats.rtt_sum / stats.received;
        
        printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n", 
            stats.rtt_min, 
            stats.rtt_avg, 
            stats.rtt_max);
    }

    free(ctx.icmp_buffer);
}

void singalHandler(int sig)
{
    (void)sig;
    finish_ping();
    exit(0);
}

int main(int ac, char **av)
{
    uint8_t rec_buf[IP_MAXPACKET];

    signal(SIGINT, singalHandler); 
    parse_args(ac, av);
    resolve_dns(flags.target);
    setup_context();
    printf("PING %s (%s): %zu data bytes\n", flags.target, ctx.ipv4, ctx.payload_len);

    while(true) {
        if (flags.count > 0 && ctx.sequence >= flags.count)
            break;
        memset(ctx.icmp_buffer, 0, ctx.icmp_buffer_len);        
        fill_icmp_buffer();
        sendto(ctx.sockfd, ctx.icmp_buffer, ctx.icmp_buffer_len, 0,
            (const struct sockaddr *)&ctx.addr, ctx.addr_len);
        ctx.sequence++;

        memset(rec_buf, 0, IP_MAXPACKET);
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);

        ssize_t bytes_ret = recvfrom(ctx.sockfd, rec_buf, IP_MAXPACKET, 0,
            (struct sockaddr *)&addr, &addr_len);

        if (bytes_ret < 0)
            continue ;
        if ((size_t)bytes_ret < sizeof(struct ip))
            continue ;

        struct ip *ip = (struct ip *)rec_buf;
        int ip_len = ip->ip_hl * 4;

        if ((size_t)bytes_ret < ip_len + sizeof(struct icmp))
            continue ;

        struct icmp *icmp = (struct icmp *)(rec_buf + ip_len);

  

        // Need switch case to handle 
        if (icmp->icmp_type == ICMP_ECHOREPLY) {
            if (icmp->icmp_id != htons(getpid()))
                continue;
        }
        else
            continue;


        /* TODO
         *  
         * 
         *  Implement all flags :
         *  [ ] *-v* flag verbose
         *  [x] *-c* flag count qui stop apres N ping                               
         *  [x] *-i* flag interval, change le temps entre deux ping                 
         *  [x] *-f* flag flood, spam de ping sans attendre                         
         *  [ ] *-W* Time out on recvftom
         *      [ ] Parsing
         *      [ ] init + handling on icmp reply flag
         *  [ ] *-ttl* flag set time to live, mandatory pour traceroute             
         *      [ ] handle multiple ICMP reply type
         * 
         */

        // int headers_size = ip_len + sizeof(struct icmp);

        // // On vérifie qu'il reste assez de place pour contenir un struct timeval
        // if (bytes_ret < headers_size + sizeof(struct timeval)) {
        //     // Le paquet est valide (bon checksum/type) mais il ne contient pas de timestamp !
        //     // On ne peut pas calculer le RTT.
        //     return; // Ou continue
        // }

        struct timeval *start_time = (struct timeval *)((char *)icmp + sizeof(struct icmp));
        struct timeval end_time;
        gettimeofday(&end_time, NULL);

        double rtt_in_us = (double)(end_time.tv_sec - start_time->tv_sec) * 1e6 +
                          (double)(end_time.tv_usec - start_time->tv_usec);
        
        double time_to_sleep = (flags.interval * 1e6) - rtt_in_us;

        if (time_to_sleep > 0 && !flags.flood)
            usleep((useconds_t)time_to_sleep);
        

        // 64 bytes from 172.217.171.238: icmp_seq=2 ttl=116 time=10.692 ms
        printf("%zu bytes from %s: icmp_seq=%d ttl= time=%.3f ms\n", (bytes_ret - ip_len), ctx.ipv4,  ntohs(icmp->icmp_seq), rtt_in_us);

    }
    finish_ping();
    return 0;
}

    // printf("Target: %s\n", flags.target);
    // printf("Resolved IP: %s\n", ctx.ipv4);