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
#include <sys/types.h>

#define SHORT_TTL_IF 1000
#define PING_MIN_USER_INTERVAL (0.2)
#define EXIT_FAILURE 1
#define EXIT_FAILURE_USAGE 64
#define MAXIPLEN 60
#define MAXICMPLEN 76
#define PING_MAX_DATALEN (65535 - MAXIPLEN - MAXICMPLEN)
#define DEFAULT_PAYLOAD_LEN 56

#define exit_on_error(code, usage_msg, fmt, ...) do { \
    fprintf(stderr, "ft_ping: "); \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    fprintf(stderr, "\n"); \
    if (usage_msg) \
        fprintf(stderr, "Try 'ping --help' or 'ping --usage' for more information.\n"); \
    exit(code); \
} while(0)


size_t err_nb = 0;
#define debug_err() do { \
    printf("%d\n", __LINE__); \
    err_nb++; \
} while(0)

typedef struct s_ping {
    bool        verbose;
    bool        help;
    bool        flood;
    int         time_to_live;
    double      interval;
    size_t      count;
    size_t      size;
    char        *target;
} t_ping_flg;

typedef struct s_ping_context {
    char                ipv4[INET_ADDRSTRLEN];
    char                *icmp_buffer;
    bool                size_permit_rtt;
    bool                running;
    int                 sockfd;
    size_t              icmp_buffer_len;
    uint16_t            sequence;
    socklen_t           addr_len;
    struct sockaddr_in  addr;

} t_ping_context;

typedef struct s_ping_stats {
    double      rtt_min;
    double      rtt_avg;
    double      rtt_max;
    double      rtt_sum;
    size_t      received;
} t_ping_stats;

struct icmp_code_descr
{
  int type;
  int code;
  char *diag;
} icmp_code_descr[] =
  {
    {ICMP_DEST_UNREACH, ICMP_NET_UNREACH, "Destination Net Unreachable"},
    {ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, "Destination Host Unreachable"},
    {ICMP_DEST_UNREACH, ICMP_PROT_UNREACH, "Destination Protocol Unreachable"},
    {ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, "Destination Port Unreachable"},
    {ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, "Fragmentation needed and DF set"},
    {ICMP_DEST_UNREACH, ICMP_SR_FAILED, "Source Route Failed"},
    {ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN, "Network Unknown"},
    {ICMP_DEST_UNREACH, ICMP_HOST_UNKNOWN, "Host Unknown"},
    {ICMP_DEST_UNREACH, ICMP_HOST_ISOLATED, "Host Isolated"},
    {ICMP_DEST_UNREACH, ICMP_NET_UNR_TOS, "Destination Network Unreachable At This TOS"},
    {ICMP_DEST_UNREACH, ICMP_HOST_UNR_TOS, "Destination Host Unreachable At This TOS"},
    {ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, "Time to live exceeded"},
    {ICMP_TIME_EXCEEDED, ICMP_EXC_FRAGTIME, "Frag reassembly time exceeded"},
    {0, 0, NULL}
};

t_ping_flg flags = {
    .verbose = false,
    .help = false,
    .flood = false,
    .count = 0,
    .size = DEFAULT_PAYLOAD_LEN,
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

static inline void check_invalid_value(char *optarg, char *endptr)
{
    if (*endptr)
        exit_on_error(EXIT_FAILURE_USAGE, true, "invalid value (`%s' near `%s')", optarg, endptr);
}

static inline void check_value_too_big(bool condition, char *optarg)
{
    if (condition)
        exit_on_error(EXIT_FAILURE, false, "option value too big: %s", optarg);
}

static inline struct ip *get_ip_from_buffer(uint8_t *rec_buf)
{
    return (struct ip *)rec_buf;
}

static inline int get_ip_len(struct ip *ip)
{
    return ip->ip_hl * 4;
}

static inline struct ip *err_to_ori_ip(uint8_t *err_icmp)
{
    return (struct ip *)(err_icmp + ICMP_MINLEN);
}

static inline struct icmp *err_to_ori_icmp(uint8_t *err_icmp)
{
    struct ip *ori_ip = err_to_ori_ip(err_icmp);
    int ip_len = get_ip_len(ori_ip);
    
    return (struct icmp *)((uint8_t *)ori_ip + ip_len);
}

static void parse_args(int ac, char **av)
{
    int opt;

    opterr = 0;
    while (true)
    {
        char *endptr;
        opt = getopt_long(ac, av, "v?fs:c:i:", long_options, NULL);
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
                check_invalid_value(optarg, endptr);
                
                if (flags.interval < PING_MIN_USER_INTERVAL)
                    exit_on_error(EXIT_FAILURE, false, "option value too small: %s", optarg);
                check_value_too_big(errno == ERANGE || flags.interval > INT_MAX, optarg);
                break;

            case 'c':
                long count = strtol(optarg, &endptr, 10);
                if (count < 0)
                    count = 0;
                check_invalid_value(optarg, endptr);
                flags.count = (errno == ERANGE ? -1 : count);
            break;

            case SHORT_TTL_IF:
                errno = 0;
                unsigned long ttl = strtoul(optarg, &endptr, 10);
                check_invalid_value(optarg, endptr);
                check_value_too_big(errno == ERANGE || ttl > 255, optarg);
                flags.time_to_live = (int)ttl;
            break;

            case 's':
                errno = 0;
                flags.size = strtoul(optarg, &endptr, 0);
                check_invalid_value(optarg, endptr);
                check_value_too_big(errno == ERANGE || (PING_MAX_DATALEN && flags.size > PING_MAX_DATALEN), optarg);
                break;

            default:
                exit(EXIT_FAILURE_USAGE);
                break;
        }
    }
    if (optind < ac)
        flags.target = av[optind];
    else
        exit_on_error(EXIT_FAILURE_USAGE, true, "missing host operand");

}

static void resolve_dns(char *target)
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
            exit_on_error(EXIT_FAILURE, false, "getaddrinfo: %s",  gai_strerror(ret_code));
    }

    ctx.addr_len = result->ai_addrlen;

    memcpy(&ctx.addr, result->ai_addr, ctx.addr_len);
    freeaddrinfo(result);
    inet_ntop(AF_INET, &(ctx.addr.sin_addr), ctx.ipv4, INET_ADDRSTRLEN);
}

static void setup_context(void)
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
    ctx.size_permit_rtt = (flags.size >= sizeof(struct timeval));
    ctx.icmp_buffer_len = flags.size + ICMP_MINLEN;

    ctx.icmp_buffer = malloc(sizeof(char) * ctx.icmp_buffer_len);
    if (!ctx.icmp_buffer)
        exit_on_error(EXIT_FAILURE, false, "No space left on device");

    ctx.running = true;
    ctx.sequence = 1;

}

static uint16_t checksum(void *addr, size_t len) {
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


static void fill_icmp_buffer(void)
{
    size_t start_fill = 0;
    // fill payload data (only timestamp used actually)
    char *data_start = ctx.icmp_buffer + sizeof(struct icmp);
    if (ctx.size_permit_rtt) {
        gettimeofday((struct timeval *)data_start, NULL);
        start_fill = sizeof(struct timeval);
    }
    for (size_t i = start_fill; i < flags.size; i++)
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

    if (stats.received > 0 && ctx.size_permit_rtt)
    {
        stats.rtt_avg = stats.rtt_sum / stats.received;
        
        printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n", 
            stats.rtt_min / 1000.0, 
            stats.rtt_avg / 1000.0, 
            stats.rtt_max / 1000.0);
    }
    if (!ctx.icmp_buffer || ctx.sockfd == -1)
        exit_on_error(EXIT_FAILURE, false, "WTF is happening bro ??");
    close(ctx.sockfd);
    ctx.sockfd = -1;
    free(ctx.icmp_buffer);
    ctx.icmp_buffer = NULL;
}

void singalHandler(int sig)
{
    (void)sig;
    ctx.running = false;
}



// Separate Prompt and wait and update stats

// static inline prompt()
// {

// }

static void wait_and_prompt(ssize_t bytes_ret, uint8_t *rec_buf, struct icmp *icmp)
{
    double rtt_in_us = 0;
    
    struct ip *ip = get_ip_from_buffer(rec_buf);
    int ip_len = get_ip_len(ip);
    size_t headers_size = ip_len + sizeof(struct icmp);
    
    bool rtt_is_calculable = ((size_t)bytes_ret >= headers_size + sizeof(struct timeval) && ctx.size_permit_rtt);

    if (rtt_is_calculable) {
        struct timeval *start_time = (struct timeval *)((char *)icmp + sizeof(struct icmp));
        struct timeval end_time;
        gettimeofday(&end_time, NULL);
    
        rtt_in_us = (double)(end_time.tv_sec - start_time->tv_sec) * 1e6 +
                    (double)(end_time.tv_usec - start_time->tv_usec);
        stats.rtt_sum += rtt_in_us;
        if (rtt_in_us < stats.rtt_min)
            stats.rtt_min = rtt_in_us;
        if (rtt_in_us > stats.rtt_max)
            stats.rtt_max = rtt_in_us;
    }

    double time_to_sleep = (flags.interval * 1e6) - rtt_in_us;
    if (time_to_sleep > 0 && !flags.flood)
        usleep((useconds_t)time_to_sleep);

    printf("%zu bytes from %s: icmp_seq=%d ttl=%d", (bytes_ret - ip_len), ctx.ipv4, ntohs(icmp->icmp_seq), ip->ip_ttl);

    if (rtt_is_calculable)
        printf(" time=%.3f ms", rtt_in_us / 1000.0);
    printf("\n");
}

static struct icmp *check_recv_ret(ssize_t bytes_ret, uint8_t *rec_buf)
{
    if ((size_t)bytes_ret < sizeof(struct ip))
        return NULL;

    struct ip *ip = get_ip_from_buffer(rec_buf);
    int ip_len = get_ip_len(ip);
    if (bytes_ret < ip_len + ICMP_MINLEN)
        return NULL;

    return (struct icmp *)(rec_buf + ip_len);
}


static void send_ping(void) 
{
    memset(ctx.icmp_buffer, 0, ctx.icmp_buffer_len);        
    fill_icmp_buffer();

    int send_ret = sendto(ctx.sockfd, ctx.icmp_buffer, ctx.icmp_buffer_len, 0,
                    (struct sockaddr *)&ctx.addr, ctx.addr_len);
    // (void)send_ret;
    if (send_ret < 0) {
        if (errno == ENETUNREACH)
            exit_on_error(EXIT_FAILURE, false, "sending packet: Network is unreachable");
        else
            fprintf(stderr, "ft_ping: sendto: %s\n", strerror(errno));
    }
    ctx.sequence++;
}

static char *handle_imcp_error(struct icmp* icmp)
{
    for (int i = 0; icmp_code_descr[i].diag; i++) {
        struct icmp_code_descr current = icmp_code_descr[i];
        if (icmp->icmp_type == current.type && 
            icmp->icmp_code == current.code)
            return current.diag;
    }
    return "Unknow icmp error code/type.";
}


static void recv_pong(void)
{
    ssize_t bytes_ret = 0;
    struct icmp *icmp = NULL;
    uint8_t rec_buf[IP_MAXPACKET];

    while (ctx.running) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        memset(rec_buf, 0, IP_MAXPACKET);
        bytes_ret = recvfrom(ctx.sockfd, rec_buf, IP_MAXPACKET, 0,
                                (struct sockaddr *)&addr, &addr_len);
        if (bytes_ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break; 
            if (errno == EINTR) 
                break;
            continue;
        }
        icmp = check_recv_ret(bytes_ret, rec_buf);
        if (!icmp)
            continue ;
        switch (icmp->icmp_type )
        {
            case ICMP_ECHOREPLY:
                if (icmp->icmp_id != htons(getpid()))
                    continue;
                // if (!flags.flood)
                wait_and_prompt(bytes_ret, rec_buf, icmp);
                stats.received++;
                return;
            case ICMP_DEST_UNREACH:
                struct ip *ip = get_ip_from_buffer(rec_buf);
                struct icmp *original_icmp = err_to_ori_icmp((uint8_t *)icmp);
                if (original_icmp->icmp_id != htons(getpid()))
                    continue;
                fprintf(stderr, "From %s: icmp_seq=%u %s\n", 
                       inet_ntoa(ip->ip_src), 
                       ntohs(original_icmp->icmp_seq), 
                       handle_imcp_error(icmp));
                break;
            
            default:
                break;
        }
    }
}

int main(int ac, char **av)
{
    parse_args(ac, av);
    signal(SIGINT, singalHandler); 
    resolve_dns(flags.target);
    setup_context();
    printf("PING %s (%s): %zu data bytes\n", flags.target, ctx.ipv4, flags.size);

    while(ctx.running) {
        if (flags.count > 0 && ctx.sequence >= flags.count)
            break;
        send_ping();
        recv_pong();

    }
    finish_ping();
    return EXIT_SUCCESS;
}

/* TODO
 * 
 *  Implement all flags :
 *  [x] ECHO_UNREACHEABLE
 *  [ ] *-ttl* flag set time to live, mandatory pour traceroute             
 *      [ ] ECHO TIME EXCEED 
 *  [ ] *-v* flag verbose
 *      [ ] horrible
 * [ ] separate prompt wait and stats
 *  [ ] Get same output for -f than real ping
 * 
 */