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
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <float.h>
#include <signal.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#define SHORT_TTL_IF 1000
#define PING_MIN_USER_INTERVAL (0.2)
#define EXIT_FAILURE 1
#define EXIT_FAILURE_USAGE 64
#define MAXIPLEN 60
#define INT_MAX	2147483647
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
    int                 proc_pid;
    size_t              icmp_buffer_len;
    uint16_t            sequence;
    uint16_t            transmited;
    socklen_t           addr_len;
    struct sockaddr_in  addr;

} t_ping_context;

typedef struct s_ping_stats {
    bool        calulated;
    double      current_rtt;
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
    .calulated = false,
    .current_rtt = 0.0,
    .rtt_min = DBL_MAX,
    .rtt_avg = 0.0,
    .rtt_max = 0.0,
    .rtt_sum = 0.0,
    .received = 0,
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

static inline struct icmp *get_icmp_header(uint8_t *buf)
{
    struct ip *ip = (struct ip *)buf;
    return (struct icmp *)(buf + (ip->ip_hl << 2));
}

static inline size_t get_ip_len(struct ip *ip) {return ip->ip_hl << 2;}

static inline struct ip   *get_ip_header(void *buf) {return (struct ip *)buf;}

static inline struct ip   *get_orig_ip(struct icmp *icmp_err) {return (struct ip *)((uint8_t *)icmp_err + 8);}

static inline struct icmp *get_orig_icmp(struct ip *orig_ip) {return (struct icmp *)((uint8_t *)orig_ip + get_ip_len(orig_ip));}

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

            case 'c': {
                long count = strtol(optarg, &endptr, 10);
                if (count < 0)
                    count = 0;
                check_invalid_value(optarg, endptr);
                flags.count = (errno == ERANGE ? -1 : count);
            }
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
    // Socket option (ttl, timeout)
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
    ctx.proc_pid = getpid();
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
    imsg->icmp_id = htons(ctx.proc_pid);
    imsg->icmp_seq = htons(ctx.sequence);
    // imsg->icmp_code = 0;                    // Already 0 ( Normally needed for echo paaeut)
    imsg->icmp_cksum = checksum(ctx.icmp_buffer, ctx.icmp_buffer_len);
}

void finish_ping(void)
{
    printf("--- %s ping statistics ---\n", flags.target);
    
    int percent_loss = 0;
    if (ctx.transmited > 0)
        percent_loss = ((ctx.transmited - stats.received) * 100) / ctx.transmited;

    printf("%d packets transmitted, %zu packets received, %d%% packet loss\n", 
        ctx.transmited, 
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

void singalHandler(int sig) {(void)sig; ctx.running = false;}

static char *handle_imcp_error(int reply_type, int reply_code)
{
    for (int i = 0; icmp_code_descr[i].diag; i++) {
        struct icmp_code_descr current = icmp_code_descr[i];
        if (reply_type == current.type && 
            reply_code == current.code)
            return current.diag;
    }
    return "Unknow icmp error code/type ";
}

static inline bool is_rtt_calculable(ssize_t bytes_ret, int ip_len)
{
    size_t headers_size = ip_len + sizeof(struct icmp);

    return ((size_t)bytes_ret >= headers_size + sizeof(struct timeval) && ctx.size_permit_rtt);
}

static void dumo_ip_hdr(struct icmp *icmp) {
    struct ip *o = get_orig_ip(icmp);
    struct icmp *oi = get_orig_icmp(o);
    uint16_t *p = (uint16_t *)o;
    char s[16], d[16];

    printf("IP Hdr Dump:\n ");
    for (int i = 0; i < 10; i++)
        printf("%04x ", ntohs(p[i]));
    inet_ntop(AF_INET, &o->ip_src, s, 16);
    inet_ntop(AF_INET, &o->ip_dst, d, 16);
    printf("\nVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n"
           " %1x  %1x  %02x %04x %04x %1x %04x  %02x  %02x %04x %s  %s \n",
           o->ip_v, o->ip_hl, o->ip_tos, ntohs(o->ip_len), ntohs(o->ip_id),
           ntohs(o->ip_off) >> 13, ntohs(o->ip_off) & 0x1fff, o->ip_ttl, o->ip_p, ntohs(o->ip_sum), s, d);
    printf("ICMP: type %d, code %d, size %ld, id 0x%04x, seq 0x%04x",
           oi->icmp_type, oi->icmp_code, ntohs(o->ip_len) - get_ip_len(o), 
           ntohs(oi->icmp_id), ntohs(oi->icmp_seq));
}


static inline void prompt_icmp_reply(
    struct icmp *icmp,
    int data_len,
    struct ip *ip,
    bool rtt_is_calculable)
{
    char pr_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_src), pr_addr, INET_ADDRSTRLEN);

    if (flags.flood)
        return;
    printf("%d bytes from %s", data_len, pr_addr);

    switch (icmp->icmp_type) {
        case ICMP_ECHOREPLY:
        {
            printf(": icmp_seq=%d ttl=%d", ntohs(icmp->icmp_seq), ip->ip_ttl);
            if (rtt_is_calculable)
                printf(" time=%.3f ms", stats.current_rtt / 1000.0);
            break;
        }
        case ICMP_TIME_EXCEEDED:
        {
            printf(": %s", handle_imcp_error(icmp->icmp_type, icmp->icmp_code));
            if (flags.verbose)
                dumo_ip_hdr(icmp);
            break;
        }
        default: 
            fprintf(stderr, "ft_ping: unknow reply type: %s (%d/%d) ",
                handle_imcp_error(icmp->icmp_type, icmp->icmp_code),
                icmp->icmp_type,
                icmp->icmp_code);
            break;
    }
    printf("\n");
}

static void update_stats(struct icmp *icmp, bool rtt_is_calculable, uint8_t type)
{
    stats.current_rtt = 0;
    if (type == ICMP_ECHOREPLY)
        stats.received++;
    if (rtt_is_calculable) {
        struct timeval *start_time = (struct timeval *)((char *)icmp + sizeof(struct icmp));
        struct timeval end_time;
        gettimeofday(&end_time, NULL);
    
        stats.current_rtt = (double)(end_time.tv_sec - start_time->tv_sec) * 1e6 +
                    (double)(end_time.tv_usec - start_time->tv_usec);
        stats.rtt_sum += stats.current_rtt;
        if (stats.current_rtt < stats.rtt_min)
            stats.rtt_min = stats.current_rtt;
        if (stats.current_rtt > stats.rtt_max)
            stats.rtt_max = stats.current_rtt;
    }
}

static inline void wait_next_ping(void)
{
    if (flags.flood)
        return;
    double time_to_sleep = (flags.interval * 1e6) - stats.current_rtt;
    if (time_to_sleep > 0)
        usleep((useconds_t)time_to_sleep);
}

static void send_ping(void) 
{
    memset(ctx.icmp_buffer, 0, ctx.icmp_buffer_len);        
    fill_icmp_buffer();

    int send_ret = sendto(ctx.sockfd, ctx.icmp_buffer, ctx.icmp_buffer_len, 0,
                    (struct sockaddr *)&ctx.addr, ctx.addr_len);
    if (send_ret < 0) {
        if (errno == ENETUNREACH)
            exit_on_error(EXIT_FAILURE, false, "sending packet: Network is unreachable");
        else
            exit_on_error(EXIT_FAILURE, false, "sending packet: %s", strerror(errno));
            /* 
             * Exiting here kills the diagnostic like inetutils
             * Print the error and to keep cycle alive and reflect real network state (iputils style) 
             */
    }
    ctx.sequence++;
    ctx.transmited++;
}

static void recv_pong(void)
{
    uint8_t rec_buf[IP_MAXPACKET];
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    while (ctx.running) {
        memset(rec_buf, 0, IP_MAXPACKET);
        ssize_t bytes_ret = recvfrom(ctx.sockfd, rec_buf, IP_MAXPACKET, 0,
                                     (struct sockaddr *)&addr, &addr_len);
        if (bytes_ret < 0) {
            if (errno == EWOULDBLOCK)
                break;
            continue;
        }
        else if ((size_t)bytes_ret < sizeof(struct ip))
            continue;
        else {
            struct ip *ip = get_ip_header(rec_buf);
            int ip_len = get_ip_len(ip);

            if (bytes_ret < ip_len + ICMP_MINLEN)
                continue;
    
            struct icmp *recv_icmp = get_icmp_header(rec_buf);
            bool rtt_is_calculable = is_rtt_calculable(bytes_ret, ip_len);

            switch (recv_icmp->icmp_type) {
                case ICMP_ECHOREPLY:
                    if (recv_icmp->icmp_id != htons(ctx.proc_pid))
                        continue;
                    update_stats(recv_icmp, rtt_is_calculable, recv_icmp->icmp_type);
                    break;
                case ICMP_DEST_UNREACH:
                case ICMP_TIME_EXCEEDED:
                {
                    struct icmp *o_icmp = get_orig_icmp(get_orig_ip(recv_icmp));
                    if (o_icmp->icmp_id != htons(ctx.proc_pid))
                        continue;
                    break;
                }
                default:
                    if (flags.verbose)
                        printf("Unrecognized ICMP type %d\n", recv_icmp->icmp_type);
                    continue;
            }
            prompt_icmp_reply(recv_icmp, bytes_ret - ip_len, ip, rtt_is_calculable);
            return;
        }
    }
}

int main(int ac, char **av)
{
    parse_args(ac, av);
    signal(SIGINT, singalHandler); 
    resolve_dns(flags.target);
    setup_context();
    
    printf("PING %s (%s): %zu data bytes", flags.target, ctx.ipv4, flags.size);
    if (flags.verbose)
        printf(", 0x%x = %d", ctx.proc_pid, ctx.proc_pid);
    printf("\n");

    while(ctx.running) {
        if (flags.count > 0 && ctx.transmited >= flags.count)
            break;
        send_ping();
        recv_pong();
        wait_next_ping();
    }
    finish_ping();
    return EXIT_SUCCESS;
}