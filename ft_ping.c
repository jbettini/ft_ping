#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>

#define SHORT_TTL_IF 1000
#define PING_MIN_USER_INTERVAL (0.2)
#define EXIT_FAILURE 1
#define EXIT_FAILURE_USAGE 64

#define exit_on_error(code, usage_msg, fmt, ...) do { \
    fprintf(stderr, "ping: "); \
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
    char         time_to_live;
    double      interval;
    size_t      count;
    char        *target;
} t_ping;

t_ping flags = {
    .verbose = false,
    .help = false,
    .flood = false,
    .numeric_only = false,
    .count = 0,
    .time_to_live = 0,
    .interval = 1,
    .target = NULL
};

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
                errno = 0;
                flags.interval = strtod(optarg, &endptr);
                if (*endptr)
                    exit_on_error(EXIT_FAILURE_USAGE, true, "invalid value (`%s' near `%s')", optarg, endptr);
                if (flags.interval < PING_MIN_USER_INTERVAL)
                    exit_on_error(EXIT_FAILURE, false, "option value too small: %s", optarg);
                if (errno == ERANGE || flags.interval > INT_MAX)
                    exit_on_error(EXIT_FAILURE, false, "option value too big: %s", optarg);
                if (flags.interval == 0)
                    exit_on_error(EXIT_FAILURE, false, "-f and -i incompatible options");
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

int main(int ac, char **av)
{
    parse_args(ac, av);
    return 0;
}