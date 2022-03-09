/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_options.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 23:11:55 by yforeau           #+#    #+#             */
/*   Updated: 2022/03/09 02:05:51 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

#define	FT_NMAP_OPT	"df:hi:p:S:s:v46"

const t_opt	g_nmap_opt[] = {
	{ "debug",					0,	NULL,	'd'	},
	{ "file",					1,	NULL,	'f'	},
	{ "help",					0,	NULL,	'h'	},
	{ "interface",				1,	NULL,	'i'	},
	{ "ports",					1,	NULL,	'p'	},
	{ "speedup",				1,	NULL,	'S'	},
	{ "scan",					1,	NULL,	's'	},
	{ "verbose",				0,	NULL,	'v'	},
	{ "ipv4",					0,	NULL,	'4'	},
	{ "ipv6",					0,	NULL,	'6'	},
	{ "complete",				0,	NULL,	1	},
	{ "heatmap",				0,	NULL,	2	},
	{ "range",					0,	NULL,	3	},
	{ "max-retries",			1,	NULL,	4	},
	{ "scan-delay",				1,	NULL,	5	},
	{ "initial-rtt-timeout",	1,	NULL,	6	},
	{ "min-rtt-timeout",		1,	NULL,	7	},
	{ "max-rtt-timeout",		1,	NULL,	8	},
	{ "disable-backoff",		0,	NULL,	9	},
	{ "disable-ping",			0,	NULL,	10	},
	{ "skip-non-responsive",	0,	NULL,	11	},
	{ NULL,						0,	NULL,	0	},
};

const char	*g_nmap_help[] = {
	"Show debugging information about posix threads and ft_nmap tasks. Also\n"
	"\t\tprint packets that do not match any valid probe (filter failures).",
	"File containing a list of hosts to scan (1 per line).",
	"Print this and exit.",
	"Select interface on which to listen on.",
	"Ports to scan specified as a comma separated list of individual ports or\n"
	"\t\tranges (eg: 80,22,1024-2048). The default is 1-1024.",
	"Number of parallel threads to use (def: " xstr(DEF_SPEEDUP)
	", min: " xstr(MIN_SPEEDUP) ", max: " xstr(MAX_SPEEDUP) ").",
	"Scans to perform specified as a comma separated list. Possible values:\n"
	"\t\t'SYN/ACK/NULL/FIN/XMAS/UDP' (eg: SYN,UDP). It is possible to only\n"
	"\t\tuse one letter by scan (eg: '-sA' for ACK). Does them all by default.",
	"Show probe packets, replies and timeouts.",
	"Use only IPv4.",
	"Use only IPv6.",
	"Show every port and scan type in the final host report. It has no effect\n"
	"\t\tif used with an other report mode than the default.",
	"Heatmap report. Shows a heat map of every port in a grid. Ports go from\n"
	"\t\tred to green depending on how filtered or open they are.",
	"Range report. This will show each scan as a range of ports on every\n"
	"\t\toutcome state instead of the default port table.",
	"Set max number of retries to for sending a probe (def: " xstr(DEF_RETRIES)
	", min: " xstr(MIN_RETRIES) ", max: " xstr(MAX_RETRIES) ").",
	"Adjust delay between probes.",
	"Set initial time to wait for a probe to respond before retry or timeout.",
	"Set minimum value of the RTT timeout.",
	"Set maximum value of the RTT timeout.",
	"Disable UDP probe backoff in case of ICMP rate limit.",
	"Disable ping echo scans.",
	"Skip hosts that do not respond to echo scans.",
	NULL,
};

const char	*g_nmap_usage[] = {
	"[-dhv46] [-f file_path] [-i interface] [-p port_list] [-S speedup]\n"
	"\t\t[-s scan_list] [--complete | --heatmap | --range]\n"
	"\t\t[--max-retries retries] [--scan-delay time]\n"
	"\t\t[--initial-rtt-timeout time] [--min-rtt-timeout time]\n"
	"\t\t[--max-rtt-timeout time] [--disable-backoff] [--disable-ping]\n"
	"\t\t[--skip-non-responsive] host ...",
	NULL,
};

const char	*g_description =
"\tThe host arguments can either be IPv4, IPv6 addresses, hosts as defined\n"
"\tin the /etc/hosts file or domain names. ft_nmap will loop on them until\n"
"\tno argument is left. Then it will look at the --file option value if it\n"
"\twas given and do the same. The host file format is one host per line.\n"
"\n\tOptions that take a 'time' value are in milliseconds by default. They\n"
"\tcan be appended a time unit which will be one of: us (microseconds),\n"
"\tms (milliseconds), s (seconds), m (minutes) or h (hours).\n"
"\n\tEach scan type given in scan list is a column in the final host report\n"
"\tand a series of letters is used to describe the result of a port scan:\n\n"
"\tO --> Open\n"
"\tC --> Closed\n"
"\tU --> Unfiltered\n"
"\tF --> Filtered\n"
"\tOF --> Open|Filtered\n\n"
"\tPossible responses and states by scan type:\n"
"\n\tSYN:\n"
"\tOpen --> tcp SYN or tcp SYN/ACK\n"
"\tClosed --> tcp RST\n"
"\tFiltered --> icmp type 3 code 0/1/2/3/9/10/13 or timeout\n"
"\n\tACK:\n"
"\tUnfiltered --> tcp RST\n"
"\tFiltered --> icmp type 3 code 0/1/2/3/9/10/13 or timeout\n"
"\n\tUDP:\n"
"\tOpen --> udp\n"
"\tClosed --> icmp type 3 code 3\n"
"\tFiltered --> icmp type 3 code 0/1/2/9/10/13\n"
"\tOpen|Filetered --> timeout\n"
"\n\tNULL, FIN, XMAS:\n"
"\tClosed --> tcp RST\n"
"\tFiltered --> icmp type 3 code 0/1/2/3/9/10/13\n"
"\tOpen|Filetered --> timeout\n";

void		get_options(t_nmap_config *cfg, int argc, char **argv)
{
	int			opt;
	t_optdata	o = { 0 };

	init_getopt(&o, FT_NMAP_OPT, (t_opt *)g_nmap_opt, NULL);
	if (ft_strlen(cfg->exec) <= ft_strlen(argv[0]))
		ft_strcpy(argv[0], cfg->exec);
	while ((opt = ft_getopt_long(argc, argv, &o)) >= 0)
		switch (opt)
		{
			case 'd': ++cfg->debug;										break;
			case 'f': cfg->hosts_file = o.optarg;						break;
			case 'i': cfg->dev = o.optarg;								break;
			case 'p': parse_ports(cfg, o.optarg, set_scan_ports, NULL);	break;
			case 'S': cfg->speedup = parse_int(o.optarg, MIN_SPEEDUP,
				MAX_SPEEDUP, "argument");								break;
			case 's': scan_option(cfg, &o);								break;
			case 'v': ++cfg->verbose;									break;
			case '4': cfg->ip_mode = E_IPV4;							break;
			case '6': cfg->ip_mode = E_IPV6;							break;
			case 1: ++cfg->complete;									break;
			case 2: cfg->report = E_REPORT_HEATMAP;						break;
			case 3: cfg->report = E_REPORT_RANGE;						break;
			case 4: cfg->retries = parse_int(o.optarg, MIN_RETRIES,
				MAX_RETRIES, "argument");								break;
			case 5: str_to_timeval(&cfg->scan_delay, o.optarg);			break;
			case 6:
				str_to_timeval(&cfg->rtt.initial_timeout, o.optarg);	break;
			case 7: str_to_timeval(&cfg->rtt.min_timeout, o.optarg);	break;
			case 8: str_to_timeval(&cfg->rtt.max_timeout, o.optarg);	break;
			case 9: cfg->exponential_backoff = 0;						break;
			case 10: cfg->ping_scan = 0;								break;
			case 11: cfg->skip_non_responsive = 1;						break;
			default: usage(cfg->exec, opt != 'h');
		}
	cfg->hosts = argv + o.optind;
}
