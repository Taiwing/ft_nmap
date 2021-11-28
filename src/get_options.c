/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_options.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 23:11:55 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/28 06:49:09 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

#define	FT_NMAP_OPT	"df:hi:p:S:s:t:v46"

t_opt	g_nmap_opt[] = {
	{ "debug",		0,	NULL,	'd' },
	{ "file",		1,	NULL,	'f'	},
	{ "help",		0,	NULL,	'h'	},
	{ "interface",	1,	NULL,	'i'	},
	{ "ports",		1,	NULL,	'p'	},
	{ "scan",		1,	NULL,	'S'	},
	{ "speedup",	1,	NULL,	's'	},
	{ "target",		1,	NULL,	't'	},
	{ "verbose",	0,	NULL,	'v'	},
	{ "ipv4",		0,	NULL,	'4'	},
	{ "ipv6",		0,	NULL,	'6'	},
	{ NULL,			0,	NULL,	0	},
};

char	*g_nmap_help[] = {
	"Show debugging information about pcap filters and posix threads. Also\n"
	"\t\tprint packets that do not match any valid probe (filter failure).",
	"File containing a list of hosts to scan (1 per line).",
	"Print this and exit.",
	"Select interface on which to listen on.\n",
	"Ports to scan specified as a comma separated list of individual ports or\n"
	"\t\tranges (eg: 80,22,1024-2048). The default is 1-1024.",
	"Scans to perform specified as a comma separated list. Possible values:\n"
	"\t\t'SYN/NULL/FIN/XMAS/ACK/UDP' (eg: SYN,UDP). Does them all by default.",
	"Number of parallel threads to use (def: 0, max: " xstr(MAX_SPEEDUP) ").",
	"Hosts to scan specified as a comma separated list of IPv4-IPv6 addresses\n"
	"\t\tor hostnames (eg: localhost,192.168.1.0/24,2001::ffff).",
	"Show probe packets, replies and timeouts.",
	"Use only IPv4.",
	"Use only IPv6.",
	NULL,
};

char	*g_nmap_usage[] = {
	"[-dhv46] [-f path] [-p list] [-S list] [-s number] [-i iface] -t list",
	"[-dhv46] [-t list] [-p list] [-S list] [-s number] [-i iface] -f path",
	NULL,
};

char	*g_description =
"\tEach scan type given in scan list is a column in the final host report\n"
"\tand a series of letters is used to describe the result of a port scan:\n\n"
"\tO --> Open\n"
"\tC --> Closed\n"
"\tF --> Filtered\n"
"\tU --> Unfiltered\n";

static void	usage(const char *exec, int exit_value)
{
	t_opt	*opts = g_nmap_opt;
	char	**help = g_nmap_help;
	char	**usage = g_nmap_usage;

	ft_printf("Usage:\n");
	while (*usage)
	{
		ft_printf("\t%s %s\n", exec, *usage);
		++usage;
	}
	ft_printf("\nOptions:\n");
	while (opts->name && *help)
	{
		ft_printf("\t-%c, --%s\n", opts->val, opts->name);
		ft_printf("\t\t%s\n", *help);
		++opts;
		++help;
	}
	ft_printf("\nDescription:\n%s", g_description);
	ft_exit(exit_value, NULL);
}


void		intopt(int *dest, const char *arg, int min, int max)
{
	int	ret;

	if ((ret = ft_secatoi(dest, min, max, arg)))
	{
		if (ret == FT_E_NOT_A_NUMBER)
			ft_exit(EXIT_FAILURE, "invalid argument: '%s'", arg);
		else
			ft_exit(EXIT_FAILURE, "invalid argument: '%s': "
				"out of range: %d <= value <= %d", arg, min, max);
	}
}

const char		*parse_comma_list(const char *str)
{
	static char			buf[MAX_LST_ELM_LEN + 1] = { 0 };
	static const char	*list = NULL;
	const char			*end = NULL;
	static const char	*p = NULL;
	size_t				len;

	if (str != list)
		list = p = str;
	else if (p && *p == ',' && p[1])
		++p;
	end = p;
	while (end && !ft_strchr(",", *end))
		++end;
	if (!p || ((!*p && p == list) || *p == ',')
		|| (len = end - p) > MAX_LST_ELM_LEN)
	{
		list = p = NULL;
		return (NULL);
	}
	ft_strncpy(buf, p, len);
	buf[len] = 0;
	p = end;
	return ((const char *)buf);
}

void		get_options(t_nmap_config *cfg, int argc, char **argv)
{
	int			opt;
	char		**args;
	t_optdata	o = { 0 };

	init_getopt(&o, FT_NMAP_OPT, g_nmap_opt, NULL);
	args = ft_memalloc((argc + 1) * sizeof(char *));
	ft_memcpy((void *)args, (void *)argv, argc * sizeof(char *));
	*args = (char *)cfg->exec;
	while ((opt = ft_getopt_long(argc, args, &o)) >= 0)
		switch (opt)
		{
			case 'd': ++cfg->debug;										break;
			case 'f': cfg->hosts_file = o.optarg;						break;
			case 'i': cfg->dev = o.optarg;								break;
			case 'p': ports_option(cfg, &o);							break;
			case 'S': scan_option(cfg, &o);								break;
			case 's': intopt(&cfg->speedup, o.optarg, 0, MAX_SPEEDUP);	break;
			case 't': cfg->hosts = o.optarg;							break;
			case 'v': ++cfg->verbose;									break;
			case '4': cfg->ip_mode = E_IPV4;							break;
			case '6': cfg->ip_mode = E_IPV6;							break;
			default: usage(cfg->exec, opt != 'h');
		}
	ft_memdel((void **)&args);
}
