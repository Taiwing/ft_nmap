/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_options.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 23:11:55 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/27 07:13:36 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

#define	FT_NMAP_OPT	"f:hi:p:S:s:"

t_opt	g_nmap_opt[] = {
	{ "file",		1,	NULL,	'f'	},
	{ "help",		0,	NULL,	'h'	},
	{ "ip",			1,	NULL,	'i'	},
	{ "ports",		1,	NULL,	'p'	},
	{ "scan",		1,	NULL,	'S'	},
	{ "speedup",	1,	NULL,	's'	},
	{ NULL,			0,	NULL,	0	},
};

char	*g_nmap_help[] = {
	"File containing a list of hosts to scan (1 per line).",
	"Print this and exit.",
	"Hosts to scan specified as a comma separated list of IPv4-IPv6 addresses\n"
	"\t\tor hostnames (eg: localhost,192.168.1.0/24,2001::ffff).",
	"Ports to scan specified as a comma separated list of individual ports or\n"
	"\t\tranges (eg: 80,22,1024-2048). The default is 1-1024.",
	"Scans to perform specified as a comma separated list. Possible values:\n"
	"\t\t'SYN/NULL/FIN/XMAS/ACK/UDP' (eg: SYN,UDP). Does them all by default.",
	"Number of parallel threads to use (def: 0, max: " xstr(MAX_SPEEDUP) ").",
	NULL,
};

char	*g_nmap_usage[] = {
	"[--file path] [--help] [--ports list] [--scan list] "
	"[--speedup number] --ip list",
	"[--help] [--ip list] [--ports list] [--scan list] "
	"[--speedup number] --file path",
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

// This is largely big enough to detect overflow from integer string
#define	INTOPT_BUF	64

char			*intopt(int *dest, const char *arg, int min, int max)
{
	int		ret, i;
	char	*err = NULL;
	char	buf[INTOPT_BUF + 1] = { 0 };

	ft_strncpy(buf, arg, INTOPT_BUF);
	for (i = 0; buf[i] && ft_isdigit(buf[i]); ++i);
	if (i == INTOPT_BUF && ft_isdigit(arg[i]))
		ft_asprintf(&err, "invalid argument: '%s'", arg);
	buf[i] = 0;
	if (!err && (ret = ft_secatoi(dest, min, max, buf)))
	{
		if (ret == FT_E_NOT_A_NUMBER)
			ft_asprintf(&err, "invalid argument: '%s'", arg); 
		else
			ft_asprintf(&err, "invalid argument: '%s': "
				"out of range: %d <= value <= %d", buf, min, max);
	}
	return (err);
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
	char		*err = NULL;
	t_optdata	optd = { 0 };

	init_getopt(&optd, FT_NMAP_OPT, g_nmap_opt, NULL);
	args = ft_memalloc((argc + 1) * sizeof(char *));
	ft_memcpy((void *)args, (void *)argv, argc * sizeof(char *));
	*args = (char *)cfg->exec;
	while (!err && (opt = ft_getopt_long(argc, args, &optd)) >= 0)
		switch (opt)
		{
			case 'f': cfg->hosts_file = optd.optarg;					break;
			case 'i': cfg->hosts = optd.optarg;							break;
			case 'p': err = ports_option(cfg, &optd);					break;
			case 'S': err = scan_option(cfg, &optd);					break;
			case 's':
				err = intopt(&cfg->speedup, optd.optarg, 0, MAX_SPEEDUP);
																		break;
			default:
				usage(cfg->exec, opt != 'h');
		}
	ft_memdel((void **)&args);
	if (err)
		ft_exit(EXIT_FAILURE, err);
}
