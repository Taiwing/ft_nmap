/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:55:31 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/20 21:42:03 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

#define	FT_NMAP_OPT	"hs:"

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
	ft_exit(NULL, exit_value);
}

static void	intopt(int *dest, t_optdata *optd, int min, int max)
{
	int		ret;
	char	*err;

	if ((ret = ft_secatoi(dest, min, max, optd->optarg)))
	{
		if (ret == FT_E_NOT_A_NUMBER)
			ft_asprintf(&err, "invalid argument: '%s'", optd->optarg);
		else
			ft_asprintf(&err, "invalid argument: '%s': "
				"out of range: %d <= value <= %d", optd->optarg, min, max);
		ft_exit(err, EXIT_FAILURE);
	}
}

void		ports_option(t_nmap_config *cfg, const char *arg)
{
	(void)cfg;
	(void)arg;
}

void		scan_option(t_nmap_config *cfg, const char *arg)
{
	(void)cfg;
	(void)arg;
}

void		get_options(t_nmap_config *cfg, int argc, char **argv)
{
	int			opt;
	char		**args;
	t_optdata	optd = { 0 };

	init_getopt(&optd, FT_NMAP_OPT, g_nmap_opt, NULL);
	args = ft_memalloc((argc + 1) * sizeof(char *));
	ft_memcpy((void *)args, (void *)argv, argc * sizeof(char *));
	*args = (char *)cfg->exec;
	while ((opt = ft_getopt_long(argc, args, &optd)) >= 0)
		switch (opt)
		{
			case 'f': cfg->hosts_file = optd.optarg;					break;
			case 'i': cfg->hosts = optd.optarg;							break;
			case 'p': ports_option(cfg, optd.optarg);					break;
			case 'S': scan_option(cfg, optd.optarg);					break;
			case 's': intopt(&cfg->speedup, &optd, 0, MAX_SPEEDUP);		break;
			default:
				usage(cfg->exec, opt != 'h');
		}
	ft_memdel((void **)&args);
}
