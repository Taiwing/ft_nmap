/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:55:31 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/20 16:45:17 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

#define	FT_NMAP_OPT	"hs:"

t_opt	g_nmap_opt[] = {
	{ "help",		0,	NULL,	'h'	},
	{ "speedup",	1,	NULL,	's'	},
	{ NULL,			0,	NULL,	0	},
};

char	*g_nmap_help[] = {
	"Print this and exit.",
	"Number of parallel threads to use (def: 0, max: " xstr(MAX_SPEEDUP) ").",
	NULL,
};

char	*g_nmap_usage[] = {
	"[--help] [--ports number/range] [--speedup number] "
	"[--scan type] --ip host",
	"[--help] [--ports number/range] [--speedup number] "
	"[--scan type] --file path",
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
			case 's': intopt(&cfg->speedup, &optd, 0, MAX_SPEEDUP);		break;
			default:
				usage(cfg->exec, opt != 'h');
		}
	ft_memdel((void **)&args);
}
