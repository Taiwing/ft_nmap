/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 23:12:12 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 10:35:05 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	set_ports(t_nmap_config *cfg, int porta, int portb)
{
	do
	{
		if (!cfg->ports_to_scan[porta] && cfg->nports < MAX_PORTS)
			++cfg->nports;
		else if (!cfg->ports_to_scan[porta])
			ft_exit(EXIT_FAILURE, "too many ports to scan, max is: %d",
				MAX_PORTS);
		cfg->ports_to_scan[porta] = 1;
		++porta;
	} while (porta <= portb);
}

// This is largely big enough to detect overflow from integer string
#define	INTOPT_BUF	64

static void	intport(int *dest, const char *arg, int min, int max)
{
	int		i, ret;
	char	buf[INTOPT_BUF + 1] = { 0 };

	ft_strncpy(buf, arg, INTOPT_BUF);
	for (i = 0; buf[i] && ft_isdigit(buf[i]); ++i);
	if (i == INTOPT_BUF && ft_isdigit(arg[i]))
		ft_exit(EXIT_FAILURE, "invalid argument: '%s'", arg);
	buf[i] = 0;
	if ((ret = ft_secatoi(dest, min, max, buf)))
	{
		if (ret == FT_E_NOT_A_NUMBER)
			ft_exit(EXIT_FAILURE, "invalid argument: '%s'", arg);
		else
			ft_exit(EXIT_FAILURE, "invalid argument: '%s': "
				"out of range: %d <= value <= %d", buf, min, max);
	}
}

void		ports_option(t_nmap_config *cfg, t_optdata *optd)
{
	const char	*arg = NULL, *p = NULL;
	int			porta, portb;

	while ((arg = parse_comma_list(optd->optarg)) && *arg)
	{
		p = arg;
		portb = 0;
		intport(&porta, p, 0, USHRT_MAX);
		for (; *p && ft_isdigit(*p); ++p);
		if (*p && *p == '-')
		{
			intport(&portb, ++p, 0, USHRT_MAX);
			if (portb <= porta)
				ft_exit(EXIT_FAILURE, "second port must be greater than first "
					"port in range: '%s'", arg);
		}
		for (; *p && ft_isdigit(*p); ++p);
		if (*p)
			break;
		set_ports(cfg, porta, portb);
	}
	if (!arg || !p || *p)
		ft_exit(EXIT_FAILURE, "invalid list argument: '%s'", optd->optarg);
}

const char		*g_nmap_scan_strings[SCAN_COUNT] = {
	"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"
};

void		scan_option(t_nmap_config *cfg, t_optdata *optd)
{
	const char	*arg = NULL;
	int			i;

	while ((arg = parse_comma_list(optd->optarg)) && *arg)
	{
		for (i = 0; i < SCAN_COUNT; ++i)
			if (!ft_ignore_case_strcmp(g_nmap_scan_strings[i], arg))
				break;
		if (i == SCAN_COUNT)
			ft_exit(EXIT_FAILURE, "invalid scan type: '%s'", arg);
		else if (!cfg->scans[i])
		{
			cfg->scans[i] = 1;
			++cfg->nscans;
		}
	}
	if (!arg || *arg)
		ft_exit(EXIT_FAILURE, "invalid list argument: '%s'", optd->optarg);
}
