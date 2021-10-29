/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 23:12:12 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/29 22:14:27 by yforeau          ###   ########.fr       */
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

void		ports_option(t_nmap_config *cfg, t_optdata *optd)
{
	const char	*arg = NULL, *p = NULL;
	int			porta, portb;

	while ((arg = parse_comma_list(optd->optarg)) && *arg)
	{
		p = arg;
		portb = 0;
		intopt(&porta, p, 0, USHRT_MAX);
		for (; *p && ft_isdigit(*p); ++p);
		if (*p && *p == '-')
		{
			intopt(&portb, ++p, 0, USHRT_MAX);
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

const char		*g_nmap_scan_strings[NB_SCANS] = {
	"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"
};

void		scan_option(t_nmap_config *cfg, t_optdata *optd)
{
	const char	*arg = NULL;
	int			i;

	while ((arg = parse_comma_list(optd->optarg)) && *arg)
	{
		for (i = 0; i < NB_SCANS; ++i)
			if (!ft_ignore_case_strcmp(g_nmap_scan_strings[i], arg))
				break;
		if (i == NB_SCANS)
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
