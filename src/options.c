/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 23:12:12 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/23 21:21:33 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static char	*set_ports(t_nmap_config *cfg, int porta, int portb)
{
	char	*err = NULL;

	do
	{
		if (!cfg->ports_to_scan[porta] && cfg->nports < MAX_PORTS)
			++cfg->nports;
		else if (!cfg->ports_to_scan[porta])
			ft_asprintf(&err, "too many ports to scan, max is: %d", MAX_PORTS);
		cfg->ports_to_scan[porta] = 1;
		++porta;
	} while (!err && porta <= portb);
	return (err);
}

char		*ports_option(t_nmap_config *cfg, t_optdata *optd)
{
	const char	*arg = NULL, *p = NULL;
	char		*err = NULL;
	int			porta, portb;

	while (!err && (arg = parse_comma_list(optd->optarg)) && *arg)
	{
		p = arg;
		portb = 0;
		err = intopt(&porta, p, 0, USHRT_MAX);
		for (; !err && *p && ft_isdigit(*p); ++p);
		if (!err && *p && *p == '-')
		{
			err = intopt(&portb, ++p, 0, USHRT_MAX);
			if (!err && portb <= porta)
				ft_asprintf(&err, "second port must be greater than first "
					"port in range: '%s'", arg);
		}
		for (; !err && *p && ft_isdigit(*p); ++p);
		if (!err && *p)
			break;
		err = !err ? set_ports(cfg, porta, portb) : err;
	}
	if (!err && (!arg || !p || *p))
		ft_asprintf(&err, "invalid list argument: '%s'", optd->optarg);
	return (err);
}

const char		*g_nmap_scan_strings[NB_SCANS] = {
	"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"
};

char		*scan_option(t_nmap_config *cfg, t_optdata *optd)
{
	char		*err = NULL;
	const char	*arg = NULL;
	int			i;

	while (!err && (arg = parse_comma_list(optd->optarg)) && *arg)
	{
		for (i = 0; i < NB_SCANS; ++i)
			if (!ft_ignore_case_strcmp(g_nmap_scan_strings[i], arg))
				break;
		if (i == NB_SCANS)
			ft_asprintf(&err, "invalid scan type: '%s'", arg);
		else if (!cfg->scans[i])
		{
			cfg->scans[i] = 1;
			++cfg->nscans;
		}
	}
	if (!err && (!arg || *arg))
		ft_asprintf(&err, "invalid list argument: '%s'", optd->optarg);
	return (err);
}
