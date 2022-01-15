/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 23:12:12 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/15 18:19:42 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

const char		*g_nmap_scan_strings[SCAN_COUNT] = {
	"SYN", "ACK", "NULL", "FIN", "XMAS", "UDP"
};

void		set_scan_ports(t_nmap_config *cfg, int porta, int portb, void *data)
{
	(void)data;
	do
	{
		if (!cfg->ports_to_scan[porta] && cfg->nports < MAX_PORTS)
			++cfg->nports;
		else if (!cfg->ports_to_scan[porta])
			ft_exit(EXIT_FAILURE, "%s: too many ports to scan, max is: %d",
				__func__, MAX_PORTS);
		cfg->ports_to_scan[porta] = 1;
		++porta;
	} while (porta <= portb);
}

void		scan_option(t_nmap_config *cfg, t_optdata *optd)
{
	const char	*arg = NULL;
	int			i, len;

	while ((arg = parse_comma_list(optd->optarg)) && *arg)
	{
		len = ft_strlen(arg);
		for (i = 0; i < SCAN_COUNT; ++i)
			if (!ft_ignore_case_strncmp(g_nmap_scan_strings[i], arg, len))
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
