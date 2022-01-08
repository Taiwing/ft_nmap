/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   range_report.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/08 00:01:03 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/08 04:22:35 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

#define	MAX_RANGE_SIZE		16
#define RANGE_REPORT_LINE	60
#define SCAN_NAME_FIELD		((RANGE_REPORT_LINE / 2) - 2)

static int	print_range(int cc, uint16_t fport, uint16_t lport)
{
	int			newcc;
	char		buf[MAX_RANGE_SIZE];

	newcc = ft_snprintf(buf, MAX_RANGE_SIZE, fport == lport ?
		"%hu" : "%hu-%hu", fport, lport);
	if (cc <= 0)
	{
		ft_printf(" %s", buf);
		newcc += 1 - cc;
	}
	else if (cc + newcc + 2 >= RANGE_REPORT_LINE)
	{
		ft_printf(",\n %s", buf);
		++newcc;
	}
	else
	{
		ft_printf(", %s", buf);
		newcc += cc + 2;
	}

	return (newcc);
}

static void	print_scan(uint8_t results[MAX_PORTS],
		uint16_t state_counters[MAX_PORT_STATUS + 1], t_nmap_config *cfg)
{
	int			cc;
	uint16_t	count, first_port, last_port;

	for (uint8_t state = E_STATE_OPEN; state <= MAX_PORT_STATUS; ++state)
	{
		if (!(count = state_counters[state]))
			continue;
		cc = -ft_printf(" %s ports (%hu): ", g_port_status[state], count);
		for (uint16_t id = 0; id < cfg->nports && count;)
		{
			while (results[id] != state)
				++id;
			first_port = last_port = cfg->ports[id];
			--count;
			while (count && results[++id] == state
				&& cfg->ports[id] == cfg->ports[id - 1] + 1)
			{
				--count;
				++last_port;
			}
			cc = print_range(cc, first_port, last_port);
		}
		ft_printf("\n");
	}
}

void		range_report(t_host_job *host_job, t_nmap_config *cfg)
{
	uint8_t		results[MAX_PORTS] = { 0 };
	uint16_t	state_counters[MAX_PORT_STATUS + 1];

	ft_printf("\n%.*s\n", RANGE_REPORT_LINE, g_sep_line);
	for (uint16_t scan = 0; scan < SCAN_COUNT; ++scan)
	{
		if (!cfg->scans[scan])
			continue;
		ft_bzero(state_counters, sizeof(state_counters));
		ft_printf(" %*s %s\n", SCAN_NAME_FIELD,
			"Scan", g_nmap_scan_strings[scan]);
		ft_printf("%.*s\n", RANGE_REPORT_LINE, g_sep_line);
		for (int port_id = 0; port_id < cfg->nports; ++port_id)
		{
			results[port_id] = host_job->port_jobs[port_id]
				.scan_jobs[scan].status & E_STATE_SCAN_MASK;
			++state_counters[results[port_id]];
		}
		print_scan(results, state_counters, cfg);
		ft_printf("%.*s\n", RANGE_REPORT_LINE, g_sep_line);
	}
}
