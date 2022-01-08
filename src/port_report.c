/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   port_report.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/08 02:54:02 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/08 02:54:18 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

//TODO: switch services array in function of type (tcp/udp/sctp)
static void	print_port(t_port_job *port_job, uint16_t port_job_id,
		uint16_t c, t_nmap_config *cfg)
{
	int			line;
	//char		***services;
	const char	*service;
	const char	*results[SCAN_COUNT] = { 0 };

	for (int i = 0, j = 0; i < SCAN_COUNT && j < cfg->nscans; ++i)
		if (cfg->scans[i])
			results[j++] = g_scan_results[port_job->scan_jobs[i].status
				& E_STATE_SCAN_MASK];
	//TODO: use other service files or getservbyport()
	//services = (char ***)g_tcp_services; //TEMP: pretend it's always TCP for now
	if (!c)
	{
		line = ft_printf("\n| %-*s | %-*s |%#*t %-"xstr(SCAN_FIELD)"s|",
			PORT_FIELD, "Port", SERVICE_FIELD, "Service", cfg->nscans,
			cfg->scan_strings);
		if (line > 1)
			ft_printf("\n%.*s\n", line - 1, g_sep_line);
	}
	if (!(service = g_tcp_services[cfg->ports[port_job_id]][0]))
		service = "(unknown)";
	ft_printf("| %-*hu | %-*s |%#*t %-"xstr(SCAN_FIELD)"s|\n",
		PORT_FIELD, cfg->ports[port_job_id], SERVICE_FIELD, service,
		cfg->nscans, results);
}

static void		print_port_by_status(t_host_job *host_job, t_nmap_config *cfg,
			uint16_t count[MAX_PORT_STATUS + 1],
			uint16_t port_id[MAX_PORT_STATUS + 1][MAX_PORTS])
{
	uint8_t	c = 0;
	uint8_t	status = E_STATE_OPEN;

	while (!cfg->verbose && !cfg->debug && !cfg->complete
			&& ++status < MAX_PORT_STATUS + 1)
		if (g_port_status[status] && count[status] > MAX_PRINT_PORTS)
			ft_printf("%s%hu %s", !c++ ? "Ports not shown: " : ", ",
				count[status], g_port_status[status]);
	if (c)
		ft_putchar('\n');
	for (status = E_STATE_OPEN; status < MAX_PORT_STATUS + 1; ++status)
	{
		if (g_port_status[status] && count[status]
			&& (count[status] <= MAX_PRINT_PORTS || status == E_STATE_OPEN
			|| cfg->verbose || cfg->debug || cfg->complete))
		{
			ft_printf("\n%s ports:", g_port_status[status]);
			for (uint16_t i = 0; i < count[status]; ++i)
				print_port(host_job->port_jobs + port_id[status][i],
					port_id[status][i], i, cfg);
		}
	}
}

void		port_report(t_host_job *host_job, t_nmap_config *cfg)
{
	uint16_t	count[MAX_PORT_STATUS + 1] = { 0 };
	uint16_t	port_id[MAX_PORT_STATUS + 1][MAX_PORTS] = { 0 };

	for (uint16_t i = 0, status; i < cfg->nports; ++i)
	{
		status = host_job->port_jobs[i].status & E_STATE_SCAN_MASK;
		port_id[status][count[status]++] = i;
	}
	print_port_by_status(host_job, cfg, count, port_id);
}
