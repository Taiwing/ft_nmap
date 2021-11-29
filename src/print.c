/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 14:52:50 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/29 21:31:42 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

# define	PORT_STATUS_MAX		(E_STATE_OPEN | E_STATE_FILTERED)
# define	MAX_PRINT_PORTS		26

const char	g_sep_line[JOB_LINE + 1] = { [0 ... JOB_LINE - 1] = '-' };

const char	*g_scan_results[PORT_STATUS_MAX + 1] = {
	[ E_STATE_OPEN ] = "O",
	[ E_STATE_CLOSED ] = "C",
	[ E_STATE_UNFILTERED ] = "U",
	[ E_STATE_FILTERED ] = "F",
	[ E_STATE_OPEN | E_STATE_FILTERED ] = "OF",
};

const char	*g_port_status[PORT_STATUS_MAX + 1] = {
	[E_STATE_OPEN] = "Open",
	[E_STATE_CLOSED] = "Closed",
	[E_STATE_UNFILTERED] = "Unfiltered",
	[E_STATE_FILTERED] = "Filtered",
	[E_STATE_OPEN | E_STATE_FILTERED] = "Open|Filtered",
};

/*
** ts_msdiff: timestamp ms substraction
**
** Substracts b from a and returns the result in ms.
*/
static double	ts_msdiff(struct timeval *a, struct timeval *b)
{
	double s;
	double us;

	s = ((double)(a->tv_sec - b->tv_sec)) * 1000.0;
	us = ((double)(a->tv_usec - b->tv_usec)) / 1000.0;
	return (s + us);
}

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
			results[j++] =
				g_scan_results[port_job->scan_jobs[i] & E_STATE_SCAN_MASK];
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

void	print_port_by_status(t_host_job *host_job, t_nmap_config *cfg,
			uint16_t count[PORT_STATUS_MAX + 1],
			uint16_t port_id[PORT_STATUS_MAX + 1][MAX_PORTS])
{
	uint8_t	c = 0;
	uint8_t	status = E_STATE_OPEN;

	while (!cfg->verbose && ++status < PORT_STATUS_MAX + 1)
		if (g_port_status[status] && count[status] > MAX_PRINT_PORTS)
			ft_printf("%s%hu %s", !c++ ? "Ports not shown: " : ", ",
				count[status], g_port_status[status]);
	if (c)
		ft_putchar('\n');
	for (status = E_STATE_OPEN; status < PORT_STATUS_MAX + 1; ++status)
	{
		if (g_port_status[status] && count[status]
			&& (count[status] <= MAX_PRINT_PORTS || status == E_STATE_OPEN
			|| cfg->verbose || cfg->debug))
		{
			ft_printf("\n%s ports:", g_port_status[status]);
			for (uint16_t i = 0; i < count[status]; ++i)
				print_port(host_job->port_jobs + port_id[status][i],
					port_id[status][i], i, cfg);
		}
	}
}

void	print_host_job(t_host_job *host_job, t_nmap_config *cfg)
{
	char		ipbuf[INET6_ADDRSTRLEN] = { 0 };
	uint16_t	count[PORT_STATUS_MAX + 1] = { 0 };
	uint16_t	port_id[PORT_STATUS_MAX + 1][MAX_PORTS] = { 0 };
	double		scan_time = ts_msdiff(&host_job->end_ts, &host_job->start_ts);

	if (cfg->speedup && (cfg->verbose || cfg->debug))
		nmap_mutex_lock(&cfg->print_mutex, &g_print_locked);
	for (uint16_t i = 0, status; i < cfg->nports; ++i)
	{
		status = host_job->port_jobs[i].status & E_STATE_SCAN_MASK;
		port_id[status][count[status]++] = i;
	}
	ft_printf("Host: %s\nScan took %g seconds\nIP address: %s\n",
		host_job->host, scan_time / 1000.0, inet_ntop(host_job->ip.family,
		ip_addr(&host_job->ip), ipbuf, INET6_ADDRSTRLEN));
	print_port_by_status(host_job, cfg, count, port_id);
	if (cfg->speedup && (cfg->verbose || cfg->debug))
		nmap_mutex_unlock(&cfg->print_mutex, &g_print_locked);
}

void		print_config(t_nmap_config *cfg)
{
	for (int i = 0, j = 0; i < SCAN_COUNT && j < cfg->nscans; ++i)
		if (cfg->scans[i])
			cfg->scan_strings[j++] = g_nmap_scan_strings[i];
	ft_printf("--- Network ---\n"
		"IPv4 Status: %s\n"
		"IPv6 Status: %s\n"
		"Default Interface: %s\n\n",
		cfg->ip_mode != E_IPV6 && cfg->netinf.defdev_v4 ? "on" : "off",
		cfg->ip_mode != E_IPV4 && cfg->netinf.defdev_v6 ? "on" : "off",
		cfg->ip_mode == E_IPV6 || !cfg->netinf.defdev_v4 ?
		cfg->netinf.defdev_v6->name : cfg->netinf.defdev_v4->name);
	ft_printf("--- Scan ---\n"
		"Number of threads: %d\n"
		"Number of ports to scan: %d\n"
		"Scans to be performed:%*t %s\n",
		cfg->speedup, cfg->nports, cfg->nscans, cfg->scan_strings);
}
