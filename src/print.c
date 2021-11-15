/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 14:52:50 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 08:27:08 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

const char	g_sep_line[JOB_LINE + 1] = { [0 ... JOB_LINE - 1] = '-' };

const char	*g_scan_results[E_STATE_CLOSED | E_STATE_UNFILTERED | 0x01] = {
	[ E_STATE_OPEN ] = "O",
	[ E_STATE_CLOSED ] = "C",
	[ E_STATE_FILTERED ] = "F",
	[ E_STATE_OPEN | E_STATE_FILTERED ] = "OF",
	[ E_STATE_CLOSED | E_STATE_FILTERED ] = "CF",
	[ E_STATE_UNFILTERED ] = "U",
	[ E_STATE_OPEN | E_STATE_UNFILTERED ] = "OU",
	[ E_STATE_CLOSED | E_STATE_UNFILTERED ] = "CU",
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
	const char	*results[NB_SCANS] = { 0 };

	for (int i = 0, j = 0; i < NB_SCANS && j < cfg->nscans; ++i)
		if (cfg->scans[i])
			results[j++] =
				g_scan_results[port_job->scan_jobs[i] & E_STATE_SCAN_MASK];
	//TODO: use other service files or getservbyport()
	//services = (char ***)g_tcp_services; //TEMP: pretend it's always TCP for now
	if (!c)
	{
		line = ft_printf("\n%-*s | %-*s |%#*t %-"xstr(SCAN_FIELD)"s| %-*s",
			PORT_FIELD, "Port", SERVICE_FIELD, "Service", cfg->nscans,
			cfg->scan_strings, STATE_FIELD, "State");
		if (line > 1)
			ft_printf("\n%.*s\n", line - 1, g_sep_line);
	}
	if (!(service = g_tcp_services[cfg->ports[port_job_id]][0]))
		service = "(unknown)";
	ft_printf("%-*hu | %-*s |%#*t %-"xstr(SCAN_FIELD)"s| %-*s\n",
		PORT_FIELD, cfg->ports[port_job_id], SERVICE_FIELD, service,
		cfg->nscans, results, STATE_FIELD, (port_job->status & E_STATE_OPEN) ?
		"Open" : "Closed");
}

void	print_host_job(t_host_job *host_job, t_nmap_config *cfg)
{
	uint16_t	i, c;
	char		ipbuf[INET6_ADDRSTRLEN] = { 0 };
	double		scan_time = ts_msdiff(&host_job->end_ts, &host_job->start_ts);

	ft_printf("Host: %s\n", host_job->host);
	ft_printf("Scan took %g seconds\n", scan_time / 1000.0);
	ft_printf("IP address: %s\n\n", inet_ntop(host_job->host_ip.family,
		ip_addr(&host_job->host_ip), ipbuf, INET6_ADDRSTRLEN));
	ft_printf("Open ports:");
	for (i = 0, c = 0; i < cfg->nports; ++i)
		if (host_job->port_jobs[i].status & E_STATE_OPEN)
			print_port(host_job->port_jobs + i, i, c++, cfg);
	if (!c)
		ft_printf(" 0\n");
	ft_printf("\nClosed/Filtered/Unfiltered ports:");
	if (cfg->nports - c > 0)
	{
		for (i = 0, c = 0; i < cfg->nports; ++i)
			if (host_job->port_jobs[i].status & E_STATE_CLOSED)
				print_port(host_job->port_jobs + i, i, c++, cfg);
	}
	else
		ft_printf(" 0\n");
}

void		print_config(t_nmap_config *cfg)
{
	for (int i = 0, j = 0; i < NB_SCANS && j < cfg->nscans; ++i)
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
