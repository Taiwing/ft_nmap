/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 14:52:50 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/15 14:18:57 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

const char	g_sep_line[JOB_LINE + 1] = { [0 ... JOB_LINE - 1] = '-' };

const char	*g_nmap_scan_strings[SCAN_COUNT] = {
	"SYN", "ACK", "NULL", "FIN", "XMAS", "UDP"
};

const char	*g_scan_results[MAX_PORT_STATUS + 1] = {
	[ E_STATE_OPEN ] = "O",
	[ E_STATE_CLOSED ] = "C",
	[ E_STATE_UNFILTERED ] = "U",
	[ E_STATE_FILTERED ] = "F",
	[ E_STATE_OPEN | E_STATE_FILTERED ] = "OF",
};

const char	*g_port_status[MAX_PORT_STATUS + 1] = {
	[ E_STATE_OPEN ] = "Open",
	[ E_STATE_CLOSED ] = "Closed",
	[ E_STATE_UNFILTERED ] = "Unfiltered",
	[ E_STATE_FILTERED ] = "Filtered",
	[ E_STATE_OPEN | E_STATE_FILTERED ] = "Open|Filtered",
};

void	print_host_job(t_host_job *host_job, t_nmap_config *cfg)
{
	char		ipbuf[INET6_ADDRSTRLEN] = { 0 };
	double		scan_time = ts_msdiff(&host_job->end_ts, &host_job->start_ts);

	if (cfg->speedup && (cfg->verbose || cfg->debug))
		nmap_mutex_lock(&cfg->print_mutex, &g_print_locked);
	ft_printf("\nHost: %s\nScan took %g seconds\nIP address: %s\n",
		host_job->host, scan_time / 1000.0, inet_ntop(host_job->ip.family,
		ft_ip_addr(&host_job->ip), ipbuf, INET6_ADDRSTRLEN));
	switch (cfg->report)
	{
		case E_REPORT_PORT: port_report(host_job, cfg);			break;
		case E_REPORT_RANGE: range_report(host_job, cfg);		break;
		case E_REPORT_HEATMAP: heatmap_report(host_job, cfg);	break;
	}
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
