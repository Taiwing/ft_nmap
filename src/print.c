/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 14:52:50 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/24 21:09:56 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

const char	g_sep_line[JOB_LINE + 1] = { [0 ... JOB_LINE - 1] = '-' };

const char	*g_scan_results[STATE_CLOSED | STATE_UNFILTERED | 0x01] = {
	[ STATE_OPEN ] = "O",
	[ STATE_CLOSED ] = "C",
	[ STATE_FILTERED ] = "F",
	[ STATE_OPEN | STATE_FILTERED ] = "OF",
	[ STATE_CLOSED | STATE_FILTERED ] = "CF",
	[ STATE_UNFILTERED ] = "U",
	[ STATE_OPEN | STATE_UNFILTERED ] = "OU",
	[ STATE_CLOSED | STATE_UNFILTERED ] = "CU",
};

#define _TO_STR_INTERNAL(arg) #arg
#define	TO_STR(arg) _TO_STR_INTERNAL(arg)

//TODO: switch services array in function of type (tcp/udp/sctp)
static void	print_port(t_task *task, uint16_t task_id,
		uint16_t c, t_nmap_config *cfg)
{
	int			line;
	//char		***services;
	const char	*service;
	const char	*results[NB_SCANS] = { 0 };

	for (int i = 0, j = 0; i < NB_SCANS && j < cfg->nscans; ++i)
		if (cfg->scans[i])
			results[j++] = g_scan_results[task->scans[i] & SCAN_MASK];
	//services = (char ***)g_tcp_services; //TEMP: pretend it's always TCP for now
	if (!c)
	{
		line = ft_printf("\n%-*s | %-*s |%#*t %-"TO_STR(SCAN_FIELD)"s| %-*s",
			PORT_FIELD, "Port", SERVICE_FIELD, "Service", cfg->nscans,
			cfg->scan_strings, STATE_FIELD, "State");
		if (line > 1)
			ft_printf("\n%.*s\n", line - 1, g_sep_line);
	}
	if (!(service = g_tcp_services[cfg->ports[task_id]][0]))
		service = "(unknown)";
	ft_printf("%-*hu | %-*s |%#*t %-"TO_STR(SCAN_FIELD)"s| %-*s\n",
		PORT_FIELD, cfg->ports[task_id], SERVICE_FIELD, service,
		cfg->nscans, results, STATE_FIELD, (task->status & STATE_OPEN) ?
		"Open" : "Closed");
}

void	print_job(t_job *job, t_nmap_config *cfg)
{
	uint16_t	i, c;
	double		scan_time = 3.666; //TEMP (TODO: compute actual time with job ts)

	//TODO: here flush job text buffer if needed
	ft_printf("\n\nScan took %g seconds\n", scan_time);
	ft_printf("host: %s\n", job->host);
	ft_printf("IP address: %s\n", "lol.mdr.xd.ptdr"); //TEMP
	ft_printf("Open ports:");
	for (i = 0, c = 0; i < cfg->nports; ++i)
		if (job->tasks[i].status & STATE_OPEN)
			print_port(job->tasks + i, i, c++, cfg);
	if (!c)
		ft_printf(" 0\n");
	ft_printf("\nClosed/Filtered/Unfiltered ports:");
	if (cfg->nports - c > 0)
	{
		for (i = 0, c = 0; i < cfg->nports; ++i)
			if (job->tasks[i].status & STATE_CLOSED)
				print_port(job->tasks + i, i, c++, cfg);
	}
	else
		ft_printf(" 0\n");
}

void		print_config(t_nmap_config *cfg)
{
	for (int i = 0, j = 0; i < NB_SCANS && j < cfg->nscans; ++i)
		if (cfg->scans[i])
			cfg->scan_strings[j++] = g_nmap_scan_strings[i];
	ft_printf("--- Scan Configuration ---\n"
		"Number of ports to scan: %d\n"
		"Scans to be performed:%*t %s\n"
		"Number of threads: %d\n",
		cfg->nports, cfg->nscans, cfg->scan_strings, cfg->speedup);
}
