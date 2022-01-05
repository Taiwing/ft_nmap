/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   new_host.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 11:36:40 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/05 16:26:11 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_scan_job	*init_task_probe(t_nmap_config *cfg, uint16_t scan_job_id,
		uint16_t scan, uint16_t port)
{
	t_scan_job	*scan_job = &cfg->host_job.port_jobs[port].scan_jobs[scan];

	cfg->scan_jobs[scan_job_id] = scan_job;
	scan_job->srcip = &cfg->host_job.dev->ip;
	scan_job->dstip = &cfg->host_job.ip;
	scan_job->srcp = PORT_DEF + scan_job_id;
	scan_job->dstp = cfg->ports[port];
	scan_job->host_job_id = cfg->host_job.host_job_id;
	scan_job->port_job_id = port;
	scan_job->type = scan;
	reset_packet(&scan_job->packet, NULL);
	build_probe_packet(scan_job, cfg->host_job.family == AF_INET ? 4 : 6);
	scan_job->socket = (cfg->host_job.ip.family == AF_INET
		? E_UDPV4 : E_UDPV6) + (scan != E_UDP);
	scan_job->retry = 1 + MAX_RETRY;
	return (scan_job);
}

static t_list	*build_probe_tasks(t_nmap_config *cfg, int *nscan_jobs)
{
	uint16_t	id = 0;
	t_list		*probe_tasks = NULL;
	t_task		probe = { .type = E_TASK_PROBE };
	t_task		listen = { .type = E_TASK_LISTEN };

	for (uint16_t scan = 0; scan < SCAN_COUNT; ++scan)
	{
		if (cfg->scans[scan])
			for (uint16_t port = 0; port < cfg->nports; ++port, ++id)
			{
				probe.scan_job = init_task_probe(cfg, id, scan, port);
				ft_lst_push_back(&probe_tasks, &probe, sizeof(probe));
				if (!cfg->speedup)
					ft_lst_push_back(&probe_tasks, &listen, sizeof(listen));
			}
	}
	*nscan_jobs = (int)id;
	return (probe_tasks);
}

static void	set_host_job_data(t_host_job *host_job, const char *host,
		t_nmap_config *cfg)
{
	++host_job->host_job_id;
	if (host_job->host)
		ft_memdel((void **)&host_job->host);
	host_job->host = ft_strdup(host);
	if (gettimeofday(&host_job->start_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	host_job->family = host_job->ip.family;
	if (host_job->family == AF_INET)
		host_job->dev = !ip_cmp(&cfg->netinf.defdev_v4->ip, &host_job->ip)
			|| !ip_cmp(&cfg->netinf.loopback_v4->ip, &host_job->ip) ?
			cfg->netinf.loopback_v4 : cfg->netinf.defdev_v4;
	else
		host_job->dev = !ip_cmp(&cfg->netinf.defdev_v6->ip, &host_job->ip)
			|| !ip_cmp(&cfg->netinf.loopback_v6->ip, &host_job->ip) ?
			cfg->netinf.loopback_v6 : cfg->netinf.defdev_v6;
	ft_bzero((void *)&host_job->end_ts, sizeof(host_job->end_ts));
	ft_bzero((void *)host_job->port_jobs, sizeof(host_job->port_jobs));
	host_job->status = 0;
}

void	new_host(t_nmap_config *cfg)
{
	int			nscan_jobs = 0;
	const char	*host = NULL;
	t_list		*probe_tasks = NULL;

	cfg->nscan_jobs = 0;
	cfg->host_job.done = cfg->nports;
	if (!(host = next_host(&cfg->host_job.ip, cfg)))
	{
		cfg->end = 1;
		return ;
	}
	set_host_job_data(&cfg->host_job, host, cfg);
	probe_tasks = build_probe_tasks(cfg, &nscan_jobs);
	if (cfg->speedup)
		set_filter(cfg, NULL);
	cfg->host_job.done = 0;
	cfg->nscan_jobs = nscan_jobs;
	if (cfg->speedup)
		push_tasks(&cfg->worker_tasks, probe_tasks, cfg, 1);
	else
		push_tasks(&cfg->main_tasks, probe_tasks, cfg, 0);
}
