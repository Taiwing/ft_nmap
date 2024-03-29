/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   new_host.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 11:36:40 by yforeau           #+#    #+#             */
/*   Updated: 2023/01/27 20:23:07 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_packet		**init_scan_probes(t_nmap_config *cfg, t_scan_job *scan_job,
	t_packet **probes)
{
	uint16_t	count = 0, port = scan_job->dstp, scan = scan_job->type;

	if (!probes)
	{
		if (scan == E_UDP && cfg->udp_payloads[port])
			while (cfg->udp_payloads[port][count])
				++count;
		if (!count)
			++count;
		probes = ft_memalloc((count + 1) * sizeof(t_packet *));
		for (uint16_t i = 0; i < count; ++i)
			probes[i] = ft_memalloc(sizeof(t_packet));
		scan_job->probe_count = count;
		scan_job->total_tries = (1 + cfg->retries) * count;
	}
	for (int i = 0; i < scan_job->probe_count; ++i)
	{
		ft_packet_reset(probes[i], NULL);
		if (scan == E_UDP && cfg->udp_payloads[port])
			build_probe_packet(probes[i], scan_job,
				cfg->udp_payloads[port][i]->data,
				cfg->udp_payloads[port][i]->size);
		else
			build_probe_packet(probes[i], scan_job, NULL, 0);
	}
	return (probes);
}

static t_scan_job	*init_scan_job(t_nmap_config *cfg, uint16_t scan_job_id,
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
	scan_job->probes = init_scan_probes(cfg, scan_job, scan_job->probes);
	scan_job->socket = (cfg->host_job.ip.family == AF_INET
		? E_SSEND_UDPV4 : E_SSEND_UDPV6) + (scan != E_UDP);
	ft_bzero(&scan_job->sent_ts, sizeof(scan_job->sent_ts));
	scan_job->tries = scan_job->total_tries;
	scan_job->status = 0;
	return (scan_job);
}

static void		build_probe_tasks(t_nmap_config *cfg)
{
	t_list		*probe_tasks = NULL;
	t_task		task = { .type = E_TASK_PROBE };

	for (uint16_t scan = 0, id = 0; scan < SCAN_COUNT; ++scan)
	{
		if (!cfg->scans[scan])
			continue;
		for (uint16_t port = 0; port < cfg->nports; ++port, ++id)
		{
			task.scan_job = init_scan_job(cfg, id, scan, port);
			ft_lst_push_back(&probe_tasks, &task, sizeof(task));
		}
	}
	push_front_tasks(&cfg->thread_tasks, probe_tasks, cfg, !!cfg->speedup);
}

static void	set_host_job_data(t_host_job *host_job, char *host,
		t_nmap_config *cfg)
{
	++host_job->host_job_id;
	ft_memdel((void **)&host_job->host);
	host_job->host = host;
	if (gettimeofday(&host_job->start_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	host_job->family = host_job->ip.family;
	if (host_job->family == AF_INET)
		host_job->dev = !ft_ip_cmp(&cfg->netinf.defdev_v4->ip, &host_job->ip)
			|| !ft_ip_cmp(&cfg->netinf.loopback_v4->ip, &host_job->ip) ?
			cfg->netinf.loopback_v4 : cfg->netinf.defdev_v4;
	else
		host_job->dev = !ft_ip_cmp(&cfg->netinf.defdev_v6->ip, &host_job->ip)
			|| !ft_ip_cmp(&cfg->netinf.loopback_v6->ip, &host_job->ip) ?
			cfg->netinf.loopback_v6 : cfg->netinf.defdev_v6;
	ft_bzero((void *)&host_job->end_ts, sizeof(host_job->end_ts));
	for (int i = 0; i < cfg->nports; ++i)
	{
		host_job->port_jobs[i].status = host_job->port_jobs[i].done = 0;
		ft_bzero((void *)&host_job->port_jobs[i].scan_locks,
			sizeof(host_job->port_jobs[i].scan_locks));
	}
	host_job->status = 0;
}

int		new_host(t_nmap_config *cfg)
{
	char		*host = NULL;

	cfg->host_job.done = cfg->nports;
	cfg->adventure_breakloop = 1;
	flush_tasks(&cfg->thread_tasks, cfg, !!cfg->speedup);
	while (cfg->running_tasks > 1 && !cfg->end);
	reset_timeout(cfg, NULL);
	if (cfg->end || !(host = next_host(&cfg->host_job.ip, cfg)))
	{
		cfg->end = 1;
		return (0);
	}
	set_host_job_data(&cfg->host_job, host, cfg);
	set_filters(cfg);
	for (int i = 0; i < SCAN_COUNT; ++i)
	{
		if (!cfg->scans[i])
			continue ;
		reset_window(&cfg->window[i]);
		if (i == E_UDP)
			cfg->window[i].exponential_backoff = cfg->exponential_backoff;
	}
	cfg->host_job.done = 0;
	build_probe_tasks(cfg);
	return (1);
}
