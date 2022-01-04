/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   new_host.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 11:36:40 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/04 09:11:53 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_probe	*init_task_probe(t_nmap_config *cfg, uint16_t probe_id,
		uint16_t scan, uint16_t port)
{
	t_probe	*probe = cfg->probes + probe_id;

	probe->srcip = &cfg->host_job.dev->ip;
	probe->dstip = &cfg->host_job.ip;
	probe->srcp = PORT_DEF + probe_id;
	probe->dstp = cfg->ports[port];
	probe->host_job_id = cfg->host_job.host_job_id;
	probe->port_job_id = port;
	probe->scan_type = scan;
	reset_packet(&probe->packet, NULL);
	build_probe_packet(probe, cfg->host_job.family == AF_INET ? 4 : 6);
	probe->socket = (cfg->host_job.ip.family == AF_INET
		? E_UDPV4 : E_UDPV6) + (scan != E_UDP);
	probe->retry = 1 + MAX_RETRY;
	return (probe);
}

static t_list	*build_probe_tasks(t_nmap_config *cfg, int *nprobes)
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
				probe.probe = init_task_probe(cfg, id, scan, port);
				ft_lst_push_back(&probe_tasks, &probe, sizeof(probe));
				if (!cfg->speedup)
					ft_lst_push_back(&probe_tasks, &listen, sizeof(listen));
			}
	}
	*nprobes = (int)id;
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
	int			nprobes = 0;
	const char	*host = NULL;
	t_list		*probe_tasks = NULL;

	cfg->nprobes = 0;
	cfg->host_job.done = cfg->nports;
	if (!(host = next_host(&cfg->host_job.ip, cfg)))
	{
		cfg->end = 1;
		return ;
	}
	set_host_job_data(&cfg->host_job, host, cfg);
	probe_tasks = build_probe_tasks(cfg, &nprobes);
	if (cfg->speedup)
		set_filter(cfg, NULL);
	cfg->host_job.done = 0;
	cfg->nprobes = nprobes;
	if (cfg->speedup)
		push_tasks(&cfg->worker_tasks, probe_tasks, cfg, 1);
	else
		push_tasks(&cfg->main_tasks, probe_tasks, cfg, 0);
}
