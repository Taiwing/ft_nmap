/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   new_host.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 11:36:40 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/16 12:21:00 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_probe	*init_task_probe(t_nmap_config *cfg, uint16_t probe_id,
		uint16_t scan, uint16_t port)
{
	t_probe	*probe = cfg->host_job.probes + probe_id;

	probe->srcip = &cfg->host_job.dev->ip;
	probe->dstip = &cfg->host_job.ip;
	probe->srcp = PORT_DEF + probe_id;
	probe->dstp = cfg->ports[port];
	probe->host_job_id = cfg->host_job.host_job_id;
	probe->port_job_id = port;
	probe->scan_type = scan;
	ft_bzero(probe->packet, sizeof(t_packet));
	build_probe_packet(probe, cfg->host_job.family == AF_INET ? 4 : 6);
	probe->socket = (cfg->host_job.ip->family == AF_INET
		? E_UDPV4 : E_UDPV6) + (scan != E_UDP);
	probe->retry = 0;
	probe->done = 0;
	return (probe);
}

static t_list	*build_probe_tasks(t_nmap_config *cfg, int *nprobes)
{
	uint16_t	id = 0;
	t_list		*probe_tasks = NULL;
	t_task		task = { .type = E_TASK_PROBE, .reply = NULL };

	for (uint16_t scan = 0; scan < SCAN_COUNT; ++scan)
	{
		if (cfg->scans[scan])
			for (uint16_t port = 0; port < cfg->nports; ++port, ++id)
			{
				task.probe = init_probe_task(cfg, id, scan, port);
				ft_push_back(&probe_tasks, task, sizeof(task));
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
	host_job->ongoing = 0;
}

void	new_host(t_nmap_config *cfg)
{
	int		nprobes = 0;
	char	*host = NULL;
	t_list	*probe_tasks = NULL;

	//TODO: set cfg end bool to true when no more host
	cfg->nprobes = 0;
	cfg->host_job.done = 1;
	if (!(host = next_host(&cfg->host_job.ip, cfg)))
		return ;
	set_host_job_data(&cfg->host_job);
	set_filter(cfg);
	probe_tasks = build_probe_tasks(cfg, &nprobes);
	cfg->host_job.done = 0;
	cfg->nprobes = nprobes;
	//TODO: push probe tasks to worker task list and then add new_host_task and
	// or push them to main_thread task list with alernating LISTEN tasks to
	// actually wait for incoming packets (in monothreaded mode of course)
}
