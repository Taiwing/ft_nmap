/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   new_host.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 11:36:40 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 14:59:11 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_list	*build_probe_tasks(t_nmap_config *cfg, t_host_job *host_job)
{
	t_list		*probe_tasks = NULL;
	t_task		task = { .type = E_TASK_PROBE, .cfg = cfg, .reply = NULL };

	for (uint16_t scan = 0, id = 0; scan < SCAN_COUNT; ++scan)
	{
		task.scan_type = scan;
		if (host_job->scans[scan])
			for (uint16_t port = 0; port < cfg->nports; ++port)
			{
				task.probe = host_job->probes + id
				ft_bzero(task.probe, sizeof(t_probe));
				task.probe->srcip = &host_job->dev->ip;
				task.probe->dstip = &host_job->host_ip;
				task.probe->srcp = PORT_DEF + id++;
				task.probe->dstp = cfg->ports[port];
				task.probe->host_job_id = host_job->host_job_id;
				task.probe->port_job_id = port;
				task.probe->socket = (host_job->ip->family == AF_INET
					? E_UDPV4 : E_UDPV6) + (scan != E_UDP);
				build_probe(&task, task.probe->srcp, task.probe->dstp);
				ft_push_back(&probe_tasks, task, sizeof(task));
			}
	}
	return (probe_tasks);
}

void	new_host(t_nmap_config *cfg)
{
	t_list	*probe_tasks = NULL;
	t_list	*new_host_job = init_new_host_job(cfg);

	//TODO: set cfg end bool to true
	if (!new_host_job)
		return ;
	if (cfg->host_jobs)
		ft_lst_last(cfg->host_jobs)->next = new_host_job;
	else
		cfg->host_jobs = new_host_job;
	probe_tasks = build_probe_tasks(cfg, (t_host_job *)new_host_job->content);
	//TODO: push probe tasks to worker task list and then add new_host_task and
	// or push them to main_thread task list with alernating LISTEN tasks to
	// actually wait for incoming packets (in monothreaded mode of course)
}
