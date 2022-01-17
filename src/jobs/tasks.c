/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tasks.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 10:45:13 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/17 19:12:14 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	task_worker_spawn(t_task *task, t_nmap_config *cfg)
{
	if (cfg->debug > 1)
		debug_task(cfg, task, 0);
	if (cfg->speedup)
		start_worker_threads(cfg);
	//TODO: when we get rid of the alarm_handler for timeouts (remove
	//set_alarm_handler() call from main.c)
	/*
	else
		set_alarm_handler();
	*/
}

static void	task_new_host(t_task *task, t_nmap_config *cfg)
{
	t_task          new_task = { .type = E_TASK_LISTEN };

	if (cfg->debug > 1)
		debug_task(cfg, task, 0);
	new_host(cfg);
	//TODO: remove 'cfg->speedup' in condition (when we will be using the same
	//pcap filter in monothreaded runs as in multithreaded runs) and replace
	//'!cfg->end' by checking the return of new_host (make it return something
	//obvioulsy).
	if (!cfg->end && cfg->speedup)
		push_tasks(&cfg->main_tasks,
			ft_lstnew(&new_task, sizeof(new_task)), cfg, 0);
}

static void	task_listen(t_task *task, t_nmap_config *cfg)
{
	int	packet_count;

	if (cfg->debug > 1)
		debug_task(cfg, task, 0);
	if (!cfg->speedup)
	{
		if (task->scan_job->tries < 0)
			return ;
		while (!cfg->end && cfg->current_scan_job >= 0)
		{
			packet_count = ft_listen(NULL, cfg->descr, pcap_handlerf, 0);
			stats_listen(cfg, packet_count);
		}
	}
	else
	{
		while (!cfg->end && !(cfg->host_job.status & E_STATE_DONE))
		{
			packet_count = ft_listen(NULL, cfg->descr, pcap_handlerf, 0);
			stats_listen(cfg, packet_count);
		}
	}
}

static void	task_probe(t_task *task, t_nmap_config *cfg)
{
	if (cfg->debug > 1)
		debug_task(cfg, task, 0);
	if (!cfg->speedup)
	{
		if (task->scan_job->tries < 0)
			return ;
		set_filter(cfg, task->scan_job);
		cfg->current_scan_job = task->scan_job->srcp - PORT_DEF;
		cfg->current_payload_index = task->payload_index;
	}
	if (cfg->verbose)
		verbose_scan(cfg, task->scan_job,
			task->scan_job->probes[task->payload_index], "Sending probe...");
	send_probe(cfg, task->scan_job, task->payload_index);
}

static void	task_reply(t_task *task, t_nmap_config *cfg)
{
	t_list          *lst;
	uint8_t         result;
	t_scan_job		*scan_job = task->scan_job;
	t_task          new_task = { .type = E_TASK_NEW_HOST };

	result = !scan_job ? parse_reply_packet(task, cfg, &scan_job)
		: scan_result(scan_job->type, NULL);
	if (cfg->debug > 1)
		debug_task(cfg, task, result);
	if (result != E_STATE_NONE && update_job(cfg, scan_job, result))
	{
		lst = ft_lstnew(&new_task, sizeof(new_task));
		push_tasks(&cfg->main_tasks, lst, cfg, 0);
		//TODO: remove condition when only one LISTEN task in monothread mode
		if (cfg->speedup)
			pcap_breakloop(cfg->descr);
	}
	ft_memdel((void **)&task->reply);
}

static void	task_worker_wait(t_task *task, t_nmap_config *cfg)
{
	if (cfg->debug > 1)
		debug_task(cfg, task, 0);
	if (cfg->speedup)
		wait_worker_threads(cfg);
	//TODO: uncomment when we get rid of alarm_handler for multithreaded runs
	/*
	else
		alarm(0);
	*/
}

static void	task_print_stats(t_task *task, t_nmap_config *cfg)
{
	double	total_time;

	if (cfg->debug > 1)
		debug_task(cfg, task, 0);
	if (gettimeofday(&cfg->end_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	total_time = ts_msdiff(&cfg->end_ts, &cfg->start_ts) / 1000.0;
	ft_printf("\n--- ft_nmap done ---\n%d address%s scanned in %g seconds\n",
		cfg->host_count, cfg->host_count > 1 ? "es" : "", total_time);
	debug_print(cfg,
		"total packets sent: %d (%g per second)\n"
		"icmp packets received: %d (%g per second)\n"
		"total packets received: %d (%g per second)\n"
		"total listen breaks: %d\n"
		"manual listen breaks: %d\n"
		"listen breaks with 0 packet received: %d\n",
		cfg->sent_packet_count, cfg->sent_packet_count / total_time,
		cfg->icmp_count, cfg->icmp_count / total_time,
		cfg->received_packet_count, cfg->received_packet_count / total_time,
		cfg->listen_breaks_total, cfg->listen_breaks_manual,
		cfg->listen_breaks_zero_packet);
}

const taskf	g_tasks[TASK_COUNT] = {
	[E_TASK_WORKER_SPAWN] = task_worker_spawn,
	[E_TASK_NEW_HOST] = task_new_host,
	[E_TASK_LISTEN] = task_listen,
	[E_TASK_PROBE] = task_probe,
	[E_TASK_REPLY] = task_reply,
	[E_TASK_WORKER_WAIT] = task_worker_wait,
	[E_TASK_PRINT_STATS] = task_print_stats,
};
