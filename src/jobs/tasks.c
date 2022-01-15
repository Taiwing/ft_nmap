/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tasks.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 10:45:13 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/15 20:32:56 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	task_thread_spawn(t_task *task, t_nmap_config *cfg)
{
	if (cfg->debug > 1)
		debug_task(cfg, task, 0);
	start_workers(cfg);
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
		while (!cfg->end)
		{
			packet_count = ft_listen(NULL, cfg->descr, pcap_handlerf, 0);
			stats_listen(cfg, packet_count);
		}
	}
}

static void	task_new_host(t_task *task, t_nmap_config *cfg)
{
	if (cfg->debug > 1)
		debug_task(cfg, task, 0);
	new_host(cfg);
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
		lst = ft_lstnew(&new_task, sizeof(t_task));
		if (cfg->speedup)
			push_tasks(&cfg->worker_tasks, lst, cfg, 1);
		else
			push_tasks(&cfg->main_tasks, lst, cfg, 0);
	}
	ft_memdel((void **)&task->reply);
}

static void	task_thread_wait(t_task *task, t_nmap_config *cfg)
{
	if (cfg->debug > 1)
		debug_task(cfg, task, 0);
	wait_workers(cfg);
}

static void	task_print_stats(t_task *task, t_nmap_config *cfg)
{
	double	total_time;

	if (cfg->debug > 1)
		debug_task(cfg, task, 0);
	if (gettimeofday(&cfg->end_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	total_time = ts_msdiff(&cfg->end_ts, &cfg->start_ts);
	ft_printf("\n--- ft_nmap done ---\n%d address%s scanned in %g seconds\n",
		cfg->host_count, cfg->host_count > 1 ? "es" : "", total_time / 1000.0);
	debug_print(cfg,
		"pcap received packet count: %d\n"
		"total listen breaks: %d\n"
		"manual listen breaks: %d\n"
		"listen breaks with 0 packet received: %d\n"
		"icmp packets received: %d (%g per second)\n",
		cfg->received_packet_count, cfg->listen_breaks_total,
		cfg->listen_breaks_manual, cfg->listen_breaks_zero_packet,
		cfg->icmp_count, cfg->icmp_count / (total_time / 1000.0));
}

const taskf	g_tasks[TASK_COUNT] = {
	[E_TASK_THREAD_SPAWN] = task_thread_spawn,
	[E_TASK_LISTEN] = task_listen,
	[E_TASK_NEW_HOST] = task_new_host,
	[E_TASK_PROBE] = task_probe,
	[E_TASK_REPLY] = task_reply,
	[E_TASK_THREAD_WAIT] = task_thread_wait,
	[E_TASK_PRINT_STATS] = task_print_stats,
};
