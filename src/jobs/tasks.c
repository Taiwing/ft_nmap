/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tasks.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 10:45:13 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/23 12:37:47 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	task_worker_spawn(t_task *task)
{
	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (g_cfg->speedup)
		start_worker_threads(g_cfg);
	set_alarm_handler();
}

static void	task_new_host(t_task *task)
{
	t_task          new_task = { .type = E_TASK_LISTEN };

	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (new_host(g_cfg))
		push_front_tasks(&g_cfg->main_tasks,
			ft_lstnew(&new_task, sizeof(new_task)), g_cfg, 0);
}

static void	task_listen(t_task *task)
{
	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	while (!g_cfg->end && !g_cfg->listen_breakloop)
		ft_listen(NULL, g_cfg->descr, pcap_handlerf, 0);
	g_cfg->listen_breakloop = 0;
}

static void	task_probe(t_task *task)
{
	struct timeval	exec_time = { 0 };

	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (task->scan_job->tries < 0)
		return ;
	else
		--task->scan_job->tries;
	if (g_cfg->verbose)
		verbose_scan(g_cfg, task->scan_job,
			task->scan_job->probes[task->payload_index], "Sending probe...");
	send_probe(g_cfg, task->scan_job, task->payload_index);
	if (!task->payload_index)
	{
		probe_retry_time(&exec_time);
		if (task->scan_job->tries > 0)
			init_scan_job_probes(g_cfg, task->scan_job, &exec_time);
		else if (!task->scan_job->tries)
			set_scan_job_timeout(g_cfg, task->scan_job, &exec_time);
	}
}

static void	task_reply(t_task *task)
{
	t_list          *lst;
	uint8_t         result;
	t_scan_job		*scan_job = task->scan_job;
	t_task          new_task = { .type = E_TASK_NEW_HOST };

	result = !scan_job ? parse_reply_packet(task, g_cfg, &scan_job)
		: scan_result(scan_job->type, NULL);
	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, result);
	if (result != E_STATE_NONE && update_job(g_cfg, scan_job, result))
	{
		lst = ft_lstnew(&new_task, sizeof(new_task));
		push_front_tasks(&g_cfg->main_tasks, lst, g_cfg, !!g_cfg->speedup);
		g_cfg->listen_breakloop = 1;
		if (!g_cfg->speedup)
			pcap_breakloop(g_cfg->descr);
	}
	ft_memdel((void **)&task->reply);
}

static void	task_worker_wait(t_task *task)
{
	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (g_cfg->speedup)
		wait_worker_threads(g_cfg);
	else
		alarm(0);
}

static void	task_print_stats(t_task *task)
{
	double	total_time;

	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (gettimeofday(&g_cfg->end_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	total_time = ts_msdiff(&g_cfg->end_ts, &g_cfg->start_ts) / 1000.0;
	ft_printf("\n--- ft_nmap done ---\n%d address%s scanned in %g seconds\n",
		g_cfg->host_count, g_cfg->host_count > 1 ? "es" : "", total_time);
	debug_print(g_cfg,
		"total packets sent: %d (%g per second)\n"
		"icmp packets received: %d (%g per second)\n"
		"total packets received: %d (%g per second)\n",
		g_cfg->sent_packet_count, g_cfg->sent_packet_count / total_time,
		g_cfg->icmp_count, g_cfg->icmp_count / total_time,
		g_cfg->received_packet_count,
		g_cfg->received_packet_count / total_time);
}

const taskf	g_tasks[] = {
	[E_TASK_WORKER_SPAWN] = task_worker_spawn,
	[E_TASK_NEW_HOST] = task_new_host,
	[E_TASK_LISTEN] = task_listen,
	[E_TASK_PROBE] = task_probe,
	[E_TASK_REPLY] = task_reply,
	[E_TASK_WORKER_WAIT] = task_worker_wait,
	[E_TASK_PRINT_STATS] = task_print_stats,
};
