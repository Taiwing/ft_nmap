/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tasks.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 10:45:13 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/13 16:52:23 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	task_worker_spawn(t_task *task)
{
	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (g_cfg->speedup)
		start_worker_threads(g_cfg);
}

static void	task_new_host(t_task *task)
{
	t_task          listen_task = { .type = E_TASK_LISTEN };

	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (new_host(g_cfg))
		push_front_tasks(&g_cfg->main_tasks,
			ft_lstnew(&listen_task, sizeof(listen_task)), g_cfg, 0);
}

static void	task_listen(t_task *task)
{
	int				reply_count;
	uint16_t		family = g_cfg->host_job.family;
	struct pollfd	listen_fds[SOCKET_RECV_COUNT] = { 0 };

	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	for (int i = 0; i < SOCKET_RECV_COUNT; ++i)
	{
		if (SOCKET_SRECV_IS_IPV4(i) && family != AF_INET)
			listen_fds[i].fd = -1;
		else if (SOCKET_SRECV_IS_IPV6(i) && family != AF_INET6)
			listen_fds[i].fd = -1;
		else
		{
			listen_fds[i].events = POLLIN;
			listen_fds[i].fd = g_cfg->recv_sockets[i];
		}
	}
	while (!g_cfg->end && !g_cfg->listen_breakloop)
	{
		reply_count = ft_listen(listen_fds, SOCKET_RECV_COUNT, 0);
		if (!g_cfg->speedup && !reply_count)
			pseudo_thread_worker();
	}
	g_cfg->listen_breakloop = 0;
}

static void	task_probe(t_task *task)
{
	int				payload_index;
	int				tries = task->scan_job->tries;
	t_task			timeout_task = {
		.type = E_TASK_TIMEOUT, .scan_job = task->scan_job,
	};

	if (g_cfg->host_job.status & E_STATE_DONE || tries < 0)
		return ;
	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	payload_index = tries % task->scan_job->probe_count;
	if (g_cfg->verbose)
		verbose_scan(g_cfg, task->scan_job,
			task->scan_job->probes[payload_index], "Sending probe...");
	send_probe(g_cfg, task->scan_job, payload_index);
	probe_timeout(&task->scan_job->sent_ts, &timeout_task.exec_time);
	push_task(&g_cfg->thread_tasks, g_cfg, &timeout_task, 0);
}

static void	task_reply(t_task *task)
{
	uint8_t         result;
	int				timeout = !!task->scan_job;
	t_scan_job		*scan_job = task->scan_job;
	enum e_iphdr	iph = task->reply_ip_header;
	t_task          new_host_task = { .type = E_TASK_NEW_HOST };

	if (g_cfg->host_job.status & E_STATE_DONE)
		return ;
	if (timeout)
		result = scan_result(scan_job->type, NULL);
	else
		result = parse_reply_packet(task, g_cfg, &scan_job, iph);
	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, result);
	if (result != E_STATE_NONE && update_job(g_cfg, scan_job, result, timeout))
	{
		push_task(&g_cfg->main_tasks, g_cfg, &new_host_task, 1);
		g_cfg->listen_breakloop = 1;
	}
	else if (result != E_STATE_NONE && !timeout)
		rtt_update(&scan_job->sent_ts, &task->reply_time);
	ft_memdel((void **)&task->reply);
}

static void	task_timeout(t_task *task)
{
	t_task	probe_task = { .type = E_TASK_PROBE, .scan_job = task->scan_job };

	if (g_cfg->host_job.status & E_STATE_DONE || task->scan_job->tries < 0)
		return ;
	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (--task->scan_job->tries > 0)
	{
		update_window(&g_cfg->window[task->scan_job->type], 1);
		push_task(&g_cfg->thread_tasks, g_cfg, &probe_task, 0);
	}
	else
	{
		task->type = E_TASK_REPLY;
		task_reply(task);
	}
}

static void	task_worker_wait(t_task *task)
{
	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (g_cfg->speedup)
		wait_worker_threads(g_cfg);
}

static void	task_print_stats(t_task *task)
{
	double	total_time;

	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (g_cfg->end)
		total_time = print_end_stats();
	else
		total_time = print_update_stats();
	debug_print(g_cfg,
		"total packets sent: %d (%g per second)\n"
		"icmp packets received: %d (%g per second)\n"
		"total packets received: %d (%g per second)\n",
		g_cfg->sent_packet_count,
		total_time ? g_cfg->sent_packet_count / total_time : -1,
		g_cfg->icmp_count,
		total_time ? g_cfg->icmp_count / total_time : -1,
		g_cfg->received_packet_count,
		total_time ? g_cfg->received_packet_count / total_time : -1);
}

const taskf	g_tasks[] = {
	[E_TASK_WORKER_SPAWN] = task_worker_spawn,
	[E_TASK_NEW_HOST] = task_new_host,
	[E_TASK_LISTEN] = task_listen,
	[E_TASK_PROBE] = task_probe,
	[E_TASK_REPLY] = task_reply,
	[E_TASK_TIMEOUT] = task_timeout,
	[E_TASK_WORKER_WAIT] = task_worker_wait,
	[E_TASK_PRINT_STATS] = task_print_stats,
};
