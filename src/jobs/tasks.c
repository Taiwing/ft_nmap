/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tasks.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 10:45:13 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/06 11:40:20 by yforeau          ###   ########.fr       */
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
	t_task          new_task = { .type = E_TASK_LISTEN };

	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (new_host(g_cfg))
		push_front_tasks(&g_cfg->main_tasks,
			ft_lstnew(&new_task, sizeof(new_task)), g_cfg, 0);
}

static void	task_listen(t_task *task)
{
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
		//while (ft_listen(listen_fds, SOCKET_RECV_COUNT, 0) > 0);
		ft_listen(listen_fds, SOCKET_RECV_COUNT, 0);
		if (!g_cfg->speedup)
			pseudo_thread_worker();
	}
	g_cfg->listen_breakloop = 0;
}

static void	task_probe(t_task *task)
{
	int				tries;
	int				payload_index;
	struct timeval	retry_ts = { 0 };

	if (g_cfg->host_job.status & E_STATE_DONE)
		return ;
	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, 0);
	if (task->scan_job->tries < 0)
		return ;
	tries = --task->scan_job->tries;
	payload_index = (tries + 1) % task->scan_job->probe_count;
	if (g_cfg->verbose)
		verbose_scan(g_cfg, task->scan_job,
			task->scan_job->probes[payload_index], "Sending probe...");
	send_probe(g_cfg, task->scan_job, payload_index);
	probe_retry_time(&task->scan_job->sent_ts, &retry_ts);
	if (tries > 0)
		push_probe_task(g_cfg, task->scan_job, &retry_ts);
	else
		set_scan_job_timeout(g_cfg, task->scan_job, &retry_ts);
}

static void	task_reply(t_task *task)
{
	t_list          *lst;
	uint8_t         result;
	t_scan_job		*scan_job = task->scan_job;
	enum e_iphdr	iph = task->reply_ip_header;
	t_task          new_task = { .type = E_TASK_NEW_HOST };

	if (g_cfg->host_job.status & E_STATE_DONE)
		return ;
	result = !scan_job ? parse_reply_packet(task, g_cfg, &scan_job, iph)
		: scan_result(scan_job->type, NULL);
	if (g_cfg->debug > 1)
		debug_task(g_cfg, task, result);
	if (result != E_STATE_NONE && update_job(g_cfg, scan_job, result))
	{
		lst = ft_lstnew(&new_task, sizeof(new_task));
		push_front_tasks(&g_cfg->main_tasks, lst, g_cfg, !!g_cfg->speedup);
		g_cfg->listen_breakloop = 1;
	}
	else if (result != E_STATE_NONE && !task->scan_job)
		rtt_update(&scan_job->sent_ts, &task->reply_time);
	ft_memdel((void **)&task->reply);
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
