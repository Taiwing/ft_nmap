/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tasks.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 10:45:13 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/13 07:08:48 by yforeau          ###   ########.fr       */
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
		if (task->scan_job->retry < 0)
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

pthread_mutex_t g_shitty_mutex = PTHREAD_MUTEX_INITIALIZER;

static void	task_probe(t_task *task, t_nmap_config *cfg)
{
	if (cfg->debug > 1)
		debug_task(cfg, task, 0);
	if (!cfg->speedup)
	{
		if (task->scan_job->retry < 0)
			return ;
		set_filter(cfg, task->scan_job);
		cfg->current_scan_job = task->scan_job->srcp - PORT_DEF;
		cfg->current_payload_index = task->payload_index;
	}
	if (cfg->verbose)
		verbose_scan(cfg, task->scan_job,
			task->scan_job->probes[task->payload_index], "Sending probe...");
	//TEMP
	ft_mutex_lock(&g_shitty_mutex);
	send_probe(cfg, task->scan_job, task->payload_index);
	//shitty_usleep(1);
	struct timespec	sleep_time = { .tv_sec = 0, .tv_nsec = 500000 };
	nanosleep(&sleep_time, NULL);
	ft_mutex_unlock(&g_shitty_mutex);
	//TEMP
	//send_probe(cfg, task->scan_job, task->payload_index);
}

static void	task_probe_all(t_task *task, t_nmap_config *cfg)
{
	t_scan_job		*scan_job;
	uint16_t		sent_count = 0;
	struct timeval	start_ts = { 0 }, end_ts = { 0 };

	(void)task;
	if (gettimeofday(&start_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	for (uint16_t scan = 0; scan < SCAN_COUNT; ++scan)
	{
		if (!cfg->scans[scan])
			continue ;
		for (uint16_t port = 0; port < cfg->nports; ++port)
		{
			scan_job = &cfg->host_job.port_jobs[port].scan_jobs[scan];
			if (scan_job->status & E_STATE_DONE)
				continue ;
			for (uint16_t i = 0; scan_job->probes[i]; ++i, ++sent_count)
				send_probe(cfg, scan_job, i);
		}
	}
	if (gettimeofday(&end_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	double time = ts_msdiff(&end_ts, &start_ts);
	ft_printf("time TASK_PROBE_ALL: %hu probes sent in %g ms\n", sent_count, time);
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
		"listen breaks with 0 packet received: %d\n",
		cfg->received_packet_count, cfg->listen_breaks_total,
		cfg->listen_breaks_manual, cfg->listen_breaks_zero_packet);
}

const taskf	g_tasks[TASK_COUNT] = {
	[E_TASK_THREAD_SPAWN] = task_thread_spawn,
	[E_TASK_LISTEN] = task_listen,
	[E_TASK_NEW_HOST] = task_new_host,
	[E_TASK_PROBE] = task_probe,
	[E_TASK_PROBE_ALL] = task_probe_all,
	[E_TASK_REPLY] = task_reply,
	[E_TASK_THREAD_WAIT] = task_thread_wait,
	[E_TASK_PRINT_STATS] = task_print_stats,
};
