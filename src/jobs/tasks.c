/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tasks.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 10:45:13 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/17 16:33:16 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	task_thread_spawn(t_task *task, t_nmap_config *cfg)
{
	(void)task;
	start_workers(cfg);
}

static void	task_listen(t_task *task, t_nmap_config *cfg)
{
	(void)task;
	ft_listen(NULL, cfg->descr, pcap_handler, 0);
}

static void	task_new_host(t_task *task, t_nmap_config *cfg)
{
	(void)task;
	new_host(cfg);
}

static void	task_probe(t_task *task, t_nmap_config *cfg)
{
	t_list	*new_task;

	if (cfg->verbose)
		verbose_scan(cfg, task->probe, task->probe->packet, "Sending probe...");
	send_probe(cfg, task->probe);
}

static void	task_reply(t_task *task, t_nmap_config *cfg)
{
	t_list	*new_task;

	if (update_job(cfg, task))
	{
		task->type = E_TASK_NEW_HOST;
		task->probe = NULL;
		task->result = 0;
		new_task = ft_lstnew(task, sizeof(t_task));
		if (cfg->speedup)
			push_tasks(&cfg->worker_tasks, new_task, 1);
		else
			push_tasks(&cfg->main_tasks, new_task, 0);
	}
}

static void	task_thread_wait(t_task *task, t_nmap_config *cfg)
{
	(void)task;
	wait_workers(cfg);
}

const taskf	g_tasks[TASK_COUNT] = {
	[E_TASK_THREAD_SPAWN] = task_thread_spawn,
	[E_TASK_LISTEN] = task_listen,
	[E_TASK_NEW_HOST] = task_new_host,
	[E_TASK_PROBE] = task_probe,
	[E_TASK_REPLY] = task_reply,
	[E_TASK_THREAD_WAIT] = task_thread_wait,
};
