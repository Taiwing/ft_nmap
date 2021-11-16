/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tasks.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 10:45:13 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/16 10:28:24 by yforeau          ###   ########.fr       */
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
	t_packet	reply = { 0 };

	(void)task;
	ft_listen(&reply, cfg->descr, grab_reply);
}

static void	task_new_host(t_task *task, t_nmap_config *cfg)
{
	(void)task;
	new_host(cfg);
}

static void	task_probe(t_task *task, t_nmap_config *cfg)
{
	send_probe(cfg, task->probe);
}

static void	task_reply(t_task *task, t_nmap_config *cfg)
{
	uint8_t	result = scan_result(task->probe->scan_type, task->reply);	

	ft_memdel((void **)&task->reply);
	update_job(cfg, task, result);
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
