/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tasks.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 10:45:13 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 15:06:20 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	task_thread_spawn(t_task *task)
{
	start_workers(task->cfg);
}

static void	task_listen(t_task *task)
{
	t_packet	reply = { 0 };

	ft_listen(&reply, task->cfg->descr, grab_reply);
}

static void	task_new_host(t_task *task)
{
	new_host(task->cfg);
}

static void	task_probe(t_task *task)
{
	send_probe(task->cfg, task->probe);
}

static void	task_reply(t_task *task)
{
	
}

static void	task_thread_wait(t_task *task)
{
	wait_workers(task->cfg);
}

const taskf	g_tasks[TASK_COUNT] = {
	[E_TASK_THREAD_SPAWN] = task_thread_spawn,
	[E_TASK_LISTEN] = task_listen,
	[E_TASK_NEW_HOST] = task_new_host,
	[E_TASK_PROBE] = task_probe,
	[E_TASK_REPLY] = task_reply,
	[E_TASK_THREAD_WAIT] = task_thread_wait,
};
