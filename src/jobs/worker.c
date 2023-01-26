/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   worker.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/23 21:26:35 by yforeau           #+#    #+#             */
/*   Updated: 2023/01/26 21:36:24 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	worker_exit(void)
{
	nmap_mutex_unlock(&g_cfg->print_mutex, &g_print_locked);
	nmap_mutex_unlock(&g_cfg->high_mutex, &g_high_locked);
	nmap_mutex_unlock(&g_cfg->low_mutex, &g_low_locked);
	nmap_mutex_unlock(&g_cfg->send_mutex, &g_send_locked);
	nmap_mutex_unlock(&g_cfg->rtt_mutex, &g_rtt_locked);
	if (g_cfg->debug > 1)
		debug_print(g_cfg, "worker_exit - worker %llu (%llx)!\n",
			ft_thread_self(), pthread_self());
	g_cfg->end = 1;
	ft_thread_exit();
}

void		wait_worker_threads(t_nmap_config *cfg)
{
	cfg->end = 1;
	while (cfg->nthreads)
		ft_thread_join(cfg->thread + cfg->nthreads--, NULL);
	cfg->speedup = 0;
}

void		start_worker_threads(t_nmap_config *cfg)
{
	int				error = 0;

	while (!error && cfg->nthreads < cfg->speedup && !cfg->end)
		error = ft_thread_create(cfg->thread + ++cfg->nthreads,
			NULL, worker, &cfg->worker_thread_config);
	if (error)
	{
		--cfg->nthreads;
		ft_exit(EXIT_FAILURE, "pthread_create: %s", strerror(error));
	}
}

# define	MAX_PSEUDO_THREAD_TASKS	16

void		pseudo_thread_worker(int task_max)
{
	t_worker_config	wcfg = {
		.type = E_WORKER_PSEUDO_THREAD,
		.task_list = &g_cfg->thread_tasks,
		.task_types = WORKER_TASKS,
		.task_max = task_max <= 0 || task_max > MAX_PSEUDO_THREAD_TASKS ?
			MAX_PSEUDO_THREAD_TASKS : task_max,
	};

	worker(&wcfg);
}

void		*worker(void *ptr)
{
	t_task			*task = NULL;
	t_worker_config	*wcfg = (t_worker_config *)ptr;
	t_task_match	task_match = { .task_types = wcfg->task_types };

	if (wcfg->type == E_WORKER_THREAD)
		ft_atexit(worker_exit);
	while ((task = pop_task(wcfg->task_list, g_cfg,
		wcfg->type == E_WORKER_THREAD, &task_match)))
	{
		++g_cfg->running_tasks;
		g_tasks[task->type](task);
		--g_cfg->running_tasks;
		ft_memdel((void **)&task);
		if (wcfg->type == E_WORKER_PSEUDO_THREAD && --wcfg->task_max <= 0)
			break;
	}
	if (wcfg->type == E_WORKER_MAIN || wcfg->type == E_WORKER_THREAD)
		ft_atexit(NULL);
	return (NULL);
}
