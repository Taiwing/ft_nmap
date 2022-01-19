/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   worker.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/23 21:26:35 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/19 22:13:13 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	worker_exit(void)
{
	nmap_mutex_unlock(&g_cfg->print_mutex, &g_print_locked);
	nmap_mutex_unlock(&g_cfg->high_mutex, &g_high_locked);
	nmap_mutex_unlock(&g_cfg->low_mutex, &g_low_locked);
	nmap_mutex_unlock(&g_cfg->send_mutex, &g_send_locked);
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

	if (gettimeofday(&cfg->worker_thread_config.task_match.exec_time, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	while (!error && cfg->nthreads < cfg->speedup && !cfg->end)
		error = ft_thread_create(cfg->thread + ++cfg->nthreads,
			NULL, worker, &cfg->worker_thread_config);
	if (error)
	{
		--cfg->nthreads;
		ft_exit(EXIT_FAILURE, "pthread_create: %s", strerror(error));
	}
}

void		*worker(void *ptr)
{
	t_task_match	task_match;
	t_task			*task = NULL;
	t_worker_config	*wcfg = (t_worker_config *)ptr;

	ft_memcpy(&task_match, &wcfg->task_match, sizeof(task_match));
	if (wcfg->type == E_WORKER_THREAD)
		ft_atexit(worker_exit);
	while ((task = pop_task(wcfg->task_list, g_cfg,
		wcfg->type == E_WORKER_THREAD, &task_match)))
	{
		g_tasks[task->type](task);
		ft_memdel((void **)&task);
		if (wcfg->type == E_WORKER_PSEUDO_THREAD
			&& is_passed(&wcfg->expiry, NULL))
			break ;
	}
	if (wcfg->type == E_WORKER_MAIN || wcfg->type == E_WORKER_THREAD)
		ft_atexit(NULL);
	return (NULL);
}
