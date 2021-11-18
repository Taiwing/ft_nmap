/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   worker.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/23 21:26:35 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/18 19:01:22 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	worker_exit(void)
{
	nmap_mutex_unlock(&g_cfg->print_mutex, &g_print_locked);
	nmap_mutex_unlock(&g_cfg->high_mutex, &g_high_locked);
	nmap_mutex_unlock(&g_cfg->low_mutex, &g_low_locked);
	if (g_cfg->debug)
		ft_printf("worker_exit - worker %llu (%llx)!\n",
			ft_thread_self(), pthread_self());
	g_cfg->end = 1;
	ft_thread_exit();
}

void		wait_workers(t_nmap_config *cfg)
{
	cfg->end = 1;
	while (cfg->nthreads)
		ft_thread_join(cfg->thread + cfg->nthreads--, NULL);
	cfg->speedup = 0;
}

void		start_workers(t_nmap_config *cfg)
{
	int					e;

	while (cfg->nthreads < cfg->speedup && !cfg->end)
	{
		e = ft_thread_create(cfg->thread + ++cfg->nthreads, NULL, worker, cfg);
		if (e)
		{
			--cfg->nthreads;
			ft_exit(EXIT_FAILURE, "pthread_create: %s", strerror(e));
		}
	}
}

void		*worker(void *ptr)
{
	t_nmap_config	*cfg;
	t_list			**task_list;
	t_task			*task = NULL;
	uint64_t		is_worker_thread;

	cfg = (t_nmap_config *)ptr;
	if ((is_worker_thread = ft_thread_self()))
		ft_atexit(worker_exit);
	task_list = is_worker_thread ? &cfg->worker_tasks : &cfg->main_tasks;
	while ((task = pop_task(task_list, cfg, is_worker_thread)))
	{
		g_tasks[task->type](task, cfg);
		ft_memdel((void **)&task);
	}
	ft_atexit(NULL);
	return (NULL);
}
