/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   worker.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/23 21:26:35 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/18 16:33:30 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	worker_exit(void)
{
	nmap_mutex_unlock(&g_cfg->print_mutex, &g_print_locked);
	nmap_mutex_unlock(&g_cfg->high_mutex, &g_high_locked);
	nmap_mutex_unlock(&g_cfg->low_mutex, &g_low_locked);
	if (g_cfg->verbose > 2)
		ft_printf("worker_exit - worker %llu (%llx)!\n",
			ft_thread_self(), pthread_self());
	g_cfg->end = 1;
	ft_thread_exit();
}

void		wait_workers(t_nmap_config *cfg)
{
	uint64_t	nthreads;

	if ((nthreads = ft_thread_count()))
	{
		cfg->end = 1;
		for (uint8_t i = 0; i < nthreads; ++i)
			ft_thread_join(cfg->thread + i + 1, NULL);
		cfg->speedup = 0;
	}
}

void		start_workers(t_nmap_config *cfg)
{
	int			ret;

	for (uint8_t i = 0; i < cfg->speedup && !cfg->end; ++i)
		if ((ret = ft_thread_create(cfg->thread + i + 1, NULL, worker, cfg)))
			ft_exit(EXIT_FAILURE, "pthread_create: %s", strerror(ret));
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
