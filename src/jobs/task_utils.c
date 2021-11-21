/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   task_utils.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 15:14:19 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/18 19:40:10 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	push_tasks(t_list **dest, t_list *tasks, t_nmap_config *cfg, int prio)
{
	if (!tasks)
		return ;
	if (prio)
		nmap_mutex_lock(&cfg->high_mutex, &g_high_locked);
	if (*dest)
		ft_lst_last(tasks)->next = *dest;
	*dest = tasks;
	if (prio)
	{
		g_cfg->pending_tasks = 1;
		nmap_mutex_unlock(&cfg->high_mutex, &g_high_locked);
	}
}

//TODO: Design the "waiting for a task" system (maybe directly with pthread
//conditions or just like that for the test). See if the two high/low lock
//setup is appropriate for waiting.
t_task	*pop_task(t_list **src, t_nmap_config *cfg, int prio)
{
	t_list	*lst = NULL;
	t_task	*task = NULL;

	if (!prio)
	{
		if ((lst = ft_lst_pop(src, 0)))
			task = (t_task *)lst->content;
		ft_memdel((void **)&lst);
		return (task);
	}
	nmap_mutex_lock(&cfg->low_mutex, &g_low_locked);
	while (!lst && !cfg->end)
	{
		if (!g_cfg->pending_tasks)
			continue;
		nmap_mutex_lock(&cfg->high_mutex, &g_high_locked);
		lst = ft_lst_pop(src, 0);
		if (!*src)
			g_cfg->pending_tasks = 0;
		nmap_mutex_unlock(&cfg->high_mutex, &g_high_locked);
	}
	nmap_mutex_unlock(&cfg->low_mutex, &g_low_locked);
	task = lst ? (t_task *)lst->content : task;
	ft_memdel((void **)&lst);
	return (task);
}

void	init_tasks(t_nmap_config *cfg)
{
	t_task	task = { E_TASK_NEW_HOST, NULL, 0 };
	t_list	*main = NULL;
	t_list	*workers = NULL;

	if (cfg->speedup)
	{
		main = ft_lstnew(&task, sizeof(task));
		task.type = E_TASK_THREAD_SPAWN;
		ft_lst_last(main)->next = ft_lstnew(&task, sizeof(task));
		task.type = E_TASK_LISTEN;
		ft_lst_last(main)->next = ft_lstnew(&task, sizeof(task));
		task.type = E_TASK_THREAD_WAIT;
		ft_lst_last(main)->next = ft_lstnew(&task, sizeof(task));
	}
	else
		main = ft_lstnew(&task, sizeof(task));
	cfg->main_tasks = main;
	cfg->worker_tasks = workers;
}
