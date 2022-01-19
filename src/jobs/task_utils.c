/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   task_utils.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 15:14:19 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/19 19:54:06 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void			push_back_tasks(t_list **dest, t_list *tasks,
			t_nmap_config *cfg, int prio)
{
	if (!tasks)
		return ;
	if (prio)
		nmap_mutex_lock(&cfg->high_mutex, &g_high_locked);
	if (*dest)
		ft_lst_last(*dest)->next = tasks;
	else
		*dest = tasks;
	if (prio)
	{
		g_cfg->pending_tasks = 1;
		nmap_mutex_unlock(&cfg->high_mutex, &g_high_locked);
	}
}

void			push_front_tasks(t_list **dest, t_list *tasks,
			t_nmap_config *cfg, int prio)
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

static int		valid_task(void *content_ref, void *element)
{
	t_task			*task = (t_task *)element;
	t_task_match	*task_match = (t_task_match *)content_ref;

	if (!(task_match->task_types & task->type))
		return (1);
	if (!task->exec_time.tv_sec || !task_match->exec_time.tv_sec)
		return (0);
	return (!is_passed(&task_match->exec_time, &task->exec_time));
}

static t_task	*get_task(t_list **src, t_task_match *task_match)
{
	t_list			*lst = NULL;
	t_task			*task = NULL;

	if (!(lst = ft_lst_pop_if(src, task_match, valid_task)))
		return (NULL);
	task = (t_task *)lst->content;
	ft_memdel((void **)&lst);
	return (task);
}

t_task			*pop_task(t_list **src, t_nmap_config *cfg, int prio,
		t_task_match *task_match)
{
	t_task	*task = NULL;

	if (!prio)
		return (get_task(src, task_match));
	nmap_mutex_lock(&cfg->low_mutex, &g_low_locked);
	while (!task && !cfg->end)
	{
		if (!g_cfg->pending_tasks)
			continue;
		nmap_mutex_lock(&cfg->high_mutex, &g_high_locked);
		task = get_task(src, task_match);
		if (!*src)
			g_cfg->pending_tasks = 0;
		nmap_mutex_unlock(&cfg->high_mutex, &g_high_locked);
	}
	nmap_mutex_unlock(&cfg->low_mutex, &g_low_locked);
	return (task);
}

void			init_tasks(t_nmap_config *cfg)
{
	t_task	task = { .type = E_TASK_WORKER_SPAWN };
	t_list	*main = NULL;

	main = ft_lstnew(&task, sizeof(task));
	task.type = E_TASK_NEW_HOST;
	ft_lst_last(main)->next = ft_lstnew(&task, sizeof(task));
	task.type = E_TASK_WORKER_WAIT;
	ft_lst_last(main)->next = ft_lstnew(&task, sizeof(task));
	task.type = E_TASK_PRINT_STATS;
	ft_lst_last(main)->next = ft_lstnew(&task, sizeof(task));
	cfg->main_tasks = main;
}
