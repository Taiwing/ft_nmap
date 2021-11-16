/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   task_utils.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 15:14:19 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/16 14:07:59 by yforeau          ###   ########.fr       */
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
		nmap_mutex_unlock(&cfg->high_mutex, &g_high_locked);
}

t_task	*pop_task(t_list **src, int prio)
{
	t_list	*lst = NULL;
	t_task	*task = NULL;

	if (prio)
	{
		nmap_mutex_lock(&cfg->low_mutex, &g_low_locked);
		nmap_mutex_lock(&cfg->high_mutex, &g_high_locked);
	}
	lst = ft_lst_pop(src, 0);
	if (prio)
	{
		nmap_mutex_unlock(&cfg->high_mutex, &g_high_locked);
		nmap_mutex_unlock(&cfg->low_mutex, &g_low_locked);
	}
	if (lst)
		task = (t_task *)lst->content;
	ft_memdel((void **)&lst);
	return (task);
}
