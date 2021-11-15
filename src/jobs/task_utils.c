/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   task_utils.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 15:14:19 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 15:36:46 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	push_tasks(t_list **dest, t_list *tasks, t_nmap_config *cfg, int prio)
{
	if (prio)
		ft_lock_mutex(&cfg->high_mutex);
	ft_lst_move_to_back(NULL, &tasks, dest);
	if (prio)
		ft_unlock_mutex(&cfg->high_mutex);
}

t_task	*pop_task(t_list **src, int prio)
{
	t_list	*lst = NULL;
	t_task	*task = NULL;

	if (prio)
	{
		ft_lock_mutex(&cfg->low_mutex);
		ft_lock_mutex(&cfg->high_mutex);
	}
	lst = ft_lst_pop(src, 0);
	if (prio)
	{
		ft_unlock_mutex(&cfg->high_mutex);
		ft_unlock_mutex(&cfg->low_mutex);
	}
	if (lst)
		task = (t_task *)lst->content;
	ft_memdel((void **)&lst);
	return (task);
}
