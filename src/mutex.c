/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   mutex.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/02 22:36:08 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/02 22:39:17 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

__thread int	g_locked = 0;

void	nmap_mutex_lock(pthread_mutex_t *mutex)
{
	ft_mutex_lock(mutex);
	g_locked = 1;
}

void	nmap_mutex_unlock(pthread_mutex_t *mutex)
{
	if (g_locked)
	{
		g_locked = 0;
		ft_mutex_unlock(mutex);
	}
}
