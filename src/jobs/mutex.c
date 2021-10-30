/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   mutex.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/02 22:36:08 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/30 10:52:07 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

__thread int	g_probe_locked = 0;
__thread int	g_global_locked = 0;

void	nmap_mutex_lock(pthread_mutex_t *mutex, int *locked)
{
	ft_mutex_lock(mutex);
	*locked = 1;
}

void	nmap_mutex_unlock(pthread_mutex_t *mutex, int *locked)
{
	if (*locked)
	{
		*locked = 0;
		ft_mutex_unlock(mutex);
	}
}
