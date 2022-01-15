/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   mutex.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/02 22:36:08 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/15 22:22:07 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

__thread int	g_print_locked = 0;
__thread int	g_high_locked = 0;
__thread int	g_low_locked = 0;
__thread int	g_send_locked = 0;

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
