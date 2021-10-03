/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   worker.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/23 21:26:35 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/03 16:06:39 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	exec_scan(t_scan *scan)
{
	//TEMP
	char		buf[64] = { 0 };
	uint64_t	randval = 0;

	if (scan->cfg->speedup
		&& !ft_rand_uint64(&randval, 0, (uint64_t)scan->cfg->speedup))
		ft_exit("ft_rand_uint64: error", 0, EXIT_FAILURE);
	if (scan->cfg->speedup && ft_thread_self() == randval)
	{
		ft_snprintf(buf, 64, "WOOOOW!!! exiting worker %llu (%llx)!\n",
			ft_thread_self(), pthread_self());
		ft_exit(buf, 0, 123);
	}
	if (scan->cfg->speedup < 10)
		sleep(randval);
	else if (scan->cfg->speedup < 100)
		sleep(randval / 10);
	else
		sleep(randval / 25);
	if (!ft_rand_uint64(&randval, 0, 4))
		ft_exit("ft_rand_uint64: error", 0, EXIT_FAILURE);
	if (!randval)
		scan->result = STATE_OPEN;
	else if (randval == 1)
		scan->result = STATE_CLOSED;
	else if (randval == 2)
		scan->result = STATE_FILTERED;
	else if (randval == 3)
		scan->result = STATE_UNFILTERED;
	else
		scan->result = STATE_OPEN | STATE_FILTERED;
	//TEMP
}

static void	worker_exit(void)
{
	nmap_mutex_unlock(&g_cfg->mutex);
	//TEMP
	ft_printf("worker_exit - worker %llu (%llx)!\n",
		ft_thread_self(), pthread_self());
	//TEMP
	ft_thread_exit();
}

void		*worker(void *ptr)
{
	t_scan			*scan;

	if (ft_thread_self())
		ft_atexit(worker_exit);
	scan = (t_scan *)ptr;
	do
	{
		exec_scan(scan);
		update_job(scan);
	} while (next_scan(scan) && !ft_thread_error());
	return (NULL);
}
