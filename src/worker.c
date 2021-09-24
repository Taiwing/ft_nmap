/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   worker.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/23 21:26:35 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/24 02:10:48 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	exec_scan(t_scan *scan)
{
	//TEMP
	uint64_t	randval;

	if (!ft_rand_uint64(&randval, 0, (uint64_t)scan->cfg->speedup - 1))
		ft_exit("ft_rand_uint64: error\n", EXIT_FAILURE);
	ft_printf("Thread number %hhu (randval: %u)\n", scan->id, randval);
	if (scan->id == randval)
		ft_exit("WOOOOW!!!!", 123);
	sleep(randval);
	if (!ft_rand_uint64(&randval, 0, 4))
		ft_exit("ft_rand_uint64: error\n", EXIT_FAILURE);
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

void		*worker(void *ptr)
{
	t_scan			*scan;

	scan = (t_scan *)ptr;
	do
	{
		exec_scan(scan);
		update_job(scan); //TODO
	} while (next_scan(scan));
	return (NULL);
}
