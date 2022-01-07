/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/06 04:35:54 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/07 12:04:28 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*
** ts_msdiff: timestamp ms substraction
**
** Substracts b from a and returns the result in ms.
*/
double	ts_msdiff(struct timeval *a, struct timeval *b)
{
	double s;
	double us;

	s = ((double)(a->tv_sec - b->tv_sec)) * 1000.0;
	us = ((double)(a->tv_usec - b->tv_usec)) / 1000.0;
	return (s + us);
}

/*
** shitty_usleep: 'sleep' for ms shitty busy waiting milliseconds
**
** To be used with a shitty mutex to synchronize send calls.
*/
void	shitty_usleep(uint64_t ms)
{
	struct timeval	start, end;
	double			diff = 0;

	if (gettimeofday(&start, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	do {
		if (gettimeofday(&end, NULL) < 0)
			ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
		diff = ts_msdiff(&end, &start);
	} while (diff < (double)ms);
}
