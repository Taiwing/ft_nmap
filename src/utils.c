/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/06 04:35:54 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/16 22:20:02 by yforeau          ###   ########.fr       */
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

const char	*g_nmap_time_unit_strings[] = {
	"ms", "s", "m", "h", NULL
};

const double	g_nmap_time_units[] = {
	1.0, 1000.0, 60000.0, 3600000.0
};

void	str_to_timespec(struct timespec *time, const char *str)
{
	double		ms_value = 0.0;
	int			value = 0, i = 0;
	const char	*unit_str = NULL, *p;

	p = str;
	value = parse_int_prefix(p, 0, INT_MAX, "time value");
	while (ft_isdigit(*p))
		++p;
	unit_str = !*p ? "s" : p;
	while (g_nmap_time_unit_strings[i]
		&& ft_strcmp(unit_str, g_nmap_time_unit_strings[i]))
		++i;
	if (!g_nmap_time_unit_strings[i])
		ft_exit(EXIT_FAILURE, "invalid argument: '%s': '%s' is not a valid "
			"time unit (must be one of: ms, s, m or h)", str, unit_str);
	ms_value = (double)value * g_nmap_time_units[i];
	time->tv_sec = ms_value / 1000;
	time->tv_nsec = (ms_value - time->tv_sec * 1000) * 1000000;
}
