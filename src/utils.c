/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/06 04:35:54 by yforeau           #+#    #+#             */
/*   Updated: 2022/03/15 16:26:01 by yforeau          ###   ########.fr       */
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
** shitty_usleep: shitty 'sleep' for some shitty timeval time
**
** To be used with a shitty mutex to synchronize shitty send calls.
*/
void	shitty_usleep(struct timeval *time)
{
	struct timeval	start, end, diff;

	if (gettimeofday(&start, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	do {
		if (gettimeofday(&end, NULL) < 0)
			ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
		if (ft_timeval_sub(&diff, &end, &start) < 0)
			ft_exit(EXIT_FAILURE, "ft_timeval_sub: %s", ft_strerror(ft_errno));
	} while (ft_timeval_cmp(time, &diff) > 0);
}

#define	UNITS_COUNT	5
const char	*g_nmap_time_unit_strings[] = { "us", "ms", "s", "m", "h", NULL };
const int	g_nmap_us_time_units[] = { 1, 1000 };
const int	g_nmap_s_time_units[] = { 1, 60, 3600 };

//TODO: maybe one day define a MAX_TIME_VALUE per time unit because this is a
//bit rough for smaller units which can't go above ~500000
#define MAX_TIME_VALUE	(INT_MAX / g_nmap_s_time_units[2])

void	str_to_timeval(struct timeval *time, const char *str)
{
	const char	*unit_str = NULL, *p;
	int			i = 0, value = 0, second = 1;

	p = str;
	value = parse_int_prefix(p, 0, MAX_TIME_VALUE, "time value");
	while (ft_isdigit(*p))
		++p;
	unit_str = !*p ? "s" : p;
	while (g_nmap_time_unit_strings[i]
		&& ft_strcmp(unit_str, g_nmap_time_unit_strings[i]))
		++i;
	if (!g_nmap_time_unit_strings[i])
		ft_exit(EXIT_FAILURE, "invalid argument: '%s': '%s' is not a valid "
			"time unit (must be one of: us, ms, s, m or h)", str, unit_str);
	if (i < 2)
		second = 1000000 / g_nmap_us_time_units[i];
	else
		value *= g_nmap_s_time_units[i - 2];
	time->tv_sec = value / second;
	time->tv_usec = (value % second) * g_nmap_us_time_units[i < 2 ? i : 0];
}

int		timeval_to_str(char *buf, size_t size, struct timeval *time)
{
	int64_t	us, ms, s, m, h, sign;

	sign = time->tv_sec < 0 || time->tv_usec < 0 ? -1 : 1;
	h = time->tv_sec / g_nmap_s_time_units[2] * sign;
	m = (time->tv_sec % g_nmap_s_time_units[2]) / g_nmap_s_time_units[1] * sign;
	s = (time->tv_sec % g_nmap_s_time_units[1]) * sign;
	ms = time->tv_usec / g_nmap_us_time_units[1] * sign;
	us = (time->tv_usec % g_nmap_us_time_units[1]) * sign;
	if (h)
		return (ft_snprintf(buf, size, "%s%lldh %02lldm",
			sign < 0 ? "-" : "", h, m));
	else if (m)
		return (ft_snprintf(buf, size, "%s%lldm %02llds",
			sign < 0 ? "-" : "", m, s));
	else if (s)
		return (ft_snprintf(buf, size, "%s%llds %02lldms",
			sign < 0 ? "-" : "", s, ms));
	else if (ms)
		return (ft_snprintf(buf, size, "%s%lldms %02lldus",
			sign < 0 ? "-" : "", ms, us));
	return (ft_snprintf(buf, size, "%lldus", us));
}
