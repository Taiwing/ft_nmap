/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/06 04:35:54 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/06 19:40:05 by yforeau          ###   ########.fr       */
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
		if (timeval_sub(&diff, &end, &start) < 0)
			ft_exit(EXIT_FAILURE, "timeval_sub: overflow");
	} while (timeval_cmp(time, &diff) > 0);
}

#define	UNITS_COUNT	5
const char	*g_nmap_time_unit_strings[] = { "us", "ms", "s", "m", "h", NULL };
const int	g_nmap_us_time_units[] = { 1, 1000 };
const int	g_nmap_s_time_units[] = { 1, 60, 3600 };

void	str_to_timeval(struct timeval *time, const char *str)
{
	const char	*unit_str = NULL, *p;
	int			i = 0, value = 0, second = 1;

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

/*
** is_passed: check if date has passed expiry
**
** More precisely, this function returns 1 (true) if the timestamp of date is
** equal or greater to that of the expiry. If date or expiry is NULL, it is
** gonna be replace by gettimeofday output.
**
** So here are the possibilies:
**
** -- Basic cases --
** A: date > expiry --> 1
** B: date == expiry --> 1
** C: date < expiry --> 0
**
** -- NULL case --
** D: date == NULL && expiry == NULL --> 1
**
** -- NULL expiry (expiry == now) --
** E: date == yesterday && expiry == NULL --> 0
** F: date == now && expiry == NULL --> 1
** G: date == tomorrow && expiry == NULL --> 1
**
** -- NULL date (date == now) --
** H: date == NULL && expiry == yesterday --> 1
** I: date == NULL && expiry == now --> 1
** J: date == NULL && expiry == tomorrow --> 0
**
** Simple, right ?
*/
int		is_passed(struct timeval *date, struct timeval *expiry)
{
	struct timeval	now = { 0 };

	if (!date && !expiry)
		return (1);
	else if (!expiry || !date)
	{
		if (gettimeofday(&now, NULL) < 0)
			ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
		date = !date ? &now : date;
		expiry = !expiry ? &now : expiry;
	}
	if (expiry->tv_sec == date->tv_sec)
		return (expiry->tv_usec <= date->tv_usec);
	return (expiry->tv_sec < date->tv_sec);
}
