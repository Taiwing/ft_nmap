/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   timeval_ops.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/05 19:16:59 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/05 21:24:56 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*
** This will make ft_nmap compilation fail if the host system has implemented
** a time type greater that 128 bits. This is very unlikely to say the least
** but if it is the case, the program should not be compiled as we lose our
** only way to check overflows in the time operation functions.
*/

_Static_assert(sizeof(time_t) < sizeof(int128_t),
	"time_t is too big for overflow check!");
_Static_assert(sizeof(suseconds_t) < sizeof(int128_t),
	"suseconds_t is too big for overflow check!");

/*
** Every timeval operation function expects valid timeval parameters. Meaning
** no NULL pointers and that the tv_usec must be less than 1 million. It works
** with negative values if and only if the sec and usec are both negative. Any
** other input results in undefined behavior.
** 
** Also, it is safe for dest to be equal to left or right, or even left and
** right. This is because the values are copied first and written at the end.
**
** Every timeval function returns 0 if everything went well and -1 if there was
** an error (overflow, underflow or division by 0).
*/

static void	check_timeval_result(int128_t *secptr, int128_t *usecptr)
{
	int128_t	sec = *secptr, usec = *usecptr;

	if (sec > 0 && usec < 0)
	{
		sec -= 1;
		usec += MAX_TV_USEC;
	}
	else if (sec < 0 && usec > 0)
	{
		sec += 1;
		usec -= MAX_TV_USEC;
	}
	else if (usec >= MAX_TV_USEC || usec <= MIN_TV_USEC)
	{
		sec += usec / MAX_TV_USEC;
		usec %= MAX_TV_USEC;
	}
	*secptr = sec;
	*usecptr = usec;
}

int	timeval_add(struct timeval *dest, const struct timeval *left,
		const struct timeval *right)
{
	int128_t	sec = (int128_t)left->tv_sec + (int128_t)right->tv_sec;
	int128_t	usec = (int128_t)left->tv_usec + (int128_t)right->tv_usec;

	check_timeval_result(&sec, &usec);
	dest->tv_sec = sec;
	dest->tv_usec = usec;
	return (-!(dest->tv_sec == sec && dest->tv_usec == usec));
}

int	timeval_sub(struct timeval *dest, const struct timeval *left,
		const struct timeval *right)
{
	int128_t	sec = (int128_t)left->tv_sec - (int128_t)right->tv_sec;
	int128_t	usec = (int128_t)left->tv_usec - (int128_t)right->tv_usec;

	check_timeval_result(&sec, &usec);
	dest->tv_sec = sec;
	dest->tv_usec = usec;
	return (-!(dest->tv_sec == sec && dest->tv_usec == usec));
}

int	timeval_abs(struct timeval *dest, const struct timeval *src)
{
	int128_t	sec = (int128_t)src->tv_sec;
	int128_t	usec = (int128_t)src->tv_usec;

	if (sec < 0 || usec < 0)
	{
		sec *= -1;
		usec *= -1;
	}
	dest->tv_sec = sec;
	dest->tv_usec = usec;
	return (-!(dest->tv_sec == sec && dest->tv_usec == usec));
}

int	timeval_div(struct timeval *dest, const struct timeval *src, int div)
{
	int128_t	sec = (int128_t)src->tv_sec;
	int128_t	usec = (int128_t)src->tv_usec;

	if (!div)
		return (-1);
	sec /= div;
	usec /= div;
	usec += ((src->tv_sec % div) * MAX_TV_USEC) / div;
	dest->tv_sec = sec;
	dest->tv_usec = usec;
	return (-!(dest->tv_sec == sec && dest->tv_usec == usec));
}

int	timeval_mul(struct timeval *dest, const struct timeval *src, int mul)
{
	int128_t	sec = (int128_t)src->tv_sec;
	int128_t	usec = (int128_t)src->tv_usec;

	sec *= mul;
	usec *= mul;
	check_timeval_result(&sec, &usec);
	dest->tv_sec = sec;
	dest->tv_usec = usec;
	return (-!(dest->tv_sec == sec && dest->tv_usec == usec));
}

/*
** Compare two timeval instances. If 'a' is before 'b' ('a' thus being smaller)
** a negative value is returned, it is positive if the reverse is true (if 'a'
** is after 'b'). Otherwise, if 'a' and 'b' are equal, 0 is returned.
*/
int timeval_cmp(struct timeval *a, struct timeval *b)
{
	int128_t	sec_diff = (int128_t)a->tv_sec - (int128_t)b->tv_sec;
	int128_t	usec_diff = (int128_t)a->tv_usec - (int128_t)b->tv_usec;

	if (sec_diff)
		return (sec_diff < 0 ? -1 : 1);
	else if (usec_diff)
		return (usec_diff < 0 ? -1 : 1);
	return (0);
}
