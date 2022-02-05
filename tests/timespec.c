/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   timespec.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/05 11:55:54 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/05 17:20:59 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define int128_t	__int128_t
#define MAX_TV_NSEC	1000000000
#define MIN_TV_NSEC	(-MAX_TV_NSEC)

_Static_assert(sizeof(time_t) < sizeof(int128_t),
	"time_t is too big for overlow check!");

/*
** Every timespec operation function expects valid timespec parameters.
** Meaning no NULL pointers and that the tv_nsec must be less than 1 billion.
** It works with negative values if and only if the sec and nsec are both
** negative. Any other input results in undefined behavior.
** 
** Also, it is safe for dest to be equal to left or right, or even left and
** right. This is because the values are copied first and written at the end.
**
** Every timespec function returns 0 if everything went well and -1 if there
** was an error (overflow, underlow or division by 0).
*/

static void	check_timespec_result(int128_t *secptr, int128_t *nsecptr)
{
	int128_t	sec = *secptr, nsec = *nsecptr;

	if (sec > 0 && nsec < 0)
	{
		sec -= 1;
		nsec += MAX_TV_NSEC;
	}
	else if (sec < 0 && nsec > 0)
	{
		sec += 1;
		nsec -= MAX_TV_NSEC;
	}
	else if (nsec >= MAX_TV_NSEC || nsec <= MIN_TV_NSEC)
	{
		sec += nsec / MAX_TV_NSEC;
		nsec %= MAX_TV_NSEC;
	}
	*secptr = sec;
	*nsecptr = nsec;
}

int	timespec_add(struct timespec *dest, const struct timespec *left,
		const struct timespec *right)
{
	int128_t	sec = (int128_t)left->tv_sec + (int128_t)right->tv_sec;
	int128_t	nsec = (int128_t)left->tv_nsec + (int128_t)right->tv_nsec;

	check_timespec_result(&sec, &nsec);
	dest->tv_sec = sec;
	dest->tv_nsec = nsec;
	return (-!(dest->tv_sec == sec && dest->tv_nsec == nsec));
}

int	timespec_sub(struct timespec *dest, const struct timespec *left,
		const struct timespec *right)
{
	int128_t	sec = (int128_t)left->tv_sec - (int128_t)right->tv_sec;
	int128_t	nsec = (int128_t)left->tv_nsec - (int128_t)right->tv_nsec;

	check_timespec_result(&sec, &nsec);
	dest->tv_sec = sec;
	dest->tv_nsec = nsec;
	return (-!(dest->tv_sec == sec && dest->tv_nsec == nsec));
}

int	timespec_abs(struct timespec *dest, const struct timespec *src)
{
	int128_t	sec = (int128_t)src->tv_sec;
	int128_t	nsec = (int128_t)src->tv_nsec;

	if (sec < 0 || nsec < 0)
	{
		sec *= -1;
		nsec *= -1;
	}
	dest->tv_sec = sec;
	dest->tv_nsec = nsec;
	return (-!(dest->tv_sec == sec && dest->tv_nsec == nsec));
}

int	timespec_div(struct timespec *dest, const struct timespec *src, int div)
{
	int128_t	sec = (int128_t)src->tv_sec;
	int128_t	nsec = (int128_t)src->tv_nsec;

	if (!div)
		return (-1);
	sec /= div;
	nsec /= div;
	nsec += ((src->tv_sec % div) * MAX_TV_NSEC) / div;
	dest->tv_sec = sec;
	dest->tv_nsec = nsec;
	return (-!(dest->tv_sec == sec && dest->tv_nsec == nsec));
}

int main(int argc, char **argv)
{
	struct timespec	left = { 0 };
	struct timespec right = { 0 };
	struct timespec	sum = { 0 };
	struct timespec	sub = { 0 };
	struct timespec	abs = { 0 };
	struct timespec	div = { 0 };
	int				ret_sum = 0, ret_sub = 0, ret_abs = 0, ret_div;
	int				divisor;

	if (argc > 1)
		left.tv_sec = strtoll(argv[1], NULL, 10);
	if (argc > 2)
		left.tv_nsec = strtoll(argv[2], NULL, 10);
	if (argc > 3)
		right.tv_sec = strtoll(argv[3], NULL, 10);
	if (argc > 4)
		right.tv_nsec = strtoll(argv[4], NULL, 10);
	if (argc > 5)
		divisor = atoi(argv[5]);
	printf("left - sec: %ld - nsec: %ld\n", left.tv_sec, left.tv_nsec);
	printf("right - sec: %ld - nsec: %ld\n", right.tv_sec, right.tv_nsec);
	ret_sum = timespec_add(&sum, &left, &right);
	ret_sub = timespec_sub(&sub, &left, &right);
	printf("sum - (return %d) - sec: %ld - nsec: %ld\n",
		ret_sum, sum.tv_sec, sum.tv_nsec);
	printf("sub - (return %d) - sec: %ld - nsec: %ld\n",
		ret_sub, sub.tv_sec, sub.tv_nsec);
	memcpy(&abs, &left, sizeof(abs));
	ret_abs = timespec_abs(&abs, &abs);
	printf("abs(left) - (return %d) - sec: %ld - nsec: %ld\n",
		ret_abs, abs.tv_sec, abs.tv_nsec);
	memcpy(&abs, &right, sizeof(abs));
	ret_abs = timespec_abs(&abs, &abs);
	printf("abs(right) - (return %d) - sec: %ld - nsec: %ld\n",
		ret_abs, abs.tv_sec, abs.tv_nsec);
	ret_div = timespec_div(&div, &left, divisor);
	printf("left / %d - (return %d) - sec: %ld - nsec: %ld\n",
		divisor, ret_div, div.tv_sec, div.tv_nsec);
	ret_div = timespec_div(&div, &right, divisor);
	printf("right / %d - (return %d) - sec: %ld - nsec: %ld\n",
		divisor, ret_div, div.tv_sec, div.tv_nsec);
	return (EXIT_SUCCESS);
}
