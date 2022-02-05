/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   timeval.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/05 11:55:54 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/05 19:15:28 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define int128_t		__int128_t
#define MAX_TV_USEC		1000000
#define MIN_TV_USEC		(-MAX_TV_USEC)

_Static_assert(sizeof(time_t) < sizeof(int128_t),
	"time_t is too big for overlow check!");
_Static_assert(sizeof(suseconds_t) < sizeof(int128_t),
	"suseconds_t is too big for overlow check!");

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
** an error (overflow, underlow or division by 0).
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

int main(int argc, char **argv)
{
	struct timeval	left = { 0 };
	struct timeval	right = { 0 };
	struct timeval	sum = { 0 };
	struct timeval	sub = { 0 };
	struct timeval	abs = { 0 };
	struct timeval	div = { 0 };
	struct timeval	mul = { 0 };
	int				ret_sum = 0,
					ret_sub = 0,
					ret_abs = 0,
					ret_div = 0,
					ret_mul = 0;
	int				divisor, multiplier;

	if (argc > 1)
		left.tv_sec = strtoll(argv[1], NULL, 10);
	if (argc > 2)
		left.tv_usec = strtoll(argv[2], NULL, 10);
	if (argc > 3)
		right.tv_sec = strtoll(argv[3], NULL, 10);
	if (argc > 4)
		right.tv_usec = strtoll(argv[4], NULL, 10);
	if (argc > 5)
		multiplier = divisor = atoi(argv[5]);
	printf("left - sec: %ld - usec: %ld\n", left.tv_sec, left.tv_usec);
	printf("right - sec: %ld - usec: %ld\n", right.tv_sec, right.tv_usec);
	ret_sum = timeval_add(&sum, &left, &right);
	ret_sub = timeval_sub(&sub, &left, &right);
	printf("sum - (return %d) - sec: %ld - usec: %ld\n",
		ret_sum, sum.tv_sec, sum.tv_usec);
	printf("sub - (return %d) - sec: %ld - usec: %ld\n",
		ret_sub, sub.tv_sec, sub.tv_usec);
	memcpy(&abs, &left, sizeof(abs));
	ret_abs = timeval_abs(&abs, &abs);
	printf("abs(left) - (return %d) - sec: %ld - usec: %ld\n",
		ret_abs, abs.tv_sec, abs.tv_usec);
	memcpy(&abs, &right, sizeof(abs));
	ret_abs = timeval_abs(&abs, &abs);
	printf("abs(right) - (return %d) - sec: %ld - usec: %ld\n",
		ret_abs, abs.tv_sec, abs.tv_usec);
	ret_div = timeval_div(&div, &left, divisor);
	printf("left / %d - (return %d) - sec: %ld - usec: %ld\n",
		divisor, ret_div, div.tv_sec, div.tv_usec);
	ret_div = timeval_div(&div, &right, divisor);
	printf("right / %d - (return %d) - sec: %ld - usec: %ld\n",
		divisor, ret_div, div.tv_sec, div.tv_usec);
	ret_mul = timeval_mul(&mul, &left, multiplier);
	printf("left * %d - (return %d) - sec: %ld - usec: %ld\n",
		multiplier, ret_mul, mul.tv_sec, mul.tv_usec);
	ret_mul = timeval_mul(&mul, &right, multiplier);
	printf("right * %d - (return %d) - sec: %ld - usec: %ld\n",
		multiplier, ret_mul, mul.tv_sec, mul.tv_usec);
	return (EXIT_SUCCESS);
}
