/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   window.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/08 08:01:50 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/14 19:21:51 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*
** Check if the send window is full. If it is not the case, increment the
** current count for the probe to be sent and decrease it back if there is
** concurrent access (which should never happen since this operation is done
** within a mutex in multithreaded mode).
*/
int			full_window(t_send_window *window)
{
	if (window->current == window->size)
		return (1);
	else if (++window->current > window->size)
	{
		--window->current;
		return (1);
	}
	return (0);
}

int			rate_limit(t_send_window *window, int64_t ts)
{
	if (ts > window->rate_limit_ts)
	{
		window->rate_limit_ts = ts;
		window->rate_limit_current = 0;
	}
	if (++window->rate_limit_current > window->rate_limit
		|| full_window(window))
	{
		--window->rate_limit_current;
		return (1);
	}
	return (0);
}

void		set_rate_limit(t_send_window *window)
{
	window->size = 1;
	window->ssthresh = window->size;
	window->max = window->size;
	window->rate_limit = 1;
}

static void	congestion_avoidance(t_send_window *window)
{
	if (++window->avoid_count >= window->size)
	{
		window->avoid_count = 0;
		if (++window->size > window->max)
			--window->size;
	}
}

static void	slow_start(t_send_window *window)
{
	if (++window->size > window->max)
		--window->size;
}

/*
** Decrease current count when receiving reply or on timeout. Then increase the
** send window using an algorithm or the other depending on ssthresh value.
** If exponential_backoff is set (eg: if the scan is UDP), set rate limit.
*/
void		update_window(t_send_window *window, int is_timeout)
{
	--window->current;
	if (is_timeout)
	{
		++window->timeout_count;
		if (window->exponential_backoff && window->responsive
			&& window->reply_count <= DEF_SIZE
			&& !(++window->successive_timeout_count % window->timeoutthresh))
			return (set_rate_limit(window));
	}
	else if (!is_timeout)
	{
		if (window->timeout_count < MAX_RESPONSIVE_TIMEOUT)
			window->responsive = 1;
		++window->reply_count;
		window->successive_timeout_count = 0;
	}
	if (window->size <= window->ssthresh)
		slow_start(window);
	else
		congestion_avoidance(window);
}

void		reset_window(t_send_window *window)
{
	t_send_window	default_window = DEF_SEND_WINDOW;

	ft_memcpy(window, &default_window, sizeof(default_window));
}
