/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   window.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/08 08:01:50 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/14 16:07:48 by yforeau          ###   ########.fr       */
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

void		exponential_backoff(t_send_window *window)
{
	window->ssthresh = window->size;
	window->size = window->ssthresh / 2;
	if (window->size < window->min)
		window->size = window->min;
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
** Execute exponential backoff if too many timeouts are detected on a responsive
** host during a UDP scan (it is basically useless on TCP scans, or at least
** I did not encounter a case where the network was actually limiting TCP probes
** so it does not really matter because I dont have all the time in the world).
*/
void		update_window(t_send_window *window, int is_timeout)
{
	--window->current;
	if (is_timeout)
	{
		++window->timeout_count;
		if (window->exponential_backoff && window->responsive
			&& !(++window->successive_timeout_count % window->timeoutthresh))
			return (exponential_backoff(window));
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
