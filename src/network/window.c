/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   window.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/08 08:01:50 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/13 16:11:02 by yforeau          ###   ########.fr       */
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

void		backoff_window(t_send_window *window)
{
	window->size /= 2;
	if (window->size < window->min)
		window->size = window->min;
}

static void	congestion_avoidance(t_send_window *window)
{
	if (++window->avoid_count == window->size)
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
** Execute exponential backoff if too many drops are detected.
*/
void		update_window(t_send_window *window, int is_timeout)
{
	if (--window->current < 0)
		window->current = 0;
	if (is_timeout && ++window->timeout_count < window->reply_count
		&& ++window->successive_timeout_count == window->timeoutthresh)
		return (backoff_window(window));
	else if (!is_timeout)
	{
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
