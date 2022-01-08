/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   heatmap_report.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/08 04:50:11 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/09 00:56:51 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

#define WIDTH_FROM_N(n)	\
	(n > 768 ? 64 : n > 448 ? 48 : n > 160 ? 32 : n > 24 ? 16 : 8)

const char	*g_port_char = "\U000025AE";					// rectangle

const char	*g_state_colors[MAX_PORT_STATUS + 1] = {
	[ 0 ] = "\e[38;5;236m",									// dark grey
	[ E_STATE_OPEN ] = "\e[38;5;22m",						// green
	[ E_STATE_CLOSED ] = "\e[38;5;214m",					// yellow
	[ E_STATE_UNFILTERED ] = "\e[38;5;202m",				// orange
	[ E_STATE_FILTERED ] = "\e[38;5;1m",					// red
	[ E_STATE_OPEN | E_STATE_FILTERED ] = "\e[38;5;242m",	// light grey
};

static void	print_legend(uint16_t state_counters[MAX_PORT_STATUS + 1])
{
	ft_printf("\n");
	for (int state = E_STATE_OPEN; state <= MAX_PORT_STATUS; ++state)
	{
		if (!state_counters[state])
			continue;
		ft_printf("%s%s\e[0m %s ports (%hu)\n", g_state_colors[state],
			g_port_char, g_port_status[state], state_counters[state]);
	}
	if (state_counters[0])
		ft_printf("%s%s\e[0m filler (%hu)\n", g_state_colors[0],
			g_port_char, state_counters[0]);
}

void		heatmap_report(t_host_job *host_job, t_nmap_config *cfg)
{
	uint8_t			state = 0, new_state;
	const uint8_t	width = WIDTH_FROM_N(cfg->nports);
	uint16_t		state_counters[MAX_PORT_STATUS + 1] = { 0 };

	ft_printf("\n");
	for (uint16_t id = 0; id < cfg->nports || id % width; ++id, new_state = 0)
	{
		if (id < cfg->nports)
			new_state = host_job->port_jobs[id].status & E_STATE_SCAN_MASK;
		ft_printf("%s%s%s", new_state != state ? g_state_colors[new_state] : "",
			g_port_char, id % width == width - 1 ? "\n" : "");
		state = new_state;
		++state_counters[state];
	}
	ft_printf("\e[0m");
	print_legend(state_counters);
}
