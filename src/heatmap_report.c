/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   heatmap_report.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/08 04:50:11 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/09 00:30:31 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

//TODO:
//- add port numbers on the sides as a reference
//- if complete is set show an independant heatmap for each scan type
//- add a color legend for available the different states on the map

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

void		heatmap_report(t_host_job *host_job, t_nmap_config *cfg)
{
	uint8_t			state = 0, new_state;
	const uint8_t	width = WIDTH_FROM_N(cfg->nports);

	ft_printf("\n");
	for (uint16_t id = 0; id < cfg->nports || id % width; ++id, new_state = 0)
	{
		if (id < cfg->nports)
			new_state = host_job->port_jobs[id].status & E_STATE_SCAN_MASK;
		ft_printf("%s%s%s", new_state != state ? g_state_colors[new_state] : "",
			g_port_char, id % width == width - 1 ? "\n" : "");
		state = new_state;
	}
	ft_printf("\e[0m");
}
