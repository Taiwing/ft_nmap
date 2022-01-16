/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   stats.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/07 11:13:54 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/16 16:02:49 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	stats_listen(t_nmap_config *cfg, int packet_count)
{
	++cfg->listen_breaks_total;
	if (packet_count < 0)
		++cfg->listen_breaks_manual;
	if (packet_count == 0)
		++cfg->listen_breaks_zero_packet;
}
