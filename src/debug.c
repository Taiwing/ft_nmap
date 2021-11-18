/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   debug.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/18 19:17:09 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/18 19:17:16 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	debug_invalid_packet(t_nmap_config *cfg, t_packet *packet)
{
	if (cfg->speedup)
		nmap_mutex_lock(&cfg->print_mutex, &g_print_locked);
	ft_printf("\n---- Dropping Invalid Packet ----\n");
	if (cfg->speedup)
		ft_printf("Worker Thread %llu (%#llx)\n",
			ft_thread_self(), pthread_self());
	print_packet(packet->raw_data, cfg->host_job.family,
		packet->size, (char *)cfg->exec);
	if (cfg->speedup)
		nmap_mutex_unlock(&cfg->print_mutex, &g_print_locked);
}
