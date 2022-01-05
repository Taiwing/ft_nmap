/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   verbose.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 06:17:13 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/05 16:35:04 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	verbose_scan(t_nmap_config *cfg, t_scan_job *scan_job,
			t_packet *packet, const char *action)
{
	if (cfg->speedup)
		nmap_mutex_lock(&cfg->print_mutex, &g_print_locked);
	ft_printf("\n---- Scan type %s on host '%s' port %hu "
		"(port_job %hu/%d) ----\n",  g_nmap_scan_strings[scan_job->type],
		cfg->host_job.host, scan_job->dstp, scan_job->port_job_id + 1,
		cfg->nports);
	if (cfg->speedup)
		ft_printf("Worker Thread %llu (%#llx)\n",
			ft_thread_self(), pthread_self());
	ft_printf("%s\n", action);
	if (packet)
		print_packet(packet->raw_data, cfg->host_job.family,
			packet->size, (char *)cfg->exec);
	if (cfg->speedup)
		nmap_mutex_unlock(&cfg->print_mutex, &g_print_locked);
}

void		verbose_reply(t_nmap_config *cfg, t_scan_job *scan_job,
				t_packet *reply, uint8_t result)
{
	if (!reply)
		verbose_scan(cfg, scan_job, reply, "Probe Timeout.");
	else if (result == E_STATE_NONE)
		verbose_scan(cfg, scan_job, reply, "Dropping invalid reply.");
	else
		verbose_scan(cfg, scan_job, reply, "Received reply packet!");
}
