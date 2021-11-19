/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   debug.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/18 19:17:09 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/19 11:03:41 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include "ft_printf_internal.h"

void	debug_listener_setup(t_nmap_config *cfg, char *filter)
{
	if (cfg->speedup)
		nmap_mutex_lock(&cfg->print_mutex, &g_print_locked);
	ft_putchar('\n');
	if (cfg->speedup)
		ft_printf("Worker Thread %llu (%#llx)\n",
				ft_thread_self(), pthread_self());
	ft_printf("Setting pcap filter:\n%s\n", filter);
	if (cfg->speedup)
		nmap_mutex_unlock(&cfg->print_mutex, &g_print_locked);
}

void	debug_invalid_packet(t_nmap_config *cfg, t_packet *packet, char *action)
{
	if (cfg->speedup)
		nmap_mutex_lock(&cfg->print_mutex, &g_print_locked);
	ft_printf("\n---- %s ----\n", action);
	if (cfg->speedup)
		ft_printf("Worker Thread %llu (%#llx)\n",
				ft_thread_self(), pthread_self());
	print_packet(packet->raw_data, cfg->host_job.family,
			packet->size, (char *)cfg->exec);
	if (cfg->speedup)
		nmap_mutex_unlock(&cfg->print_mutex, &g_print_locked);
}

const char	*g_nmap_task_strings[TASK_COUNT] = {
	"THREAD_SPAWN",
	"LISTEN",
	"NEW_HOST",
	"PROBE",
	"REPLY",
	"THREAD_WAIT",
};

const char	*g_nmap_state_strings[] = {
	[E_STATE_PENDING]		= "PENDING",
	[E_STATE_ONGOING]		= "ONGOING",
	[E_STATE_FULL]			= "FULL",
	[E_STATE_DONE]			= "DONE",
	[E_STATE_OPEN]			= "OPEN",
	[E_STATE_CLOSED]		= "CLOSED",
	[E_STATE_FILTERED]		= "FILTERED",
	[E_STATE_UNFILTERED]	= "UNFILTERED",
	[E_STATE_NONE]			= "NONE",
};

static void	debug_reply(uint8_t result)
{
	uint8_t	bit = 0;
	int		append = 0;

	ft_printf("reply result: ");
	if (!result)
		ft_printf("%s", g_nmap_state_strings[result]);
	for (int i = 0; result && i < 8; ++i)
	{
		bit = result & (0x01 << i);
		if (bit)
		{
			result ^= bit;
			ft_printf("%s%s", append ? " | " : "", g_nmap_state_strings[bit]);
			append = 1;
		}
	}
	ft_putchar('\n');
}

void	debug_task(t_nmap_config *cfg, t_task *task)
{
	if (cfg->speedup)
		nmap_mutex_lock(&cfg->print_mutex, &g_print_locked);
	ft_putchar('\n');
	if (cfg->speedup)
		ft_printf("Worker Thread %llu (%#llx)\n",
				ft_thread_self(), pthread_self());
	ft_printf("Executing %s task\n", g_nmap_task_strings[task->type]);
	if (task->probe)
		ft_printf("probe: scan = %s, srcp = %hu, dstp = %hu\n",
				g_nmap_scan_strings[task->probe->scan_type],
				task->probe->srcp, task->probe->dstp);
	if (task->type == E_TASK_REPLY)
		debug_reply(task->result);
	if (cfg->speedup)
		nmap_mutex_unlock(&cfg->print_mutex, &g_print_locked);
}

void	debug_print(t_nmap_config *cfg, const char *format, ...)
{
	t_farg  args = { 0 };
	t_pdata data;

	if (!cfg->debug)
		return;
	if (cfg->speedup)
		nmap_mutex_lock(&cfg->print_mutex, &g_print_locked);
	pdata_init(&data, PMODE_CLASSIC, 1);
	pdata_set_buf(&data, NULL, 0);
	va_start(args.cur, format);
	va_copy(args.ref, args.cur);
	ft_printf_internal(&data, format, &args);
	va_end(args.cur);
	va_end(args.ref);
	if (cfg->speedup)
		nmap_mutex_unlock(&cfg->print_mutex, &g_print_locked);
}
