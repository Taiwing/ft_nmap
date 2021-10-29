/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   worker.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/23 21:26:35 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/29 20:50:45 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	lol_wait(t_scan *scan)
{
	//TEMP
	uint64_t	randval = 0;
	uint64_t	speedup = scan->cfg->speedup ?
		(uint64_t)scan->cfg->speedup : MAX_SPEEDUP;

	if (!ft_rand_uint64(&randval, 0, speedup))
		ft_exit(EXIT_FAILURE, "ft_rand_uint64: error");
	if (speedup && ft_thread_self() == randval)
		ft_exit(123, "WOOOOW!!! exiting worker %llu (%llx)!",
			ft_thread_self(), pthread_self());
	else if (speedup < 10)
		sleep(randval);
	else if (speedup < 100)
		sleep(randval / 10);
	else
		sleep(randval / 25);
	if (!ft_rand_uint64(&randval, 0, 4))
		ft_exit(EXIT_FAILURE, "ft_rand_uint64: error");
	if (!randval)
		scan->result = STATE_OPEN;
	else if (randval == 1)
		scan->result = STATE_CLOSED;
	else if (randval == 2)
		scan->result = STATE_FILTERED;
	else if (randval == 3)
		scan->result = STATE_UNFILTERED;
	else
		scan->result = STATE_OPEN | STATE_FILTERED;
	//TEMP
}

static void	exec_scan(t_scan *scan)
{
	uint8_t	probe[PROBE_MAXSIZE];
	int		size;

	//buidl the packet to send
	if ((size = build_scan_probe(probe, scan, PORT_DEF + ft_thread_self(),
		scan->cfg->ports[scan->task_id])) < 0)
		ft_dprintf(2, "%s: %s: failed to build probe packet\n",
			scan->cfg->exec, __func__);
	else
	{
		ft_printf("\n\n");
		print_packet(probe, scan->job->host_ip.family,
			size, (char *)scan->cfg->exec);
	}
	//setup pcap filter
	//put packet pointer and pcap handle in shared array (for alarm handler)
	//start listening
	//interpret answer or non-answer and set scan result

	//TEST
	lol_wait(scan);
	//TEST
}

static void	worker_exit(void)
{
	nmap_mutex_unlock(&g_cfg->mutex);
	//TEMP
	/*
	ft_printf("worker_exit - worker %llu (%llx)!\n",
		ft_thread_self(), pthread_self());
	*/
	//TEMP
	ft_thread_exit();
}

void		wait_workers(t_nmap_config *cfg)
{
	uint64_t	nthreads;

	if (cfg->speedup && (nthreads = ft_thread_count()))
	{
		nmap_mutex_unlock(&cfg->mutex);
		//TODO: probably send a signal to end threads (through ft_exit of course)
		// or just set g_thread_error to a non-zero value (if it is not already
		// the case)
		ft_set_thread_error(EXIT_FAILURE);//TEMP
		for (uint8_t i = 0; i < nthreads; ++i)
			ft_thread_join(cfg->thread + i, NULL);
		cfg->speedup = 0;
	}
}

void		start_workers(t_nmap_config *cfg, t_scan *scan)
{
	int			ret;

	if (!cfg->speedup)
	{
		if (next_job(scan))
			worker((void *)(scan));
		return;
	}
	for (uint8_t i = 0; i < cfg->speedup && next_job(scan + i)
		&& !ft_thread_error(); ++i)
	{
		if ((ret = ft_thread_create(cfg->thread + i, NULL,
			worker, (void *)(scan + i))))
			ft_exit(EXIT_FAILURE, "pthread_create: %s", strerror(ret));
	}
}

void		*worker(void *ptr)
{
	t_scan			*scan;

	if (ft_thread_self())
		ft_atexit(worker_exit);
	scan = (t_scan *)ptr;
	do
	{
		exec_scan(scan);
		update_job(scan);
	} while (next_job(scan) && !ft_thread_error());
	return (NULL);
}
