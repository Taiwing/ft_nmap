/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   worker.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/23 21:26:35 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/10 08:47:39 by yforeau          ###   ########.fr       */
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
		scan->result = E_STATE_OPEN;
	else if (randval == 1)
		scan->result = E_STATE_CLOSED;
	else if (randval == 2)
		scan->result = E_STATE_FILTERED;
	else if (randval == 3)
		scan->result = E_STATE_UNFILTERED;
	else
		scan->result = E_STATE_OPEN | E_STATE_FILTERED;
	//TEMP
}

static void	exec_scan(t_scan *scan)
{
	t_packet	reply = { 0 };
	uint16_t	srcp = PORT_DEF + ft_thread_self();
	uint16_t	dstp = scan->cfg->ports[scan->task_id];

	//buidl the packet to send
	build_scan_probe(&scan->probe, scan, srcp, dstp);
	if (scan->cfg->verbose > 0)
		verbose_scan(scan, &scan->probe, "Sending probe...");
	//setup listener and pcap filter
	if (!(scan->descr = setup_listener(scan, srcp, dstp)))
		ft_exit(EXIT_FAILURE, "%s: failed to setup listener", __func__);
	//put packet pointer and pcap handle in shared array (for alarm handler)
	share_probe(scan, scan->probe.size);
	//start listening
	ft_listen(&reply, scan->descr, grab_reply);
	if (scan->cfg->verbose > 0)
		verbose_scan(scan, &reply,
			reply.size > 0 ? "Received reply!" : "Probe timed out...");
	//interpret answer or non-answer and set scan result
	set_scan_result(scan, &reply);

	//cleanup
	if (scan->descr)
	{
		pcap_close(scan->descr);
		scan->descr = NULL;
	}
	//TEST
	//lol_wait(scan);
	//TEST
}

__thread t_scan	*g_scan = NULL;

static void	worker_exit(void)
{
	nmap_mutex_unlock(&g_cfg->global_mutex, &g_global_locked);
	nmap_mutex_unlock(&g_cfg->probe_mutex, &g_probe_locked);
	if (g_scan && g_scan->descr)
	{
		pcap_close(g_scan->descr);
		g_scan->descr = NULL;
	}
	if (g_cfg->verbose > 2)
		ft_printf("worker_exit - worker %llu (%llx)!\n",
			ft_thread_self(), pthread_self());
	ft_thread_exit();
}

void		wait_workers(t_nmap_config *cfg)
{
	uint64_t	nthreads;

	if (cfg->speedup && (nthreads = ft_thread_count()))
	{
		nmap_mutex_unlock(&cfg->global_mutex, &g_global_locked);
		//TODO: probably send a signal to end threads (through ft_exit of course)
		// or just set g_thread_error to a non-zero value (if it is not already
		// the case)
		ft_set_thread_error(EXIT_FAILURE);//TEMP
		for (uint8_t i = 0; i < nthreads; ++i)
			ft_thread_join(cfg->thread + i + 1, NULL);
		cfg->speedup = 0;
	}
}

void		start_workers(t_nmap_config *cfg, t_scan *scan)
{
	int			ret;

	if (!cfg->speedup)
		worker((void *)(scan));
	for (uint8_t i = 0; i < cfg->speedup && !ft_thread_error(); ++i)
		if ((ret = ft_thread_create(cfg->thread + i + 1, NULL,
			worker, (void *)(scan + i + 1))))
			ft_exit(EXIT_FAILURE, "pthread_create: %s", strerror(ret));
}

void		*worker(void *ptr)
{
	t_scan			*scan;

	if (ft_thread_self())
		ft_atexit(worker_exit);
	scan = (t_scan *)ptr;
	g_scan = scan;
	while (next_job(scan) && !ft_thread_error())
	{
		exec_scan(scan);
		update_job(scan);
	}
	ft_atexit(NULL);
	return (NULL);
}
