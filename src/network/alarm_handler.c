#include "ft_nmap.h"

static void	init_probe_task(t_scan_job *scan_job, int current_payload_index)
{
	t_list	*new_task = NULL;
	t_task	task = { .type = E_TASK_PROBE, .scan_job = scan_job };

	if (!g_cfg->speedup)
	{
		task.payload_index = current_payload_index;
		new_task = ft_lstnew(&task, sizeof(task));
		task.type = E_TASK_LISTEN;
		new_task->next = ft_lstnew(&task, sizeof(task));
		push_tasks(&g_cfg->main_tasks, new_task, g_cfg, 0);
		g_cfg->current_scan_job = -1;
		pcap_breakloop(g_cfg->descr);
	}
	else
	{
		for (uint16_t i = 0; task.scan_job->probes[i]; ++i)
		{
			task.payload_index = i;
			ft_lst_push_back(&new_task, &task, sizeof(task));
		}
		push_tasks(&g_cfg->worker_tasks, new_task, g_cfg, 1);
	}
}

static void	set_scan_job_timeout(t_scan_job *scan_job,
		int current_payload_index)
{
	t_task			task = { .type = E_TASK_REPLY, .scan_job = scan_job };

	if (!g_cfg->speedup && scan_job->probes[current_payload_index + 1])
	{
		g_cfg->current_scan_job = -1;
		g_cfg->current_payload_index = -1;
		scan_job->retry = 1 + MAX_RETRY;
		pcap_breakloop(g_cfg->descr);
	}
	else
	{
		if (g_cfg->verbose)
			verbose_reply(g_cfg, scan_job, NULL, 0);
		push_reply_task(&task);
	}
}

static void	alarm_handler(int sig)
{
	t_scan_job	**scan_job = g_cfg->scan_jobs;
	int			current_scan_job = g_cfg->current_scan_job;
	int			current_payload_index = g_cfg->current_payload_index;
	int			nscan_jobs = g_cfg->speedup ?
		g_cfg->nscan_jobs : current_scan_job + 1;

	(void)sig;
	if (g_cfg->end || (!g_cfg->speedup && current_scan_job < 0))
	{
		if (g_cfg->end)
			pcap_breakloop(g_cfg->descr);
		return;
	}
	for (int i = g_cfg->speedup ? 0 : current_scan_job; i < nscan_jobs; ++i)
	{
		if (scan_job[i]->retry <= 0)
			continue ;
		if (--scan_job[i]->retry > 0)
			init_probe_task(scan_job[i], current_payload_index);
		else
			set_scan_job_timeout(scan_job[i], current_payload_index);
	}
	alarm(1);
}

void	set_alarm_handler(void)
{
	struct sigaction	act = { .sa_handler = alarm_handler, .sa_flags = 0 };

	if (sigemptyset(&act.sa_mask) < 0)
		ft_exit(EXIT_FAILURE, "sigemptyset: %s", strerror(errno));
	if (sigaction(SIGALRM, &act, NULL) < 0)
		ft_exit(EXIT_FAILURE, "sigaction: %s", strerror(errno));
	alarm(1);
}
