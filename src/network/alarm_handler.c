#include "ft_nmap.h"

static void	init_probe_task(t_probe *probe)
{
	t_list	*new_task;
	t_task	task = { E_TASK_PROBE, probe, 0 };

	new_task = ft_lstnew(&task, sizeof(task));
	if (!g_cfg->speedup)
	{
		task.type = E_TASK_LISTEN;
		task.probe = NULL;
		new_task->next = ft_lstnew(&task, sizeof(task));
		push_tasks(&g_cfg->main_tasks, new_task, g_cfg, 0);
		g_cfg->current_probe = -1;
		pcap_breakloop(g_cfg->descr);
	}
	else
		push_tasks(&g_cfg->worker_tasks, new_task, g_cfg, 1);
}

static void	set_probe_timeout(t_probe *probe)
{
	t_task			task = { E_TASK_REPLY, probe, E_STATE_NONE };

	task.result = scan_result(probe->scan_type, NULL);
	if (g_cfg->verbose)
		verbose_reply(g_cfg, &task, NULL);
	push_reply_task(&task);
}

static void	alarm_handler(int sig)
{
	t_probe	*probe = g_cfg->probes;
	int		current_probe = g_cfg->current_probe;
	int		nprobes = g_cfg->speedup ? g_cfg->nprobes : current_probe + 1;

	(void)sig;
	if (g_cfg->end || (!g_cfg->speedup && current_probe < 0))
	{
		if (g_cfg->end)
			pcap_breakloop(g_cfg->descr);
		return;
	}
	for (int i = g_cfg->speedup ? 0 : current_probe; i < nprobes; ++i)
	{
		if (probe[i].retry <= 0)
			continue ;
		if (--probe[i].retry > 0)
			init_probe_task(probe + i);
		else
			set_probe_timeout(probe + i);
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
