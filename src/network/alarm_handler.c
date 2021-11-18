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
		pcap_breakloop(g_cfg->descr);
	}
	else
		push_tasks(&g_cfg->worker_tasks, new_task, g_cfg, 1);
}

static void	alarm_handler(int sig)
{
	t_probe	*probe = g_cfg->probes;
	int		nprobes = g_cfg->nprobes;

	(void)sig;
	if (g_cfg->end)
	{
		pcap_breakloop(g_cfg->descr);
		return;
	}
	for (int i = 0; i < nprobes; ++i)
	{
		if (probe[i].done)
			continue ;
		if (probe[i].retry++ < MAX_RETRY)
			init_probe_task(probe + i);
		else
			init_reply_task(NULL, 0, 0, (uint16_t)i);
		if (!g_cfg->speedup)
			break ;
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
