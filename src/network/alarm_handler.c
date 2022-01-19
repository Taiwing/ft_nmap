#include "ft_nmap.h"

//TODO: check that this setup works, if it does not, just break the pcap loop
//here and lauch a pseudo worker in the main thread instead of here (maybe
//do it in the listen hander or create a dedicated task ?)
static void	alarm_handler(int sig)
{
	t_worker_config	wcfg = {
		.type = E_WORKER_PSEUDO_THREAD,
		.task_list = &g_cfg->thread_tasks,
		.task_match = { .task_types = WORKER_TASKS },
	};

	(void)sig;
	if (!g_cfg->pcap_worker_is_working)
	{
		if (gettimeofday(&wcfg.task_match.exec_time, NULL) < 0)
			ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
		wcfg.expiry.tv_sec = wcfg.task_match.exec_time.tv_sec
			+ ((DEF_TIMEOUT / 1000) / 2);
		worker(&wcfg);
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
