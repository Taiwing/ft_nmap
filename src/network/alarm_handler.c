#include "ft_nmap.h"

static void	alarm_handler(int sig)
{
	(void)sig;
	if (g_cfg->listen_breakloop)
	{
		g_cfg->listen_breakloop = 0;
		pcap_breakloop(g_cfg->descr);
	}
	else if (!g_cfg->speedup && !g_cfg->pcap_worker_is_working)
		pseudo_thread_worker();
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
