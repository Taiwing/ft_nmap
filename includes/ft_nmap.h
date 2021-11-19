/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:29:05 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/19 11:49:33 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "network.h"
# include <limits.h>
# include <fcntl.h>
# include <pthread.h>
# include <sys/time.h>
# include <pcap/sll.h>
# include <signal.h>
# include <stdatomic.h>

/*
** ft_nmap macros and enums
*/

# define	xstr(s)					str(s)	// stringify macro value
# define	str(s)					#s

# define	MAX_SPEEDUP				250		// max number of additional threads
# define	MAX_THREADS				(MAX_SPEEDUP + 1)	// counts main thread
# define	MAX_PORTS				1024	// maximum number of ports to scan
# define	MAX_LST_ELM_LEN			1024	// biggest possible comma list element
# define	PORTS_COUNT				0x10000	// Number of ports (USHRT_MAX + 1)
# define	MAX_RETRY				4		// Number of retries for sending probe
# define	SCAN_COUNT				6
# define	SOCKET_COUNT				4
# define	TASK_COUNT				6
# define	MAX_PROBE				(MAX_PORTS * SCAN_COUNT)

// Print format constants
# define	SERVICE_NAME_MAXLEN		20
# define	SERVICE_DESC_MAXLEN		331
# define	RES_MAXLEN				3
# define	JOB_LINE				80
# define	PORT_FIELD				5
# define	SERVICE_FIELD			SERVICE_NAME_MAXLEN
# define	SCAN_FIELD				5
# define	STATE_FIELD				6

// Job states
enum e_states {
	E_STATE_PENDING			= 0x00,	// Not started yet
	E_STATE_ONGOING			= 0x01,	// At least one scan_job started
	E_STATE_FULL			= 0x02,	// Every scan_job/port_job is ongoing
	E_STATE_DONE			= 0x04,	// Finished
	E_STATE_OPEN			= 0x08,
	E_STATE_CLOSED			= 0x10,
	E_STATE_FILTERED		= 0x20,
	E_STATE_UNFILTERED		= 0x40,
	E_STATE_NONE			= 0x80, // Invalid reply packet
	E_STATE_SCAN_MASK		= 0xf8	// Mask for scan_job status
};

// Tasks
enum e_tasks {
	E_TASK_THREAD_SPAWN = 0,
	E_TASK_LISTEN,
	E_TASK_NEW_HOST,
	E_TASK_PROBE,
	E_TASK_REPLY,
	E_TASK_THREAD_WAIT,
};

// Scans
enum e_scans { E_SYN = 0, E_NULL, E_ACK, E_FIN, E_XMAS, E_UDP };

// IP modes
enum e_ip_modes { E_IPALL = 0, E_IPV4, E_IPV6 };

// Sockets
enum e_sockets { E_UDPV4 = 0, E_TCPV4, E_UDPV6, E_TCPV6 };

/*
** Task structure: this is the status of each scan_job on a given port
**
** status: port_job status
** ongoing: counter of started scan_jobs
** done: counter of finished scan_jobs
** scan_jobs: status of each scan_job
** scan_locks: to avoid two receive tasks on a scan
*/
typedef struct		s_port_job
{
	uint8_t			status;
	_Atomic uint8_t	ongoing;
	_Atomic uint8_t	done;
	uint8_t			scan_jobs[SCAN_COUNT];
	atomic_int		scan_locks[SCAN_COUNT];
}					t_port_job;

/*
** t_probe: nmap probes
**
** retry: counter of retries (MAX_RETRY then timeout, sig atomic too)
** srcip: ip to send probe to
** dstip: ip to send probe to
** srcp: src port (PORT_DEF + index of the probe in the probes array)
** dstp: port to send probe to
** host_job_id: id of the host job for this probe
** port_job_id: index of the port_job in the host_job's port_jobs array
** scan_type: probe's scan type
** packet: probe packet
** socket: socket type
*/
typedef struct				s_probe
{
	sig_atomic_t			retry;
	_Atomic enum e_scans	scan_type;
	t_ip					*srcip;
	t_ip					*dstip;
	uint16_t				srcp;
	uint16_t				dstp;
	uint16_t				host_job_id;
	uint16_t				port_job_id;
	t_packet				packet;
	enum e_sockets			socket;
}							t_probe;

//TODO: Check if ongoing and even full states are useless now. If they are,
//as I suspect, delete them mercilessly (that would be the case here but also
//in port jobs of course).
/*
** Job structure: this is the status of each tasks on a given host
**
** host_job_id: job counter and identification
** host: host string
** ip: IP from getaddrinfo()
** family: IPv4 or IPv6 host and scans
** dev: interface to scan from
** status: host_job status
** ongoing: counter of full port_jobs
** done: counter of finished port_jobs
** start_ts: ts at start of host_job
** end_ts: ts at end of host_job
** port_jobs: status of each port_job
*/
typedef struct			s_host_job
{
	_Atomic uint64_t	host_job_id;
	char				*host;
	t_ip				ip;
	uint16_t			family;
	t_ifinfo			*dev;
	uint8_t				status;
	_Atomic uint16_t	ongoing;
	_Atomic uint16_t	done;
	struct timeval		start_ts;
	struct timeval		end_ts;
	t_port_job			port_jobs[MAX_PORTS];
}						t_host_job;

/*
** t_nmap_config: nmap configuration
**
** exec: executable name
** speedup: number of parallel threads to use
** verbose: additional printing option
** debug: even more optional additional printing
** ports_to_scan: boolean array representing every port given as arguments
** ports: compressed list with the first MAX_PORTS ports of ports_to_scan
** nports: number of ports to scan in ports array
** hosts: hosts list given by cmd argument
** hosts_file: file containing a list of hosts
** scans: scans to perform as an array of booleans
** nscans: number of scans to perform on each port
** scan_strings: store selected scan names
** hosts_fd: file descriptor for the hosts_file
** linktype: link header type (SLL or SLL2)
** linkhdr_size: size of said header
** ifap: pointer to getifaddrs output (to be freed in cleanup)
** ip_mode: ip configuration (IPv4/IPv6 enabled/disabled)
** socket: sockets for sending probe packets
** netinf: information about the network interfaces
** thread: threads array
** nthreads: thread count
** print_mutex: mutex for synchronizing printing
** high_mutex: high priority mutex access to tasks list
** low_mutex: low priority mutex access to tasks list
** host_job: current host_job
** probes: probe array each corresponding to a scan
** nprobes: probe count (sigatomic for alarm handler)
** descr: pcap handle for reading incoming packets
** main_tasks: tasks to be executed by main thread
** worker_tasks: tasks to be executed by worker threads
** pending_tasks: boolean set to true if worker_tasks is not empty
** end: boolean signaling the end of ft_nmap's execution
*/
typedef struct		s_nmap_config
{
	// Initialized at startup
	const char		*exec;
	int				speedup;
	int				verbose;
	int				debug;
	uint8_t			ports_to_scan[PORTS_COUNT];
	uint16_t		ports[MAX_PORTS + 1];
	uint16_t		nports;
	const char		*hosts;
	const char		*hosts_file;
	uint8_t			scans[SCAN_COUNT];
	uint8_t			nscans;
	const char		*scan_strings[SCAN_COUNT];
	int				hosts_fd;
	int				linktype;
	size_t			linkhdr_size;
	struct ifaddrs	*ifap;
	enum e_ip_modes	ip_mode;
	int				socket[SOCKET_COUNT];
	t_netinfo		netinf;
	t_ft_thread		thread[MAX_THREADS];
	uint8_t			nthreads;
	pthread_mutex_t	print_mutex;
	pthread_mutex_t	high_mutex;
	pthread_mutex_t	low_mutex;
	pcap_t			*descr;
	// Modified during execution
	t_host_job		host_job;
	t_probe			probes[MAX_PROBE];
	sig_atomic_t	nprobes;
	t_list			*main_tasks;
	t_list			*worker_tasks;
	sig_atomic_t	pending_tasks;
	sig_atomic_t	end;
}					t_nmap_config;

# define	CONFIG_DEF				{\
	ft_exec_name(*argv), 0, 0, 0, { 0 }, { 0 }, 0, NULL, NULL, { 0 }, 0, { 0 },\
	-1, 0, 0, NULL, E_IPALL, { -1, -1, -1, -1 }, { 0 }, {{ 0 }}, 0,\
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER,\
	PTHREAD_MUTEX_INITIALIZER, NULL, { 0 }, {{ 0 }}, 0, NULL, NULL, 0, 0\
}

/*
** Task structure: given to workers and main by next_task()
**
** type: well, type of task (duh)
** probe: probe in case the task is of type PROBE or REPLY
** result: scan result from given packet for REPLY task
*/
typedef struct		s_task
{
	enum e_tasks	type;
	t_probe			*probe;
	uint8_t			result;
}					t_task;

// task function type
typedef void		(*taskf)(t_task *task, t_nmap_config *cfg);

/*
** Option functions
*/

void		intopt(int *dest, const char *arg, int min, int max);
const char	*parse_comma_list(const char *str);
void		get_options(t_nmap_config *cfg, int argc, char **argv);
void		ports_option(t_nmap_config *cfg, t_optdata *optd);
void		scan_option(t_nmap_config *cfg, t_optdata *optd);
void		verbose_scan(t_nmap_config *cfg, t_probe *probe,
				t_packet *packet, const char *action);
void		verbose_reply(t_nmap_config *cfg, t_task *task, t_packet *reply);
void		debug_listener_setup(t_nmap_config *cfg, char *filter);
void		debug_invalid_packet(t_nmap_config *cfg,
				t_packet *packet, char *action);
void		debug_task(t_nmap_config *cfg, t_task *task);
void		debug_print(t_nmap_config *cfg, const char *format, ...);

/*
** Network functions
*/

void		open_device(t_nmap_config *cfg, int maxlen, int timeout);
void		set_alarm_handler(void);
void		init_sockets(t_nmap_config *cfg);
void		close_sockets(t_nmap_config *cfg);
void		get_network_info(t_nmap_config *cfg);
int			get_destinfo(t_ip *dest_ip, const char *target, t_nmap_config *cfg);
const char	*next_host(t_ip *ip, t_nmap_config *cfg);
void		new_host(t_nmap_config *cfg);
void		build_probe_packet(t_probe *probe, uint8_t version);
void		send_probe(t_nmap_config *cfg, t_probe *probe);
void		pcap_handlerf(uint8_t *u, const struct pcap_pkthdr *h,
				const uint8_t *bytes);
int			ft_listen(t_packet *reply, pcap_t *descr,
				pcap_handler callback, int cnt);
void		set_filter(t_nmap_config *cfg, t_probe *probe);
uint8_t		scan_result(enum e_scans scan_type, t_packet *reply);

/*
** Job functions
*/

void		nmap_mutex_lock(pthread_mutex_t *mutex, int *locked);
void		nmap_mutex_unlock(pthread_mutex_t *mutex, int *locked);
void		start_workers(t_nmap_config *cfg);
void		wait_workers(t_nmap_config *cfg);
void		*worker(void *ptr);
int			update_job(t_nmap_config *cfg, t_task *task);
void		print_config(t_nmap_config *cfg);
void		print_host_job(t_host_job *host_job, t_nmap_config *cfg);
void		push_tasks(t_list **dest, t_list *tasks,
				t_nmap_config *cfg, int prio);
t_task		*pop_task(t_list **src, t_nmap_config *cfg, int prio);
void		push_reply_task(t_task *task);
void		init_tasks(t_nmap_config *cfg);

/*
** ft_nmap constants
*/

extern const taskf		g_tasks[TASK_COUNT];
extern const char		*g_nmap_task_strings[TASK_COUNT];
extern const char		*g_nmap_scan_strings[SCAN_COUNT];
extern const char		*g_tcp_services[PORTS_COUNT][2];
extern const char		*g_udp_services[PORTS_COUNT][2];
extern const char		*g_sctp_services[PORTS_COUNT][2];

/*
** ft_nmap globals
*/

extern __thread int			g_print_locked;
extern __thread int			g_high_locked;
extern __thread int			g_low_locked;
extern t_nmap_config		*g_cfg;

#endif
