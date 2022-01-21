/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:29:05 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/21 15:40:21 by yforeau          ###   ########.fr       */
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

# define	xstr(s)						str(s)	// Stringify macro value
# define	str(s)						#s

# define	DEF_SPEEDUP					0
# define	MIN_SPEEDUP					0
# define	MAX_SPEEDUP					250
# define	MAX_THREADS					(MAX_SPEEDUP + 1)
# define	MAX_PORTS					1024
# define	MAX_LST_ELM_LEN				1024
# define	PORTS_COUNT					0x10000
# define	DEF_RETRIES					5
# define	MIN_RETRIES					0
# define	MAX_RETRIES					100
# define	MAX_PROBE					(MAX_PORTS * SCAN_COUNT)
# define	DEF_TIMEOUT_MS				256
# define	DEF_TIMEOUT					{ 0, DEF_TIMEOUT_MS * 1000000 }

// Print format constants
# define	SERVICE_NAME_MAXLEN			20
# define	SERVICE_DESC_MAXLEN			331
# define	RES_MAXLEN					3
# define	JOB_LINE					80
# define	PORT_FIELD					5
# define	SERVICE_FIELD				SERVICE_NAME_MAXLEN
# define	SCAN_FIELD					5
# define	MAX_PRINT_PORTS				26

// Job states
enum		e_states {
	E_STATE_PENDING			= 0x00,	// Not started yet
	E_STATE_DONE			= 0x01,	// Finished
	E_STATE_OPEN			= 0x02,
	E_STATE_CLOSED			= 0x04,
	E_STATE_UNFILTERED		= 0x08,
	E_STATE_FILTERED		= 0x10,
	E_STATE_NONE			= 0x20, // Invalid reply packet
	E_STATE_SCAN_MASK		= 0x1e	// Mask for scan_job status
};
# define	MAX_PORT_STATUS				(E_STATE_OPEN | E_STATE_FILTERED)

// Tasks
enum		e_tasks {
	E_TASK_WORKER_SPAWN		= 0x01,
	E_TASK_NEW_HOST			= 0x02,
	E_TASK_LISTEN			= 0x04,
	E_TASK_PROBE			= 0x08,
	E_TASK_REPLY			= 0x10,
	E_TASK_WORKER_WAIT		= 0x20,
	E_TASK_PRINT_STATS		= 0x40,
};
# define	LAST_TASK			E_TASK_PRINT_STATS
# define	ALL_TASKS			((LAST_TASK << 1) - 1)
# define	WORKER_TASKS		(E_TASK_PROBE | E_TASK_REPLY)
# define	MAIN_TASKS			(ALL_TASKS ^ WORKER_TASKS)

// Workers
enum		e_workers {
	E_WORKER_MAIN = 0,
	E_WORKER_THREAD,
	E_WORKER_PSEUDO_THREAD,
};

// Scans
# define	SCAN_COUNT		6
enum		e_scans { E_SYN = 0, E_ACK, E_NULL, E_FIN, E_XMAS, E_UDP };

// IP modes
enum		e_ip_modes { E_IPALL = 0, E_IPV4, E_IPV6 };

// Sockets
# define	SOCKET_COUNT	4
enum		e_sockets { E_UDPV4 = 0, E_TCPV4, E_UDPV6, E_TCPV6 };

// Reports
enum		e_reports { E_REPORT_PORT = 0, E_REPORT_RANGE, E_REPORT_HEATMAP };

/*
** t_scan_job: nmap scan_jobs
**
** status: scan_job status
** tries: counter of tries (cfg->tries then timeout)
** type: scan_job's scan type
** srcip: ip to send probe to
** dstip: ip to send probe to
** srcp: src port (PORT_DEF + index of the scan_job in the scan_jobs array)
** dstp: port to send probe to
** host_job_id: id of the host job for this scan_job
** port_job_id: index of the port_job in the host_job's port_jobs array
** probes: scan_job probe packets
** probe_count: number of probe packets
** socket: socket type
*/
typedef struct				s_scan_job
{
	uint8_t					status;
	_Atomic int				tries;
	_Atomic enum e_scans	type;
	t_ip					*srcip;
	t_ip					*dstip;
	uint16_t				srcp;
	uint16_t				dstp;
	uint16_t				host_job_id;
	uint16_t				port_job_id;
	t_packet				**probes;
	uint16_t				probe_count;
	enum e_sockets			socket;
}							t_scan_job;

/*
** Port job structure: this is the status of each scan_job on a given port
**
** status: port_job status
** done: counter of finished scan_jobs
** scan_jobs: status of each scan_job
** scan_locks: to avoid two receive tasks on a scan
*/
typedef struct		s_port_job
{
	uint8_t			status;
	_Atomic uint8_t	done;
	t_scan_job		scan_jobs[SCAN_COUNT];
	_Atomic int		scan_locks[SCAN_COUNT];
}					t_port_job;

/*
** Host job structure: this is the status of each port_job on a given host
**
** host_job_id: job counter and identification
** host: host string
** ip: IP from getaddrinfo()
** family: IPv4 or IPv6 host and scans
** dev: interface to scan from
** status: host_job status
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
	_Atomic uint16_t	done;
	struct timeval		start_ts;
	struct timeval		end_ts;
	t_port_job			port_jobs[MAX_PORTS];
}						t_host_job;

/*
** Task structure: given to workers and main by next_task()
**
** type: well, type of task (duh)
** scan_job: scan_job for type PROBE, REPLY (timeout), or LISTEN (monothread)
** payload_index: index of the probe to send for PROBE tasks
** reply: scan reply bytes for REPLY task
** reply_size: scan reply packet size for REPLY task
** exec_time: timestamp from which the task can be executed (immediate if 0)
*/
typedef struct		s_task
{
	enum e_tasks	type;
	t_scan_job		*scan_job;
	uint16_t		payload_index;
	uint8_t			*reply;
	size_t			reply_size;
	struct timeval	exec_time;
}					t_task;

// task function type
typedef void		(*taskf)(t_task *task);

/*
** t_task_match: find a matching task for a worker
**
** task_types: OR'ed 'E_TASK' values representing the wanted tasks
** exec_time: to check that the task can already be executed
*/
typedef struct		s_task_match
{
	int				task_types;
	struct timeval	exec_time;
}					t_task_match;

/*
** s_worker_config: worker configuration
**
** type: type of worker
** task_list: the list of tasks to be executed
** task_match: the kind of tasks the worker must execute
** expiry: timestamp to stop worker (only for E_WORKER_PSEUDO_THREAD)
*/
typedef struct		s_worker_config
{
	enum e_workers	type;
	t_list			**task_list;
	t_task_match	task_match;
	struct timeval	expiry;
}					t_worker_config;

/*
** t_nmap_config: nmap configuration
**
** exec: executable name
** speedup: number of parallel threads to use
** verbose: additional printing option
** debug: even more optional additional printing
** complete: option to show every port and scan type
** retries: number of retries per scan probe
** scan_delay: wait time between probes (def: 0)
** max_rtt_timeout: time before probe retry or timeout (def: 256ms)
** report: type of report output
** ports_to_scan: boolean array representing every port given as arguments
** ports: compressed list with the first MAX_PORTS ports of ports_to_scan
** nports: number of ports to scan in ports array
** hosts: hosts list given by cmd arguments (argv + first_arg_index)
** hosts_file: file containing a list of hosts
** dev: interface on which to listen to given by user
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
** send_mutex: mutex for sending probes
** descr: pcap handle for reading incoming packets
** udp_payloads: structure to fetch the udp payloads by port
** worker_main_config: configuration of the main worker
** worker_thread_config: configuration of the thread workers
** host_job: current host_job
** scan_jobs: scan_job array each corresponding to a scan
** main_tasks: tasks to be executed by worker main
** thread_tasks: tasks to be executed by worker threads
** pending_tasks: boolean set to true if thread_tasks is not empty
** end: boolean signaling the end of ft_nmap's execution
** start_ts: ft_nmap start timestamp (after tasks initialization)
** end_ts: ft_nmap end timestamp (after thread_wait/listen)
** host_count: number of hosts given by the user
** sent_packet_count: number of packets sent
** received_packet_count: count of received packets handled by pcap
** listen_breaks_total: total count of listen loop breaks
** listen_breaks_manual: times where pcap_breakloop() was used
** listen_breaks_zero_packet: listen breaks with 0 packet found
** icmp_count: count of icmp response packets
** pcap_worker_is_working: boolean set to true if pcap_worker has started
*/
typedef struct		s_nmap_config
{
	// Initialized at startup
	const char		*exec;
	int				speedup;
	int				verbose;
	int				debug;
	int				complete;
	int				retries;
	struct timespec	scan_delay;
	struct timespec	max_rtt_timeout;
	enum e_reports	report;
	uint8_t			ports_to_scan[PORTS_COUNT];
	uint16_t		ports[MAX_PORTS + 1];
	uint16_t		nports;
	char			**hosts;
	const char		*hosts_file;
	const char		*dev;
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
	pthread_mutex_t	send_mutex;
	pcap_t			*descr;
	t_udp_payload	**udp_payloads[PORTS_COUNT];
	t_worker_config	worker_main_config;
	t_worker_config	worker_thread_config;
	// Modified during execution
	t_host_job		host_job;
	t_scan_job		*scan_jobs[MAX_PROBE];
	t_list			*main_tasks;
	t_list			*thread_tasks;
	_Atomic int		pending_tasks;
	_Atomic int		end;
	struct timeval	start_ts;
	struct timeval	end_ts;
	int				host_count;
	int				sent_packet_count;
	int				received_packet_count;
	int				listen_breaks_total;
	int				listen_breaks_manual;
	int				listen_breaks_zero_packet;
	_Atomic int		icmp_count;
	int				pcap_worker_is_working;
}					t_nmap_config;

# define	CONFIG_DEF				{\
	*argv, DEF_SPEEDUP, 0, 0, 0, DEF_RETRIES, { 0 }, DEF_TIMEOUT, 0, { 0 },\
	{ 0 }, 0, NULL, NULL, NULL, { 0 }, 0, { 0 }, -1, 0, 0, NULL, E_IPALL,\
	{ -1, -1, -1, -1 }, { 0 }, {{ 0 }}, 0, PTHREAD_MUTEX_INITIALIZER,\
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER,\
	PTHREAD_MUTEX_INITIALIZER, NULL, { 0 },\
	{ .type = E_WORKER_MAIN, .task_match = { .task_types = MAIN_TASKS }},\
	{ .type = E_WORKER_THREAD, .task_match = { .task_types = WORKER_TASKS }},\
	{ 0 }, { 0 }, NULL, NULL, 0, 0, { 0 }, { 0 }, 0, 0, 0, 0, 0, 0, 0, 0\
}

/*
** Option functions
*/

void		usage(const char *exec, int exit_value);
int			parse_int(const char *str, int min, int max, const char *type);
int			parse_int_prefix(const char *str, int min, int max,
				const char *type);
const char	*parse_comma_list(const char *str);
void		get_options(t_nmap_config *cfg, int argc, char **argv);
void		ports_option(t_nmap_config *cfg, t_optdata *optd);
void		scan_option(t_nmap_config *cfg, t_optdata *optd);
void		verbose_scan(t_nmap_config *cfg, t_scan_job *scan_job,
				t_packet *packet, const char *action);
void		verbose_reply(t_nmap_config *cfg, t_scan_job *scan_job,
				t_packet *reply, uint8_t result);
void		debug_listener_setup(t_nmap_config *cfg, char *filter);
void		debug_invalid_packet(t_nmap_config *cfg,
				t_packet *packet, char *action);
void		debug_task(t_nmap_config *cfg, t_task *task, uint8_t result);
void		debug_print(t_nmap_config *cfg, const char *format, ...);

/*
** Ports functions
*/

// setport function type
typedef void		(*t_setportf)(t_nmap_config *cfg, int pa, int pb, void *d);

void		set_scan_ports(t_nmap_config *cfg, int porta,
		int portb, void *data);
void		parse_ports(t_nmap_config *cfg, char *str,
		t_setportf setport, void *data);
void		init_udp_payloads(t_nmap_config *cfg);

/*
** Network functions
*/

void		open_device(t_nmap_config *cfg, int maxlen, int timeout);
void		set_alarm_handler(void);
void		init_sockets(t_nmap_config *cfg);
void		close_sockets(t_nmap_config *cfg);
void		get_network_info(t_nmap_config *cfg);
int			get_destinfo(t_ip *dest_ip, const char *target, t_nmap_config *cfg);
char		*next_host(t_ip *ip, t_nmap_config *cfg);
int			new_host(t_nmap_config *cfg);
void		build_probe_packet(t_packet *dest, t_scan_job *scan_job,
				uint8_t *layer5, uint16_t l5_len);
void		send_probe(t_nmap_config *cfg, t_scan_job *scan_job, uint16_t i);
void		pcap_handlerf(uint8_t *u, const struct pcap_pkthdr *h,
				const uint8_t *bytes);
int			ft_listen(t_packet *reply, pcap_t *descr,
				pcap_handler callback, int cnt);
void		set_filter(t_nmap_config *cfg);
uint8_t		scan_result(enum e_scans type, t_packet *reply);
uint8_t		parse_reply_packet(t_task *task, t_nmap_config *cfg,
				t_scan_job **scan_job);

/*
** Job functions
*/

void		nmap_mutex_lock(pthread_mutex_t *mutex, int *locked);
void		nmap_mutex_unlock(pthread_mutex_t *mutex, int *locked);
void		start_worker_threads(t_nmap_config *cfg);
void		wait_worker_threads(t_nmap_config *cfg);
void		*worker(void *ptr);
int			update_job(t_nmap_config *cfg, t_scan_job *scan_job,
				uint8_t result);
void		print_config(t_nmap_config *cfg);
void		print_host_job(t_host_job *host_job, t_nmap_config *cfg);
void		port_report(t_host_job *host_job, t_nmap_config *cfg);
void		range_report(t_host_job *host_job, t_nmap_config *cfg);
void		heatmap_report(t_host_job *host_job, t_nmap_config *cfg);
void		push_front_tasks(t_list **dest, t_list *tasks,
				t_nmap_config *cfg, int prio);
void		push_back_tasks(t_list **dest, t_list *tasks,
				t_nmap_config *cfg, int prio);
t_task		*pop_task(t_list **src, t_nmap_config *cfg, int prio,
				t_task_match *task_match);
void		push_tasks(t_list **dest, t_list *tasks,
				t_nmap_config *cfg, int prio);
void		push_reply_task(t_nmap_config *cfg, t_task *task,
				struct timeval *exec_time);
void		init_tasks(t_nmap_config *cfg);
void		stats_listen(t_nmap_config *cfg, int packet_count);
void		probe_retry_time(struct timeval *exec_time);
void		set_scan_job_timeout(t_nmap_config *cfg, t_scan_job *scan_job,
				struct timeval *exec_time);
void		init_scan_job_probes(t_nmap_config *cfg, t_scan_job *scan_job,
				struct timeval *exec_time);

/*
** Utils
*/

void		shitty_usleep(uint64_t ms);
double		ts_msdiff(struct timeval *a, struct timeval *b);
void		str_to_timespec(struct timespec *time, const char *str);
int			is_passed(struct timeval *date, struct timeval *expiry);

/*
** ft_nmap constants
*/

extern const t_opt		g_nmap_opt[];
extern const char		*g_nmap_help[];
extern const char		*g_nmap_usage[];
extern const char		*g_description;
extern const taskf		g_tasks[];
extern const char		*g_nmap_scan_strings[SCAN_COUNT];
extern const char		g_sep_line[JOB_LINE + 1];
extern const char		*g_scan_results[MAX_PORT_STATUS + 1];
extern const char		*g_port_status[MAX_PORT_STATUS + 1];
extern const char		*g_tcp_services[PORTS_COUNT][2];
extern const char		*g_udp_services[PORTS_COUNT][2];
extern const char		*g_sctp_services[PORTS_COUNT][2];

/*
** ft_nmap globals
*/

extern __thread int			g_print_locked;
extern __thread int			g_high_locked;
extern __thread int			g_low_locked;
extern __thread int			g_send_locked;
extern t_nmap_config		*g_cfg;

#endif
