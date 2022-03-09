/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:29:05 by yforeau           #+#    #+#             */
/*   Updated: 2022/03/09 02:05:02 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "ft_nmap_network.h"
# include <limits.h>
# include <fcntl.h>
# include <pthread.h>
# include <sys/time.h>
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
# define	DEF_RETRIES					10
# define	MIN_RETRIES					0
# define	MAX_RETRIES					100
# define	MAX_PROBE					(MAX_PORTS * SCAN_COUNT)

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
	E_TASK_TIMEOUT			= 0x20,
	E_TASK_WORKER_WAIT		= 0x40,
	E_TASK_PRINT_STATS		= 0x80,
};
# define	LAST_TASK			E_TASK_PRINT_STATS
# define	ALL_TASKS			((LAST_TASK << 1) - 1)
# define	WORKER_TASKS		\
	(E_TASK_PROBE | E_TASK_REPLY | E_TASK_TIMEOUT | E_TASK_PRINT_STATS)
# define	MAIN_TASKS			\
	((ALL_TASKS ^ WORKER_TASKS) + E_TASK_PRINT_STATS)

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

// Send sockets
# define	SOCKET_SEND_COUNT	4
enum		e_send_sockets {
	E_SSEND_UDPV4 = 0,
	E_SSEND_TCPV4,
	E_SSEND_UDPV6,
	E_SSEND_TCPV6,
};

# define	SOCKET_SSEND_IS_IPV4(n)	(n == E_SSEND_UDPV4 || n == E_SSEND_TCPV4)
# define	SOCKET_SSEND_IS_IPV6(n)	(n == E_SSEND_UDPV6 || n == E_SSEND_TCPV6)
# define	SOCKET_SSEND_IS_UDP(n)	(n == E_SSEND_UDPV4 || n == E_SSEND_UDPV6)
# define	SOCKET_SSEND_IS_TCP(n)	(n == E_SSEND_TCPV4 || n == E_SSEND_TCPV6)

// Receive sockets
# define	SOCKET_RECV_COUNT	9
enum		e_recv_sockets {
	E_SRECV_UDPV4 = 0,
	E_SRECV_UDPV6,
	E_SRECV_TCPV4,
	E_SRECV_TCPV6,
	E_SRECV_ICMP_UDPV4,
	E_SRECV_ICMP_UDPV6,
	E_SRECV_ICMP_TCPV4,
	E_SRECV_ICMP_TCPV6,
	E_SRECV_STDIN,
};

# define	SOCKET_SRECV_IS_IPV4(n)\
	(n == E_SRECV_UDPV4 || n == E_SRECV_TCPV4\
	|| n == E_SRECV_ICMP_UDPV4 || n == E_SRECV_ICMP_TCPV4)
# define	SOCKET_SRECV_IS_IPV6(n)\
	(n == E_SRECV_UDPV6 || n == E_SRECV_TCPV6\
	|| n == E_SRECV_ICMP_UDPV6 || n == E_SRECV_ICMP_TCPV6)
# define	SOCKET_SRECV_IS_UDP(n)\
	(n == E_SRECV_UDPV4 || n == E_SRECV_ICMP_UDPV4\
	|| n == E_SRECV_UDPV6 || n == E_SRECV_ICMP_UDPV6)
# define	SOCKET_SRECV_IS_TCP(n)\
	(n == E_SRECV_TCPV4 || n == E_SRECV_ICMP_TCPV4\
	|| n == E_SRECV_TCPV6 || n == E_SRECV_ICMP_TCPV6)


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
** total_tries: total number of tries for this job (to initialize tries)
** socket: send socket type
** sent_ts: timestamp of last sent probe for this job
*/
typedef struct				s_scan_job
{
	uint8_t					status;
	_Atomic int				tries;
	enum e_scans			type;
	t_ip					*srcip;
	t_ip					*dstip;
	uint16_t				srcp;
	uint16_t				dstp;
	uint16_t				host_job_id;
	uint16_t				port_job_id;
	t_packet				**probes;
	uint16_t				probe_count;
	int						total_tries;
	enum e_send_sockets		socket;
	struct timeval			sent_ts;
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
** Task structure to be executed by workers
**
** type: well, type of task (duh)
** scan_job: scan_job for type PROBE or REPLY (timeout)
** reply: scan REPLY bytes
** reply_size: scan REPLY packet size
** reply_ip_header: scan REPLY ip header type for
** reply_time: timestamp of REPLY reception
** exec_time: timestamp from which the task can be executed (immediate if 0)
*/
typedef struct		s_task
{
	enum e_tasks	type;
	t_scan_job		*scan_job;
	uint8_t			*reply;
	size_t			reply_size;
	enum e_iphdr	reply_ip_header;
	struct timeval	reply_time;
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
** task_types: the kind of tasks the worker must execute
** task_max: max number of tasks to be executed (only for PSEUDO_THREADS)
*/
typedef struct		s_worker_config
{
	enum e_workers	type;
	t_list			**task_list;
	int				task_types;
	int				task_max;
}					t_worker_config;

/*
** t_nmap_config: nmap configuration
*/
typedef struct		s_nmap_config
{
	/* Initialized at startup */
	const char		*exec;
	int				speedup;
	int				verbose;
	int				debug;
	int				complete;
	int				retries;
	struct timeval	scan_delay;
	enum e_reports	report;
	int				exponential_backoff;
	int				ping_scan;
	int				skip_non_responsive;
	uint8_t			ports_to_scan[PORTS_COUNT];
	uint16_t		ports[MAX_PORTS + 1];
	uint16_t		nports;
	char			**hosts;
	const char		*hosts_file;
	const char		*dev;
	uint8_t			scans[SCAN_COUNT];
	uint8_t			nscans;
	int				has_udp_scans;
	int				has_tcp_scans;
	int				total_scan_count;
	const char		*scan_strings[SCAN_COUNT];
	int				hosts_fd;
	enum e_ip_modes	ip_mode;
	int				send_sockets[SOCKET_SEND_COUNT];
	int				recv_sockets[SOCKET_RECV_COUNT];
	t_netinfo		netinf;
	t_ft_thread		thread[MAX_THREADS];
	uint8_t			nthreads;
	pthread_mutex_t	print_mutex;
	pthread_mutex_t	high_mutex;
	pthread_mutex_t	low_mutex;
	pthread_mutex_t	send_mutex;
	pthread_mutex_t	rtt_mutex;
	t_udp_payload	**udp_payloads[PORTS_COUNT];
	t_worker_config	worker_main_config;
	t_worker_config	worker_thread_config;
	/* Modified during execution */
	t_host_job		host_job;
	t_scan_job		*scan_jobs[MAX_PROBE];
	t_list			*main_tasks;
	t_list			*thread_tasks;
	_Atomic int		pending_tasks;
	_Atomic int		running_tasks;
	_Atomic int		end;
	struct timeval	start_ts;
	struct timeval	end_ts;
	int				host_count;
	int				host_up;
	int				sent_packet_count;
	int				received_packet_count;
	_Atomic int		icmp_count;
	_Atomic int		listen_breakloop;
	t_rtt_control	rtt;
	t_send_window	window[SCAN_COUNT];
}					t_nmap_config;

# define	CONFIG_DEF				{\
	/* executable name */\
	.exec = *argv,\
	/* number of parallel threads to use */\
	.speedup = DEF_SPEEDUP,\
	/* additional printing option */\
	.verbose = 0,\
	/* even more optional additional printing */\
	.debug = 0,\
	/* option to show every port and scan type */\
	.complete = 0,\
	/* number of retries per scan probe */\
	.retries = DEF_RETRIES,\
	/*wait time between probes */\
	.scan_delay = { 0 },\
	/* type of report output */\
	.report = 0,\
	/* wait for ICMP packets during UDP scans on rate-limit */\
	.exponential_backoff = 1,\
	/* execute ping scan before port scanning (to check if host is up) */\
	.ping_scan = 1,\
	/* skip non responsive hosts if ping scan is set */\
	.skip_non_responsive = 0,\
	/* boolean array representing every port given as arguments */\
	.ports_to_scan = { 0 },\
	/* compressed list with the first MAX_PORTS ports of ports_to_scan */\
	.ports = { 0 },\
	/* number of ports to scan in ports array */\
	.nports = 0,\
	/* hosts list given by cmd arguments (argv + first_arg_index) */\
	.hosts = NULL,\
	/* file containing a list of hosts */\
	.hosts_file = NULL,\
	/* interface on which to listen to given by user */\
	.dev = NULL,\
	/* scans to perform as an array of booleans */\
	.scans = { 0 },\
	/* number of scans to perform on each port */\
	.nscans = 0,\
	/* boolean set to true if UDP scan is set */\
	.has_udp_scans = 0,\
	/* boolean set to true at least one TCP scan is set */\
	.has_tcp_scans = 0,\
	/* Total number of scans to execute by host (nports * nscans) */\
	.total_scan_count = 0,\
	/* store selected scan names */\
	.scan_strings = { 0 },\
	/* file descriptor for the hosts_file */\
	.hosts_fd = -1,\
	/* ip configuration (IPv4/IPv6 enabled/disabled) */\
	.ip_mode = E_IPALL,\
	/* sockets for sending probe packets */\
	.send_sockets = { -1, -1, -1, -1 },\
	/* sockets to receive reply packets or user input */\
	.recv_sockets = { -1, -1, -1, -1, -1, -1, -1, -1, 0 },\
	/* information about the network interfaces */\
	.netinf = { .iface = {{{ 0 }, 0, { 0 }, { 0 }}} },\
	/* threads array */\
	.thread = {{ 0 }},\
	/* thread count */\
	.nthreads = 0,\
	/* mutex for synchronizing printing */\
	.print_mutex = PTHREAD_MUTEX_INITIALIZER,\
	/* high priority mutex access to tasks list */\
	.high_mutex = PTHREAD_MUTEX_INITIALIZER,\
	/* low priority mutex access to tasks list */\
	.low_mutex = PTHREAD_MUTEX_INITIALIZER,\
	/* mutex for sending probes */\
	.send_mutex = PTHREAD_MUTEX_INITIALIZER,\
	/* mutex for rtt update and read */\
	.rtt_mutex = PTHREAD_MUTEX_INITIALIZER,\
	/* structure to fetch the udp payloads by port */\
	.udp_payloads = { 0 },\
	/* configuration of the main worker */\
	.worker_main_config = { .type = E_WORKER_MAIN, .task_types = MAIN_TASKS },\
	/* configuration of the thread workers */\
	.worker_thread_config = {\
		.type = E_WORKER_THREAD, .task_types = WORKER_TASKS\
	},\
	/* current host_job */\
	.host_job = { 0 },\
	/* scan_job array each corresponding to a scan */\
	.scan_jobs = { 0 },\
	/* tasks to be executed by worker main */\
	.main_tasks = NULL,\
	/* tasks to be executed by worker threads */\
	.thread_tasks = NULL,\
	/* boolean set to true if thread_tasks is not empty */\
	.pending_tasks = 0,\
	/* count of actually running tasks */\
	.running_tasks = 0,\
	/* boolean signaling the end of ft_nmap's execution */\
	.end = 0,\
	/* ft_nmap start timestamp (after tasks initialization) */\
	.start_ts = { 0 },\
	/* ft_nmap end timestamp (after thread_wait/listen) */\
	.end_ts = { 0 },\
	/* number of hosts given by the user */\
	.host_count = 0,\
	/* number of hosts given by the user that are up (if ping_scan) */\
	.host_up = 0,\
	/* count of packets sent */\
	.sent_packet_count = 0,\
	/* count of received packets */\
	.received_packet_count = 0,\
	/* count of icmp response packets */\
	.icmp_count = 0,\
	/* end LISTEN task */\
	.listen_breakloop = 0,\
	/* RTT control structure for computing timeout */\
	.rtt = DEF_RTT,\
	/* send window for congestion handling of each scan*/\
	.window = {{ 0 }},\
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
void		init_send_sockets(t_nmap_config *cfg);
void		init_recv_sockets(t_nmap_config *cfg);
void		close_sockets(t_nmap_config *cfg);
void		get_network_info(t_nmap_config *cfg);
char		*next_host(t_ip *ip, t_nmap_config *cfg);
int			new_host(t_nmap_config *cfg);
void		build_probe_packet(t_packet *dest, t_scan_job *scan_job,
				uint8_t *layer5, uint16_t l5_len);
void		send_probe(t_nmap_config *cfg, t_scan_job *scan_job, uint16_t i);
int			ft_listen(struct pollfd *listen_fds, int fds_count, int timeout);
void		set_filters(t_nmap_config *cfg);
uint8_t		scan_result(enum e_scans type, t_packet *reply);
uint8_t		parse_reply_packet(t_task *task, t_nmap_config *cfg,
		t_scan_job **scan_job, enum e_iphdr iph);

/*
** Job functions
*/

void		nmap_mutex_lock(pthread_mutex_t *mutex, int *locked);
void		nmap_mutex_unlock(pthread_mutex_t *mutex, int *locked);
void		start_worker_threads(t_nmap_config *cfg);
void		wait_worker_threads(t_nmap_config *cfg);
void		*worker(void *ptr);
int			update_job(t_nmap_config *cfg, t_scan_job *scan_job,
				uint8_t result, int timeout);
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
void		flush_tasks(t_list **dest, t_nmap_config *cfg, int prio);
void		push_task(t_list **dest, t_nmap_config *cfg, t_task *task,
				int front);
void		init_tasks(t_nmap_config *cfg);
void		probe_timeout(struct timeval *sent_ts, struct timeval *timeout_ts);
void		pseudo_thread_worker(void);
double		print_end_stats(void);
double		print_update_stats(void);
void		reset_timeout(t_nmap_config *cfg, struct timeval *init);

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

/*
** ft_nmap globals
*/

extern __thread int			g_print_locked;
extern __thread int			g_high_locked;
extern __thread int			g_low_locked;
extern __thread int			g_send_locked;
extern __thread int			g_rtt_locked;
extern t_nmap_config		*g_cfg;

#endif
