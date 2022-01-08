/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:29:05 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/08 04:50:01 by yforeau          ###   ########.fr       */
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

# define	xstr(s)						str(s)	// stringify macro value
# define	str(s)						#s

# define	MAX_SPEEDUP					250		// max number of additional threads
# define	MAX_THREADS					(MAX_SPEEDUP + 1)	// counts main thread
# define	MAX_PORTS					1024	// maximum number of ports to scan
# define	MAX_LST_ELM_LEN				1024	// biggest possible comma list element
# define	PORTS_COUNT					0x10000	// Number of ports (USHRT_MAX + 1)
# define	MAX_RETRY					4		// Number of retries for sending probe
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
# define	TASK_COUNT		7
enum		e_tasks {
	E_TASK_THREAD_SPAWN = 0,
	E_TASK_LISTEN,
	E_TASK_NEW_HOST,
	E_TASK_PROBE,
	E_TASK_REPLY,
	E_TASK_THREAD_WAIT,
	E_TASK_PRINT_STATS,
};

// Scans
# define	SCAN_COUNT		6
enum		e_scans { E_SYN = 0, E_NULL, E_ACK, E_FIN, E_XMAS, E_UDP };

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
** retry: counter of retries (MAX_RETRY then timeout, sig atomic too)
** type: scan_job's scan type
** srcip: ip to send probe to
** dstip: ip to send probe to
** srcp: src port (PORT_DEF + index of the scan_job in the scan_jobs array)
** dstp: port to send probe to
** host_job_id: id of the host job for this scan_job
** port_job_id: index of the port_job in the host_job's port_jobs array
** probes: scan_job probe packets
** socket: socket type
*/
typedef struct				s_scan_job
{
	uint8_t					status;
	sig_atomic_t			retry;
	_Atomic enum e_scans	type;
	t_ip					*srcip;
	t_ip					*dstip;
	uint16_t				srcp;
	uint16_t				dstp;
	uint16_t				host_job_id;
	uint16_t				port_job_id;
	t_packet				**probes;
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
	atomic_int		scan_locks[SCAN_COUNT];
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
** t_nmap_config: nmap configuration
**
** exec: executable name
** speedup: number of parallel threads to use
** verbose: additional printing option
** debug: even more optional additional printing
** complete: option to show every port and scan type
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
** descr: pcap handle for reading incoming packets
** udp_payloads: structure to fetch the udp payloads by port
** host_job: current host_job
** scan_jobs: scan_job array each corresponding to a scan
** nscan_jobs: scan_job count (sigatomic for alarm handler)
** main_tasks: tasks to be executed by main thread
** worker_tasks: tasks to be executed by worker threads
** pending_tasks: boolean set to true if worker_tasks is not empty
** current_scan_job: id of current scan_job for monothreaded runs
** current_payload_index: id of current payload_index for monothreaded runs
** end: boolean signaling the end of ft_nmap's execution
** start_ts: ft_nmap start timestamp (after tasks initialization)
** end_ts: ft_nmap end timestamp (after thread_wait/listen)
** host_count: number of hosts given by the user
** received_packet_count: count of received packets handled by pcap
** listen_breaks_total: total count of listen loop breaks
** listen_breaks_manual: times where pcap_breakloop() was used
** listen_breaks_zero_packet: listen breaks with 0 packet found
*/
typedef struct		s_nmap_config
{
	// Initialized at startup
	const char		*exec;
	int				speedup;
	int				verbose;
	int				debug;
	int				complete;
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
	pcap_t			*descr;
	t_udp_payload	**udp_payloads[PORTS_COUNT];
	// Modified during execution
	t_host_job		host_job;
	t_scan_job		*scan_jobs[MAX_PROBE];
	sig_atomic_t	nscan_jobs;
	t_list			*main_tasks;
	t_list			*worker_tasks;
	sig_atomic_t	pending_tasks;
	sig_atomic_t	current_scan_job;
	sig_atomic_t	current_payload_index;
	sig_atomic_t	end;
	struct timeval	start_ts;
	struct timeval	end_ts;
	int				host_count;
	int				received_packet_count;
	int				listen_breaks_total;
	int				listen_breaks_manual;
	int				listen_breaks_zero_packet;
}					t_nmap_config;

# define	CONFIG_DEF				{\
	*argv, 0, 0, 0, 0, 0, { 0 }, { 0 }, 0, NULL, NULL, NULL, { 0 }, 0, { 0 },\
	-1, 0, 0, NULL, E_IPALL, { -1, -1, -1, -1 }, { 0 }, {{ 0 }}, 0,\
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER,\
	PTHREAD_MUTEX_INITIALIZER, NULL, { 0 }, { 0 }, { 0 }, 0, NULL, NULL, 0,\
	-1, 0, 0, { 0 }, { 0 }, 0, 0, 0, 0, 0\
}

/*
** Task structure: given to workers and main by next_task()
**
** type: well, type of task (duh)
** scan_job: scan_job for type PROBE, REPLY (timeout), or LISTEN (monothread)
** payload_index: index of the probe to send for PROBE tasks
** reply: scan reply bytes for REPLY task
** reply_size: scan reply packet size for REPLY task
*/
typedef struct		s_task
{
	enum e_tasks	type;
	t_scan_job		*scan_job;
	uint16_t		payload_index;
	uint8_t			*reply;
	size_t			reply_size;
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
void		new_host(t_nmap_config *cfg);
void		build_probe_packet(t_packet *dest, t_scan_job *scan_job,
				uint8_t *layer5, uint16_t l5_len);
void		send_probe(t_nmap_config *cfg, t_scan_job *scan_job, uint16_t i);
void		pcap_handlerf(uint8_t *u, const struct pcap_pkthdr *h,
				const uint8_t *bytes);
int			ft_listen(t_packet *reply, pcap_t *descr,
				pcap_handler callback, int cnt);
void		set_filter(t_nmap_config *cfg, t_scan_job *scan_job);
uint8_t		scan_result(enum e_scans type, t_packet *reply);
uint8_t		parse_reply_packet(t_task *task, t_nmap_config *cfg,
				t_scan_job **scan_job);

/*
** Job functions
*/

void		nmap_mutex_lock(pthread_mutex_t *mutex, int *locked);
void		nmap_mutex_unlock(pthread_mutex_t *mutex, int *locked);
void		start_workers(t_nmap_config *cfg);
void		wait_workers(t_nmap_config *cfg);
void		*worker(void *ptr);
int			update_job(t_nmap_config *cfg, t_scan_job *scan_job,
				uint8_t result);
void		print_config(t_nmap_config *cfg);
void		print_host_job(t_host_job *host_job, t_nmap_config *cfg);
void		port_report(t_host_job *host_job, t_nmap_config *cfg);
void		range_report(t_host_job *host_job, t_nmap_config *cfg);
void		heatmap_report(t_host_job *host_job, t_nmap_config *cfg);
void		push_tasks(t_list **dest, t_list *tasks,
				t_nmap_config *cfg, int prio);
t_task		*pop_task(t_list **src, t_nmap_config *cfg, int prio);
void		push_reply_task(t_task *task);
void		init_tasks(t_nmap_config *cfg);
void		stats_listen(t_nmap_config *cfg, int packet_count);

/*
** Utils
*/

void		shitty_usleep(uint64_t ms);
double		ts_msdiff(struct timeval *a, struct timeval *b);

/*
** ft_nmap constants
*/

extern const taskf		g_tasks[TASK_COUNT];
extern const char		*g_nmap_task_strings[TASK_COUNT];
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
extern t_nmap_config		*g_cfg;

#endif
