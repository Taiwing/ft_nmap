/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:29:05 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 08:30:10 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "network.h"
# include <limits.h>
# include <fcntl.h>
# include <pthread.h>
# include <sys/time.h>

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
# define	NB_SCANS				6
# define	NB_SOCKETS				4

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
	E_STATE_SCAN_MASK		= 0xf8	// Mask for scan_job status
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
*/
typedef struct	s_port_job
{
	uint8_t		status;
	uint8_t		ongoing;
	uint8_t		done;
	uint8_t		scan_jobs[NB_SCANS];
}				t_port_job;

/*
** Job structure: this is the status of each tasks on a given host
**
** host: host string
** host_ip: IP from getaddrinfo()
** family: IPv4 or IPv6 host and scans
** dev: interface to scan from
** status: host_job status
** ongoing: counter of full port_jobs
** done: counter of finished port_jobs
** start_ts: ts at start of host_job
** end_ts: ts at end of host_job
** port_jobs: status of each port_job
*/
typedef struct		s_host_job
{
	char			*host;
	t_ip			host_ip;
	uint16_t		family;
	t_ifinfo		*dev;
	uint8_t			status;
	uint16_t		ongoing;
	uint16_t		done;
	struct timeval	start_ts;
	struct timeval	end_ts;
	t_port_job		*port_jobs;
}					t_host_job;

/*
** t_probe: nmap probes
**
** is_ready: set to true if worker is ready to listen
** retry: counter of retries (MAX_RETRY then timeout)
** ip: destination IP
** size: size of probe packet
** packet: probe packet data
** socket: socket type
** descr: pcap handle
*/
typedef struct		s_probe
{
	int				is_ready;
	int				retry;
	t_ip			*ip;
	size_t			size;
	uint8_t			*packet;
	enum e_sockets	socket;
	pcap_t			*descr;
}					t_probe;

/*
** t_nmap_config: nmap configuration
**
** exec: executable name
** speedup: number of parallel threads to use
** verbose: additional printing option
** ports_to_scan: boolean array representing every port given as arguments
** ports: compressed list with the first MAX_PORTS ports of ports_to_scan
** nports: number of ports to scan in ports array
** hosts: hosts list given by cmd argument
** hosts_file: file containing a list of hosts
** scans: scans to perform as an array of booleans
** nscans: number of scans to perform on each port
** scan_strings: store selected scan names
** hosts_fd: file descriptor for the hosts_file
** host_jobs: list of active host_jobs
** empty_host_jobs: store allocated and zeroed out host_jobs
** global_mutex: global mutex
** thread: threads array
** ifap: pointer to getifaddrs output (to be freed in cleanup)
** ip_mode: ip configuration (IPv4/IPv6 enabled/disabled)
** socket: sockets for sending probe packets
** netinf: information about the network interfaces
** probe: probes built by thread workers
*/
typedef struct	s_nmap_config
{
	const char		*exec;
	int				speedup;
	int				verbose;
	uint8_t			ports_to_scan[PORTS_COUNT];
	uint16_t		ports[MAX_PORTS + 1];
	uint16_t		nports;
	const char		*hosts;
	const char		*hosts_file;
	uint8_t			scans[NB_SCANS];
	uint8_t			nscans;
	const char		*scan_strings[NB_SCANS];
	int				hosts_fd;
	t_list			*host_jobs;
	t_list			*empty_host_jobs;
	pthread_mutex_t	global_mutex;
	pthread_mutex_t	probe_mutex;
	t_ft_thread		thread[MAX_THREADS];
	struct ifaddrs	*ifap;
	enum e_ip_modes	ip_mode;
	int				socket[NB_SOCKETS];
	t_netinfo		netinf;
	t_probe			probe[MAX_THREADS];
}					t_nmap_config;

# define	CONFIG_DEF				{\
	ft_exec_name(*argv), 0, 0, { 0 }, { 0 }, 0, NULL, NULL, { 0 },\
	0, { 0 }, -1, NULL, NULL, {{ 0 }}, {{ 0 }}, {{ 0 }}, NULL,\
	E_IPALL, { -1, -1, -1, -1 }, { 0 }, {{ 0 }}\
}

/*
** Scan structure: structure given to worker
**
** type: type of scan_job to perform
** result: return status of the scan_job
** port_job: pointer to the port_job of this scan_job
** port_job_id: index of the port_job in the host_job's port_jobs array
** host_job: pointer to the host_job of this port_job
** host_job_ptr: this host_job's list pointer
** cfg: config pointer
** descr: pcap handle for receiving replies
** probe: probe packet to be sent
*/
typedef struct		s_scan_job
{
	enum e_scans	type;
	uint8_t			result;
	t_port_job		*port_job;
	uint16_t		port_job_id;
	t_host_job		*host_job;
	t_list			*host_job_ptr;
	t_nmap_config	*cfg;
	pcap_t			*descr;
	t_packet		probe;
}					t_scan_job;

# define	SCAN_DEF			{\
	0, 0, NULL, 0, NULL, NULL, &cfg, NULL, { 0 }\
}

/*
** Option functions
*/

void		intopt(int *dest, const char *arg, int min, int max);
const char	*parse_comma_list(const char *str);
void		get_options(t_nmap_config *cfg, int argc, char **argv);
void		ports_option(t_nmap_config *cfg, t_optdata *optd);
void		scan_option(t_nmap_config *cfg, t_optdata *optd);
void		verbose_listener_setup(t_scan_job *scan, char *filter);
void		verbose_scan(t_scan_job *scan, t_packet *packet,
				const char *action);

/*
** Network functions
*/

void		set_alarm_tick(void);
void		init_sockets(t_nmap_config *cfg);
void		close_sockets(t_nmap_config *cfg);
void		get_network_info(t_nmap_config *cfg);
int			get_destinfo(t_ip *dest_ip, const char *target, t_nmap_config *cfg);
const char	*next_host(t_ip *ip, t_nmap_config *cfg);
void		build_scan_probe(t_packet *probe, t_scan_job *scan,
				uint16_t srcp, uint16_t dstp);
void		share_probe(t_scan_job *scan, size_t size);
void		send_probe(t_nmap_config *cfg, t_probe *probe);
void		grab_reply(uint8_t *user, const struct pcap_pkthdr *h,
				const uint8_t *bytes);
pcap_t		*setup_listener(t_scan_job *scan, uint16_t srcp, uint16_t dstp);
int			ft_listen(t_packet *reply, pcap_t *descr, pcap_handler callback);
void		set_scan_result(t_scan_job *scan, t_packet *reply);

/*
** Job functions
*/

void		nmap_mutex_lock(pthread_mutex_t *mutex, int *locked);
void		nmap_mutex_unlock(pthread_mutex_t *mutex, int *locked);
t_scan_job		*next_job(t_scan_job *scan);
void		wait_workers(t_nmap_config *cfg);
void		start_workers(t_nmap_config *cfg, t_scan_job *scan);
void		*worker(void *ptr);
t_list		*init_new_host_job(t_scan_job *scan);
void		update_job(t_scan_job *scan);
void		print_config(t_nmap_config *cfg);
void		print_host_job(t_host_job *host_job, t_nmap_config *cfg);

/*
** ft_nmap constants
*/

extern const char		*g_nmap_scan_strings[];
extern const char		*g_tcp_services[PORTS_COUNT][2];
extern const char		*g_udp_services[PORTS_COUNT][2];
extern const char		*g_sctp_services[PORTS_COUNT][2];

/*
** ft_nmap globals
*/

extern __thread int			g_global_locked;
extern __thread int			g_probe_locked;
extern __thread t_scan_job	*g_scan;
extern t_nmap_config		*g_cfg;

#endif
