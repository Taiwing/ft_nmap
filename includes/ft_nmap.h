/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:29:05 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/29 18:18:23 by yforeau          ###   ########.fr       */
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

# define	MAX_SPEEDUP				250
# define	MAX_PORTS				1024	// maximum number of ports to scan
# define	MAX_LST_ELM_LEN			1024	// biggest possible comma list element
# define	PORTS_COUNT				0x10000	// Number of ports (USHRT_MAX + 1)

# define	NB_SCANS				6

// Scan/Task/Job states
# define	STATE_PENDING			0x00	// Not started yet
# define	STATE_ONGOING			0x01	// At least one scan started
# define	STATE_FULL				0x02	// Every scan/task is ongoing
# define	STATE_DONE				0x04	// Finished
# define	STATE_OPEN				0x08
# define	STATE_CLOSED			0x10
# define	STATE_FILTERED			0x20
# define	STATE_UNFILTERED		0x40
# define	SCAN_MASK				0xf8	// Mask for scan status

// Print format constants
# define	SERVICE_NAME_MAXLEN		20
# define	SERVICE_DESC_MAXLEN		331
# define	RES_MAXLEN				3
# define	JOB_LINE				80
# define	PORT_FIELD				5
# define	SERVICE_FIELD			SERVICE_NAME_MAXLEN
# define	SCAN_FIELD				5
# define	STATE_FIELD				6

// Scans
enum e_scans { E_SYN = 0, E_NULL, E_ACK, E_FIN, E_XMAS, S_UDP };

// IP modes
enum e_ip_modes { E_IPALL = 0, E_IPV4, E_IPV6 };

/*
** Task structure: this is the status of each scan on a given port
**
** status: task status
** ongoing: counter of started scans
** done: counter of finished scans
** scans: status of each scan
*/
typedef struct	s_task
{
	uint8_t		status;
	uint8_t		ongoing;
	uint8_t		done;
	uint8_t		scans[NB_SCANS];
}				t_task;

/*
** Job structure: this is the status of each tasks on a given host
**
** host: host string
** host_ip: IP from getaddrinfo()
** status: job status
** ongoing: counter of full tasks
** done: counter of finished tasks
** start_ts: ts at start of job
** end_ts: ts at end of job
** tasks: status of each task
*/
typedef struct		s_job
{
	char			*host;
	t_ip			host_ip;
	uint8_t			status;
	uint16_t		ongoing;
	uint16_t		done;
	struct timeval	start_ts;
	struct timeval	end_ts;
	t_task			*tasks;
}					t_job;

/*
** t_nmap_config: nmap configuration
**
** exec: executable name
** speedup: number of parallel threads to use
** ports_to_scan: boolean array representing every port given as arguments
** ports: compressed list with the first MAX_PORTS ports of ports_to_scan
** nports: number of ports to scan in ports array
** hosts: hosts list given by cmd argument
** hosts_file: file containing a list of hosts
** scans: scans to perform as an array of booleans
** nscans: number of scans to perform on each port
** scan_strings: store selected scan names
** hosts_fd: file descriptor for the hosts_file
** jobs: list of active jobs
** empty_jobs: store allocated and zeroed out jobs
** mutex: global mutex
** thread: threads array
** ifap: pointer to getifaddrs output (to be freed in cleanup)
** netinf: information about the network interfaces
*/
typedef struct	s_nmap_config
{
	const char		*exec;
	int				speedup;
	uint8_t			ports_to_scan[PORTS_COUNT];
	uint16_t		ports[MAX_PORTS + 1];
	uint16_t		nports;
	const char		*hosts;
	const char		*hosts_file;
	uint8_t			scans[NB_SCANS];
	uint8_t			nscans;
	const char		*scan_strings[NB_SCANS];
	int				hosts_fd;
	t_list			*jobs;
	t_list			*empty_jobs;
	pthread_mutex_t	mutex;
	t_ft_thread		thread[MAX_SPEEDUP];
	struct ifaddrs	*ifap;
	enum e_ip_modes	ip_mode;
	t_netinfo		netinf;
}					t_nmap_config;

# define	CONFIG_DEF				{\
	ft_exec_name(*argv), 0, { 0 }, { 0 }, 0, NULL, NULL, { 0 },\
	0, { 0 }, -1, NULL, NULL, {{ 0 }}, {{ 0 }}, NULL, E_IPALL, { 0 }\
}

/*
** Scan structure: structure given to worker
**
** type: type of scan to perform
** result: return status of the scan
** task: pointer to the task of this scan
** task_id: index of the task in the job's tasks array
** job: pointer to the job of this task
** job_ptr: this job's list pointer
** cfg: config pointer
*/
typedef struct		s_scan
{
	enum e_scans	type;
	uint8_t			result;
	t_task			*task;
	uint16_t		task_id;
	t_job			*job;
	t_list			*job_ptr;
	t_nmap_config	*cfg;
}					t_scan;

/*
** ft_nmap functions
*/
char		*intopt(int *dest, const char *arg, int min, int max);
const char	*parse_comma_list(const char *str);
void		get_options(t_nmap_config *cfg, int argc, char **argv);
char		*ports_option(t_nmap_config *cfg, t_optdata *optd);
char		*scan_option(t_nmap_config *cfg, t_optdata *optd);
void		get_network_info(t_nmap_config *cfg);
int			get_destinfo(t_ip *dest_ip, const char *target, t_nmap_config *cfg);
const char	*next_host(t_ip *ip, t_nmap_config *cfg);
void		nmap_mutex_lock(pthread_mutex_t *mutex);
void		nmap_mutex_unlock(pthread_mutex_t *mutex);
t_scan		*next_job(t_scan *scan);
void		wait_workers(t_nmap_config *cfg);
void		start_workers(t_nmap_config *cfg, t_scan *scan);
void		*worker(void *ptr);
t_list		*init_new_job(t_scan *scan);
void		update_job(t_scan *scan);
void		print_config(t_nmap_config *cfg);
void		print_job(t_job *job, t_nmap_config *cfg);

/*
** ft_nmap constants
*/
extern const char		*g_nmap_scan_strings[];
extern const char		*g_tcp_services[PORTS_COUNT][2];
extern const char		*g_udp_services[PORTS_COUNT][2];
extern const char		*g_sctp_services[PORTS_COUNT][2];

/*
** Global instance of nmap configuration (for atexit and signal handlers)
*/
extern t_nmap_config	*g_cfg;

#endif
