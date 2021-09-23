/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:29:05 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/23 21:05:40 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "libft.h"
# include <limits.h>
# include <errno.h>
# include <fcntl.h>
# include <pthread.h>

/*
** ft_nmap macros
*/

# define	xstr(s)					str(s)	// stringify macro value
# define	str(s)					#s

# define	MAX_SPEEDUP				250
# define	MAX_PORTS				1024	// maximum number of ports to scan
# define	MAX_LST_ELM_LEN			1024	// biggest possible comma list element
# define	PORTS_COUNT				0x10000	// Number of ports (USHRT_MAX + 1)

# define	SERVICE_NAME_MAXLEN		20		// biggest service name string
# define	SERVICE_DESC_MAXLEN		331		// biggest service description string

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

# define	CONFIG_DEF				{\
	ft_exec_name(*argv), 0, { 0 }, { 0 }, 0, NULL, NULL, { 0 }, 0, -1, NULL, NULL\
}

/*
** Scans
*/
enum e_scans { E_SYN = 0, E_NULL, E_ACK, E_FIN, E_XMAS, S_UDP };

/*
** Task structure: this is the status of each scan on a given port
**
** status: task status
** scans: status of each scan
*/
typedef struct	s_task
{
	uint8_t		status;
	uint8_t		scans[NB_SCANS];
}				t_task;

/*
** Job structure: this is the status of each tasks on a given host
**
** host: host string
** status: job status
** start_ts: ts at start of job
** end_ts: ts at end of job
** tasks: status of each task
*/
typedef struct		s_job
{
	char			*host;
	uint8_t			status;
	struct timeval	start_ts;
	struct timeval	end_ts;
	t_task			*tasks;
}					t_job;

/*
** ft_nmap constants
*/
extern const char		*g_nmap_scan_strings[];
extern const char		*g_tcp_services[PORTS_COUNT][2];
extern const char		*g_udp_services[PORTS_COUNT][2];
extern const char		*g_sctp_services[PORTS_COUNT][2];

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
** scans: scans to perform as an or'ed integer
** nscans: number of scans to perform on each port
** hosts_fd: file descriptor for the hosts_file
** jobs: list of active jobs
** empty_jobs: store allocated and zeroed out jobs
*/
typedef struct	s_nmap_config
{
	const char	*exec;
	int			speedup;
	uint8_t		ports_to_scan[PORTS_COUNT];
	uint16_t	ports[MAX_PORTS + 1];
	uint16_t	nports;
	const char	*hosts;
	const char	*hosts_file;
	uint8_t		scans[NB_SCANS];
	uint8_t		nscans;
	int			hosts_fd;
	t_list		*jobs;
	t_list		*empty_jobs;
}				t_nmap_config;

/*
** ft_nmap functions
*/
char		*intopt(int *dest, const char *arg, int min, int max);
const char	*parse_comma_list(const char *str);
void		get_options(t_nmap_config *cfg, int argc, char **argv);
char		*ports_option(t_nmap_config *cfg, t_optdata *optd);
char		*scan_option(t_nmap_config *cfg, t_optdata *optd);

#endif
