/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:29:05 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/21 13:39:08 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "libft.h"
# include <limits.h>

/*
** ft_nmap macros
*/

# define	xstr(s)	str(s)			// stringify macro value
# define	str(s)	#s

# define	MAX_SPEEDUP		250
# define	MAX_PORTS		1024	// maximum number of ports to scan

// scans
# define	S_SYN			0x01
# define	S_NULL			0x02
# define	S_ACK			0x04
# define	S_FIN			0x08
# define	S_XMAS			0x10
# define	S_UDP			0x20
# define	S_ALL			(S_SYN | S_NULL | S_ACK | S_FIN | S_XMAS | S_UDP)

# define	CONFIG_DEF	{\
	ft_exec_name(*argv), 0, { 0 }, { 0 }, 0, NULL, NULL, 0\
}

/*
** ft_nmap constants
*/
extern const char		*g_nmap_scan_strings[];
extern const uint8_t	g_nmap_scan_codes[];

/*
** t_nmap_config: nmap configuration
**
** exec: executable name
** speedup: number of parallel threads to use
** ports_to_scan: boolean array representing every port given as arguments
** ports: compressed list with the first MAX_PORTS ports of ports_to_scan
** nb_ports: number of ports to scan in ports array
** hosts: hosts list given by cmd argument
** hosts_file: file containing a list of hosts
** scans: scans to perform as an or'ed integer
*/
typedef struct	s_nmap_config
{
	const char	*exec;
	int			speedup;
	uint8_t		ports_to_scan[USHRT_MAX + 1];
	uint16_t	ports[MAX_PORTS + 1];
	int			nb_ports;
	const char	*hosts;
	const char	*hosts_file;
	uint8_t		scans;
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