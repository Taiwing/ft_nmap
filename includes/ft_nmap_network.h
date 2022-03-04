/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap_network.h                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 11:36:28 by yforeau           #+#    #+#             */
/*   Updated: 2022/03/04 08:01:58 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_NETWORK_H
# define FT_NMAP_NETWORK_H

# include "libft.h"
# include <poll.h>
# include <errno.h>
# include <linux/if.h>

# define	PORT_DEF					45654	//TODO: TBD, not sure we will keep this one

# define	MAX_UDP_PAYLOADS			0x100
# define	UDP_PAYLOADS_FILE			"./data/nmap-payloads"
# define	MAX_UDP_PAYLOAD_LENGTH		MAX_PACKET_PAYLOAD_SIZE
# define	MAX_UDPFILE_TOKEN_LENGTH	(MAX_UDP_PAYLOAD_LENGTH)
# define	TOKEN_COUNT					7
# define	FT_NMAP_IFACE_COUNT			4

/*
** Network info: built with ft_net_listiface
**
** defdev_v4: IPv4 default interface
** defdev_v6: IPv6 default interface
** loopback_v4: IPv4 loopback interface for localhost scanning
** loopback_v6: IPv6 loopback interface for localhost scanning
*/
typedef struct		s_netinfo
{
	t_ifinfo		iface[FT_NMAP_IFACE_COUNT];
	t_ifinfo		*defdev_v4;
	t_ifinfo		*defdev_v6;
	t_ifinfo		*loopback_v4;
	t_ifinfo		*loopback_v6;
}					t_netinfo;

/*
** Udp payload file parsing
*/

// Udp payload file tokens
enum e_udpfile_token {
	E_UF_TOKEN_NONE = 0,
	E_UF_TOKEN_EOF,
	E_UF_TOKEN_STRING,
	E_UF_TOKEN_PROTO,
	E_UF_TOKEN_PROTO_PORTS,
	E_UF_TOKEN_SOURCE,
	E_UF_TOKEN_SOURCE_PORT,
};

/*
** t_udpfile_token:
**
** type: type of the token
** last: type of the last token (for the parse table)
** size: size of token data
** text: token data
*/
typedef struct				s_udpfile_token
{
	enum e_udpfile_token	type;
	enum e_udpfile_token	last;
	size_t					size;
	char					text[MAX_UDPFILE_TOKEN_LENGTH];
}							t_udpfile_token;

/*
** t_udp_payload: possible udp payload for a given port
**
** size: length of the payload in bytes
** data: paylaod data
*/
typedef struct		s_udp_payload
{
	size_t			size;
	uint8_t			*data;
}					t_udp_payload;

/*
** t_rtt_control: estimate current RTT and compute timeout
**
** initial_timeout: value at wich the RTT timeout is initialized
** min_timeout: minimum value of the RTT timeout
** max_timeout: maximum value of the RTT timeout
** smoothed: smoothed average RTT used to compute timeout
** variance: observed variance in RTT used to compute timeout
** timeout: current RTT timeout
*/
typedef struct		s_rtt_control
{
	struct timeval	initial_timeout;
	struct timeval	min_timeout;
	struct timeval	max_timeout;
	struct timeval	smoothed;
	struct timeval	variance;
	struct timeval	timeout;
}					t_rtt_control;

# define	DEF_TIMEOUT_MS				256
# define	MIN_TIMEOUT_MS				4
# define	MAX_TIMEOUT_MS				512
# define	MS_TO_TIMEVAL(ms)			{ ms / 1000, (ms % 1000) * 1000 }
# define	DEF_TIMEOUT					MS_TO_TIMEVAL(DEF_TIMEOUT_MS)
# define	MIN_TIMEOUT					MS_TO_TIMEVAL(MIN_TIMEOUT_MS)
# define	MAX_TIMEOUT					MS_TO_TIMEVAL(MAX_TIMEOUT_MS)

# define	DEF_RTT {\
	.initial_timeout = DEF_TIMEOUT,\
	.min_timeout = MIN_TIMEOUT,\
	.max_timeout = MAX_TIMEOUT,\
}

/*
** t_send_window: adapt concurrent probe count to network conditions
**
** current: number of probes currently sent and waiting for a reply
** size: actual size of the window (how many probes can be sent at once)
** min: minimum size of the window
** max: maximum size of the window
** ssthresh: slow start threshold (start congestion avoidance)
** timeoutthresh: max number of successive packet loss before backoff
** exponential_backoff: boolean to apply exponential_backoff or not
** avoid_count: increase this instead of size during congestion avoidance
** reply_count: total reply count
** timeout_count: total timeout count
** successive_timeout_count: count of successive timeouts
** responsive: does host look responsive on this scan
** rate_limit: estimated rate limit in probes per second
** rate_limit_ts: timestamp to start rate liming from
** rate_limit_current: number of rate limited probes sent from timestamp
*/

typedef struct		s_send_window
{
	_Atomic int		current;
	_Atomic int		size;
	int				min;
	int				max;
	int				ssthresh;
	int				timeoutthresh;
	int				exponential_backoff;
	_Atomic int		avoid_count;
	_Atomic int		reply_count;
	_Atomic int		timeout_count;
	_Atomic int		successive_timeout_count;
	_Atomic int		responsive;
	_Atomic int		rate_limit;
	_Atomic int64_t	rate_limit_ts;
	_Atomic int		rate_limit_current;
}					t_send_window;


# define	DEF_SIZE				16
# define	DEF_MIN					1
# define	DEF_MAX					(USHRT_MAX >> 2)
# define	DEF_SSTHRESH			(DEF_MAX >> 2)
# define	DEF_TIMEOUTTHRESH		4
# define	MAX_RESPONSIVE_TIMEOUT	4

# define	DEF_SEND_WINDOW {\
	.size = DEF_SIZE,\
	.min = DEF_MIN,\
	.max = DEF_MAX,\
	.ssthresh = DEF_SSTHRESH,\
	.timeoutthresh = DEF_TIMEOUTTHRESH,\
}

/*
** Time functions
** TODO: maybe move this to libft
*/

void		shitty_usleep(struct timeval *time);
void		shitty_ms_usleep(double ms);
double		ts_msdiff(struct timeval *a, struct timeval *b);
void		str_to_timeval(struct timeval *time, const char *str);
int			timeval_to_str(char *buf, size_t size, struct timeval *time);
void		rtt_update(struct timeval *sent, struct timeval *received);

/*
** Window functions
*/

int			full_window(t_send_window *window);
int			rate_limit(t_send_window *window, int64_t ts);
void		update_window(t_send_window *window, int is_reply);
void		backoff_window(t_send_window *window);
void		reset_window(t_send_window *window);

#endif
