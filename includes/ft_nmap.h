/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:29:05 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/20 16:30:52 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "libft.h"

/*
** nmap macros
*/

// stringify macro value
# define	xstr(s)	str(s)
# define	str(s)	#s

# define	MAX_SPEEDUP	250

# define	CONFIG_DEF	{\
	ft_exec_name(*argv), 0\
}

/*
** t_nmap_config: nmap configuration
**
** exec: executable name
*/
typedef struct	s_nmap_config
{
	const char	*exec;
	int			speedup;
}				t_nmap_config;

/*
** nmap functions
*/
void	get_options(t_nmap_config *cfg, int argc, char **argv);

#endif
