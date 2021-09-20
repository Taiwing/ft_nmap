/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:29:05 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/20 15:33:34 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "libft.h"

/*
** nmap macros
*/

# define	CONFIG_DEF	{\
	ft_exec_name(*argv)\
}

/*
** t_nmap_config: nmap configuration
**
** exec: executable name
*/
typedef struct	s_nmap_config
{
	const char	*exec;
}				t_nmap_config;

#endif
