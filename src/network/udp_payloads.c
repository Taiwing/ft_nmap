/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   udp_payloads.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/30 19:50:50 by yforeau           #+#    #+#             */
/*   Updated: 2021/12/11 09:45:00 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

//TODO: move to ft_nmap.h
#define MAX_UDP_PAYLOAD_LENGTH		2048
#define MAX_UDPFILE_TOKEN_LENGTH	1024
#define TOKEN_COUNT					7

enum e_udpfile_token {
	E_UF_TOKEN_NONE = 0,
	E_UF_TOKEN_EOF,
	E_UF_TOKEN_STRING,
	E_UF_TOKEN_PROTO,
	E_UF_TOKEN_PROTO_PORTS,
	E_UF_TOKEN_SOURCE,
	E_UF_TOKEN_SOURCE_PORT,
};

enum e_udpfile_token	g_uf_start[] = {
	E_UF_TOKEN_EOF,
	E_UF_TOKEN_PROTO,
	E_UF_TOKEN_NONE,
};

enum e_udpfile_token	g_uf_token_string[] = {
	E_UF_TOKEN_EOF,
	E_UF_TOKEN_STRING,
	E_UF_TOKEN_PROTO,
	E_UF_TOKEN_SOURCE,
	E_UF_TOKEN_NONE,
};

enum e_udpfile_token	g_uf_token_proto[] = {
	E_UF_TOKEN_PROTO_PORTS,
	E_UF_TOKEN_NONE,
};

enum e_udpfile_token	g_uf_token_proto_ports[] = {
	E_UF_TOKEN_STRING,
	E_UF_TOKEN_NONE,
};

enum e_udpfile_token	g_uf_token_source[] = {
	E_UF_TOKEN_SOURCE_PORT,
	E_UF_TOKEN_NONE,
};

enum e_udpfile_token	*g_parse_table[TOKEN_COUNT] = {
	[E_UF_TOKEN_NONE] = g_uf_start,
	[E_UF_TOKEN_STRING] = g_uf_token_string,
	[E_UF_TOKEN_PROTO] = g_uf_token_proto,
	[E_UF_TOKEN_PROTO_PORTS] = g_uf_token_proto_ports,
	[E_UF_TOKEN_SOURCE] = g_uf_token_source,
	[E_UF_TOKEN_SOURCE_PORT] = g_uf_start,
};

typedef struct				s_udpfile_token
{
	enum e_udpfile_token	type;
	enum e_udpfile_token	last;
	size_t					size;
	char					text[MAX_UDPFILE_TOKEN_LENGTH];
}							t_udpfile_token;

const char	*g_hexdigits = "0123456789abcdef";

static uint8_t	hextochar(char a, char b)
{
	uint8_t	res = 0;
	char	*d1 = ft_strchr(g_hexdigits, ft_tolower(a));
	char	*d2 = ft_strchr(g_hexdigits, ft_tolower(b));

	if (!d1 || !d2 || !*d1 || !*d2)
		return (res);
	res = (uint8_t)(d1 - g_hexdigits) << 4;
	res += (uint8_t)(d2 - g_hexdigits);
	return (res);
}

const char	g_escape_char[CHAR_MAX + 1] = {
	['0'] = '\0',
	['a'] = '\a',
	['b'] = '\b',
	['f'] = '\f',
	['n'] = '\n',
	['r'] = '\r',
	['t'] = '\t',
	['v'] = '\v',
};

static void	get_udpfile_string(t_udpfile_token *token, const char *line, int *i)
{
	int		j = *i + 1;
	char	newchar;

	while (line[j] && line[j] != '"' && token->size < MAX_UDPFILE_TOKEN_LENGTH)
	{
		if (line[j] == '\\' && line[j + 1] == 'x' && line[j + 2] && line[j + 3])
		{
			newchar = hextochar(line[j + 2], line[j + 3]);
			j += 3;
		}
		else if (line[j] == '\\' && line[j + 1])
		{
			if (!(newchar = g_escape_char[(int)line[++j]]) && line[j] != '0')
				newchar = line[j];
		}
		else
			newchar = line[j];
		token->text[token->size++] = newchar;
		++j;
	}
	if (token->size >= MAX_UDPFILE_TOKEN_LENGTH)
		ft_exit(EXIT_FAILURE, "%s: string token too long", __func__);
	else if (line[j] != '"')
		ft_exit(EXIT_FAILURE, "%s: unterminated string token", __func__);
	*i = j + 1;
}

static enum e_udpfile_token	get_udpfile_symbol(t_udpfile_token *token,
		const char *line, int *i)
{
	int	j = *i;

	while (line[j] && (ft_isalnum(line[j]) || line[j] == '-' || line[j] == ',')
		&& token->size < MAX_UDPFILE_TOKEN_LENGTH)
		token->text[token->size++] = line[j++];
	if (token->size >= MAX_UDPFILE_TOKEN_LENGTH)
		ft_exit(EXIT_FAILURE, "%s: symbol token too long (max: ", __func__);
	token->text[token->size] = 0;
	*i = j;
	if (!ft_strcmp(token->text, "udp"))
		return (E_UF_TOKEN_PROTO);
	else if (!ft_strcmp(token->text, "source"))
		return (E_UF_TOKEN_SOURCE);
	else if (token->last == E_UF_TOKEN_SOURCE)
		return (E_UF_TOKEN_SOURCE_PORT);
	return (E_UF_TOKEN_PROTO_PORTS);
}

static enum e_udpfile_token	tokenize(t_udpfile_token *token, const char *line)
{
	static int			i = 0;
	static const char	*current_line = NULL;

	i = current_line != line ? 0 : i;
	current_line = current_line != line ? line : current_line;
	token->size = 0;
	if (!line)
		return (E_UF_TOKEN_EOF);
	while (line[i] && ft_isspace(line[i]))
		++i;
	if (!line[i] || line[i] == '#')
		return (E_UF_TOKEN_NONE);
	else if (line[i] == '"')
	{
		get_udpfile_string(token, line, &i);
		return (E_UF_TOKEN_STRING);
	}
	return (get_udpfile_symbol(token, line, &i));
}

static void	set_udp_payloads(t_nmap_config *cfg, int porta, int portb, void *d)
{
	uint16_t		i;
	t_udp_payload	*payload = d;

	do
	{
		if (!cfg->udp_payloads[porta])
			cfg->udp_payloads[porta] =
				ft_memalloc(sizeof(t_udp_payload *) * MAX_UDP_PAYLOADS);
		for (i = 0; i < MAX_UDP_PAYLOADS - 1
			&& cfg->udp_payloads[porta][i]; ++i);
		if (cfg->udp_payloads[porta][i])
			ft_exit(EXIT_FAILURE, "%s: too many udp payloads for port %hu"
				" (max is %d)", __func__, porta, MAX_UDP_PAYLOADS - 1);
		cfg->udp_payloads[porta][i] = payload;
		++porta;
	} while (porta <= portb);
}

static void	init_payload(t_udp_payload **payload,
	uint8_t data[MAX_UDP_PAYLOAD_LENGTH])
{
	if (*payload)
	{
		(*payload)->data = ft_memalloc((*payload)->size + 1);
		ft_memcpy((*payload)->data, data, (*payload)->size);
		*payload = NULL;
	}
	*payload = ft_memalloc(sizeof(t_udp_payload));
}

static void	append_string(t_udp_payload *payload,
	uint8_t data[MAX_UDP_PAYLOAD_LENGTH], t_udpfile_token *token)
{
	if (payload->size + token->size > MAX_UDP_PAYLOAD_LENGTH)
		ft_exit(EXIT_FAILURE, "%s: too much data", __func__);
	ft_memcpy(data + payload->size, token->text, token->size);
	payload->size += token->size;
}

static void	parse_token(t_nmap_config *cfg, t_udpfile_token *token,
		t_udp_payload **payload,
		uint8_t data[MAX_UDP_PAYLOAD_LENGTH])
{
	int	i = 0;

	while (g_parse_table[token->last][i] != token->type
		&& g_parse_table[token->last][i] != E_UF_TOKEN_NONE)
		++i;
	token->type = g_parse_table[token->last][i];
	switch (token->type)
	{
		case E_UF_TOKEN_NONE:
			ft_exit(EXIT_FAILURE, "%s: unexpected token", __func__);	break;
		case E_UF_TOKEN_EOF:
		case E_UF_TOKEN_PROTO: init_payload(payload, data);				break;
		case E_UF_TOKEN_STRING: append_string(*payload, data, token);	break;
		case E_UF_TOKEN_PROTO_PORTS:
		case E_UF_TOKEN_SOURCE_PORT:
			parse_ports(cfg, token->text, set_udp_payloads, *payload);	break;
		case E_UF_TOKEN_SOURCE:											break;
	}
}

static void	parse_udpfile(t_nmap_config *cfg, int fd)
{
	int				ret;
	const char		*line = NULL;
	t_udpfile_token	token = { 0 };
	t_udp_payload	*payload = NULL;
	uint8_t			data[MAX_UDP_PAYLOAD_LENGTH] = { 0 };

	while ((ret = get_next_line(fd, (char **)&line)) >= 0)
	{
		while (token.type != E_UF_TOKEN_EOF
			&& (token.type = tokenize(&token, line)) != E_UF_TOKEN_NONE)
			parse_token(cfg, &token, &payload, data);
		if (!line)
			break;
		ft_memdel((void **)&line);
	}
	if (ret < 0)
		ft_exit(EXIT_FAILURE, "get_next_line: unknown error");
}

void		init_udp_payloads_list(t_nmap_config *cfg)
{
	if ((cfg->hosts_fd = open(UDP_PAYLOADS_FILE, O_RDONLY)) < 0)
		return;
	//TODO: do the things
	parse_udpfile(cfg, cfg->hosts_fd);
	close(cfg->hosts_fd);
	cfg->hosts_fd = -1;
}
