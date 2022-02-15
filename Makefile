############################## COMPILE VAR #####################################

CC			=	gcc
#CFLAGS		=	-Wall -Wextra -Werror -DTHREAD_SAFE
CFLAGS		=	-Wall -Wextra -Werror -DTHREAD_SAFE -g -fsanitize=address,undefined
HDIR		=	includes
SRCDIR		=	src
SUB1D		=	libft
HFLAGS		=	-I $(HDIR) -I $(SUB1D)/$(HDIR)
LIBS		=	$(SUB1D)/libft.a -lpthread
NAME		=	ft_nmap

############################## SOURCES #########################################

JOBSDIR			=	jobs
NETWORKDIR		=	network

SRCC			=	debug.c\
					port_report.c\
					utils.c\
					main.c\
					heatmap_report.c\
					print.c\
					range_report.c\
					option_utils.c\
					timeval_ops.c\
					verbose.c\
					get_options.c\

JOBSC			=	update_job.c\
					mutex.c\
					worker.c\
					timeout.c\
					stats.c\
					new_host.c\
					task_utils.c\
					tasks.c\

NETWORKC		=	filter.c\
					next_host.c\
					rtt_update.c\
					parse_reply_packet.c\
					udp_payloads.c\
					sockets.c\
					window.c\
					probe.c\
					interfaces.c\
					scan_result.c\
					listen.c\
					get_destinfo.c\
					ports.c\

ODIR			=	obj
OBJ				=	$(patsubst %.c,%.o,$(JOBSC))\
					$(patsubst %.c,%.o,$(NETWORKC))\
					$(patsubst %.c,%.o,$(SRCC))\

vpath			%.o	$(ODIR)
vpath			%.h	$(HDIR)
vpath			%.h	$(SUB1D)/$(HDIR)
vpath			%.c	$(SRCDIR)/$(JOBSDIR)
vpath			%.c	$(SRCDIR)/$(NETWORKDIR)
vpath			%.c	$(SRCDIR)

############################## BUILD ###########################################

all: $(NAME)

$(NAME): $(SUB1D)/libft.a $(ODIR) $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(patsubst %.o,$(ODIR)/%.o,$(OBJ)) $(LIBS)

$(SUB1D)/libft.a:
	make -C $(SUB1D)

debug.o: ft_nmap.h ft_nmap_network.h libft.h ft_printf_internal.h
port_report.o: ft_nmap.h ft_nmap_network.h libft.h
utils.o: ft_nmap.h ft_nmap_network.h libft.h
main.o: ft_nmap.h ft_nmap_network.h libft.h
heatmap_report.o: ft_nmap.h ft_nmap_network.h libft.h
update_job.o: ft_nmap.h ft_nmap_network.h libft.h
mutex.o: ft_nmap.h ft_nmap_network.h libft.h
worker.o: ft_nmap.h ft_nmap_network.h libft.h
timeout.o: ft_nmap.h ft_nmap_network.h libft.h
stats.o: ft_nmap.h ft_nmap_network.h libft.h
new_host.o: ft_nmap.h ft_nmap_network.h libft.h
task_utils.o: ft_nmap.h ft_nmap_network.h libft.h
tasks.o: ft_nmap.h ft_nmap_network.h libft.h
print.o: ft_nmap.h ft_nmap_network.h libft.h
range_report.o: ft_nmap.h ft_nmap_network.h libft.h
option_utils.o: ft_nmap.h ft_nmap_network.h libft.h
filter.o: ft_nmap.h ft_nmap_network.h libft.h
next_host.o: ft_nmap.h ft_nmap_network.h libft.h
rtt_update.o: ft_nmap.h ft_nmap_network.h libft.h
parse_reply_packet.o: ft_nmap.h ft_nmap_network.h libft.h
udp_payloads.o: ft_nmap.h ft_nmap_network.h libft.h
sockets.o: ft_nmap.h ft_nmap_network.h libft.h
window.o: ft_nmap.h ft_nmap_network.h libft.h
probe.o: ft_nmap.h ft_nmap_network.h libft.h
interfaces.o: ft_nmap.h ft_nmap_network.h libft.h
scan_result.o: ft_nmap.h ft_nmap_network.h libft.h
listen.o: ft_nmap.h ft_nmap_network.h libft.h
get_destinfo.o: ft_nmap.h ft_nmap_network.h libft.h
ports.o: ft_nmap.h ft_nmap_network.h libft.h
timeval_ops.o: ft_nmap.h ft_nmap_network.h libft.h
verbose.o: ft_nmap.h ft_nmap_network.h libft.h
get_options.o: ft_nmap.h ft_nmap_network.h libft.h
%.o: %.c
	@mkdir -p $(ODIR)
	$(CC) -c $(CFLAGS) $< $(HFLAGS) -o $(ODIR)/$@

$(ODIR):
	mkdir -p $@

############################## CLEANUP #########################################

clean:
	rm -rf $(ODIR)
	make -C $(SUB1D) fclean

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
