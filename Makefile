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

NETWORKDIR		=	network
JOBSDIR			=	jobs

SRCC			=	get_options.c\
					print.c\
					option_utils.c\
					main.c\
					debug.c\
					port_report.c\
					heatmap_report.c\
					verbose.c\
					utils.c\
					range_report.c\

NETWORKC		=	filter.c\
					listen.c\
					scan_result.c\
					window.c\
					next_host.c\
					parse_reply_packet.c\
					interfaces.c\
					adventure.c\
					probe.c\
					udp_payloads.c\
					rtt_update.c\
					ports.c\
					sockets.c\

JOBSC			=	timeout.c\
					stats.c\
					tasks.c\
					task_utils.c\
					update_job.c\
					worker.c\
					mutex.c\
					new_host.c\

ODIR			=	obj
OBJ				=	$(patsubst %.c,%.o,$(NETWORKC))\
					$(patsubst %.c,%.o,$(JOBSC))\
					$(patsubst %.c,%.o,$(SRCC))\

vpath			%.o	$(ODIR)
vpath			%.h	$(HDIR)
vpath			%.h	$(SUB1D)/$(HDIR)
vpath			%.c	$(SRCDIR)/$(NETWORKDIR)
vpath			%.c	$(SRCDIR)/$(JOBSDIR)
vpath			%.c	$(SRCDIR)

############################## BUILD ###########################################

all: $(NAME)

$(NAME): $(SUB1D)/libft.a $(ODIR) $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(patsubst %.o,$(ODIR)/%.o,$(OBJ)) $(LIBS)

$(SUB1D)/libft.a:
	make -C $(SUB1D)

get_options.o: ft_nmap.h ft_nmap_network.h libft.h
print.o: ft_nmap.h ft_nmap_network.h libft.h
option_utils.o: ft_nmap.h ft_nmap_network.h libft.h
main.o: ft_nmap.h ft_nmap_network.h libft.h
filter.o: ft_nmap.h ft_nmap_network.h libft.h
listen.o: ft_nmap.h ft_nmap_network.h libft.h
scan_result.o: ft_nmap.h ft_nmap_network.h libft.h
window.o: ft_nmap.h ft_nmap_network.h libft.h
next_host.o: ft_nmap.h ft_nmap_network.h libft.h
parse_reply_packet.o: ft_nmap.h ft_nmap_network.h libft.h
interfaces.o: ft_nmap.h ft_nmap_network.h libft.h
adventure.o: ft_nmap.h ft_nmap_network.h libft.h
probe.o: ft_nmap.h ft_nmap_network.h libft.h
udp_payloads.o: ft_nmap.h ft_nmap_network.h libft.h
rtt_update.o: ft_nmap.h ft_nmap_network.h libft.h
ports.o: ft_nmap.h ft_nmap_network.h libft.h
sockets.o: ft_nmap.h ft_nmap_network.h libft.h
debug.o: ft_nmap.h ft_nmap_network.h libft.h ft_printf_internal.h
port_report.o: ft_nmap.h ft_nmap_network.h libft.h
heatmap_report.o: ft_nmap.h ft_nmap_network.h libft.h
verbose.o: ft_nmap.h ft_nmap_network.h libft.h
timeout.o: ft_nmap.h ft_nmap_network.h libft.h
stats.o: ft_nmap.h ft_nmap_network.h libft.h
tasks.o: ft_nmap.h ft_nmap_network.h libft.h
task_utils.o: ft_nmap.h ft_nmap_network.h libft.h
update_job.o: ft_nmap.h ft_nmap_network.h libft.h
worker.o: ft_nmap.h ft_nmap_network.h libft.h
mutex.o: ft_nmap.h ft_nmap_network.h libft.h
new_host.o: ft_nmap.h ft_nmap_network.h libft.h
utils.o: ft_nmap.h ft_nmap_network.h libft.h
range_report.o: ft_nmap.h ft_nmap_network.h libft.h
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
