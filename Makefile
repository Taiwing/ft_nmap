############################## COMPILE VAR #####################################

CC			=	gcc
#CFLAGS		=	-Wall -Wextra -DTHREAD_SAFE
CFLAGS		=	-Wall -Wextra -DTHREAD_SAFE -g -fsanitize=address,undefined
HDIR		=	includes
SRCDIR		=	src
SUB1D		=	libft
HFLAGS		=	-I $(HDIR) -I $(SUB1D)/$(HDIR)
LIBS		=	$(SUB1D)/libft.a -lpthread -lpcap
NAME		=	ft_nmap

############################## SOURCES #########################################

JOBSDIR			=	jobs
NETWORKDIR		=	network
SERVICESDIR		=	services

SRCC			=	options.c\
					main.c\
					print.c\
					verbose.c\
					get_options.c\

JOBSC			=	update_job.c\
					init_new_host_job.c\
					mutex.c\
					worker.c\
					next_job.c\

NETWORKC		=	next_host.c\
					print_headers.c\
					ip_headers.c\
					sockets.c\
					ip.c\
					probe.c\
					interfaces.c\
					alarm_tick.c\
					scan_result.c\
					listen.c\
					get_destinfo.c\
					layer4_headers.c\
					packet.c\

SERVICESC		=	udp_services.c\
					tcp_services.c\
					sctp_services.c\

ODIR			=	obj
OBJ				=	$(patsubst %.c,%.o,$(JOBSC))\
					$(patsubst %.c,%.o,$(NETWORKC))\
					$(patsubst %.c,%.o,$(SERVICESC))\
					$(patsubst %.c,%.o,$(SRCC))\

vpath			%.o	$(ODIR)
vpath			%.h	$(HDIR)
vpath			%.h	$(SUB1D)/$(HDIR)
vpath			%.c	$(SRCDIR)/$(JOBSDIR)
vpath			%.c	$(SRCDIR)/$(NETWORKDIR)
vpath			%.c	$(SRCDIR)/$(SERVICESDIR)
vpath			%.c	$(SRCDIR)

############################## BUILD ###########################################

all: $(NAME)

$(NAME): $(SUB1D)/libft.a $(ODIR) $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(patsubst %.o,$(ODIR)/%.o,$(OBJ)) $(LIBS)

$(SUB1D)/libft.a:
	make -C $(SUB1D)

options.o: ft_nmap.h network.h libft.h
main.o: ft_nmap.h network.h libft.h
update_job.o: ft_nmap.h network.h libft.h
init_new_host_job.o: ft_nmap.h network.h libft.h
mutex.o: ft_nmap.h network.h libft.h
worker.o: ft_nmap.h network.h libft.h
next_job.o: ft_nmap.h network.h libft.h
print.o: ft_nmap.h network.h libft.h
next_host.o: ft_nmap.h network.h libft.h
print_headers.o: network.h libft.h
ip_headers.o: network.h libft.h
sockets.o: ft_nmap.h network.h libft.h
ip.o: ft_nmap.h network.h libft.h
probe.o: ft_nmap.h network.h libft.h
interfaces.o: ft_nmap.h network.h libft.h
alarm_tick.o: ft_nmap.h network.h libft.h
scan_result.o: ft_nmap.h network.h libft.h
listen.o: ft_nmap.h network.h libft.h
get_destinfo.o: ft_nmap.h network.h libft.h
layer4_headers.o: network.h libft.h
packet.o: ft_nmap.h network.h libft.h
verbose.o: ft_nmap.h network.h libft.h
udp_services.o: ft_nmap.h network.h libft.h
tcp_services.o: ft_nmap.h network.h libft.h
sctp_services.o: ft_nmap.h network.h libft.h
get_options.o: ft_nmap.h network.h libft.h
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
