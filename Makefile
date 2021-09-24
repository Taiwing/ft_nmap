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

SRCC			=	update_job.c\
					init_new_job.c\
					options.c\
					next_scan.c\
					main.c\
					print.c\
					udp_services.c\
					worker.c\
					tcp_services.c\
					get_options.c\
					sctp_services.c\

ODIR			=	obj
OBJ				=	$(patsubst %.c,%.o,$(SRCC))

vpath			%.o	$(ODIR)
vpath			%.h	$(HDIR)
vpath			%.h	$(SUB1D)/$(HDIR)
vpath			%.c	$(SRCDIR)

############################## BUILD ###########################################

all: $(NAME)

$(NAME): $(SUB1D)/libft.a $(ODIR) $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(patsubst %.o,$(ODIR)/%.o,$(OBJ)) $(LIBS)

$(SUB1D)/libft.a:
	make -C $(SUB1D)

update_job.o: ft_nmap.h libft.h
init_new_job.o: ft_nmap.h libft.h
options.o: ft_nmap.h libft.h
next_scan.o: ft_nmap.h libft.h
main.o: ft_nmap.h libft.h
print.o: ft_nmap.h libft.h
udp_services.o: ft_nmap.h libft.h
worker.o: ft_nmap.h libft.h
tcp_services.o: ft_nmap.h libft.h
get_options.o: ft_nmap.h libft.h
sctp_services.o: ft_nmap.h libft.h
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
