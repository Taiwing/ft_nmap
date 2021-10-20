############################## COMPILE VAR #####################################

CC			=	gcc
#CFLAGS		=	-Wall -Wextra
CFLAGS		=	-Wall -Wextra -g -fsanitize=address,undefined
HDIR		=	includes
SRCDIR		=	src
HFLAGS		=	-I $(HDIR)
LIBS		=	-lpcap
NAME		=	exec

############################## SOURCES #########################################

SRCC			=	init_network.c\
					grab_packet.c\
					ip_headers.c\
					print.c\
					pcap.c\
					socket.c\
					layer4_headers.c\

ODIR			=	obj
OBJ				=	$(patsubst %.c,%.o,$(SRCC))

vpath			%.o	$(ODIR)
vpath			%.h	$(HDIR)
vpath			%.c	$(SRCDIR)

############################## BUILD ###########################################

all: $(NAME)

$(NAME): $(ODIR) $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(patsubst %.o,$(ODIR)/%.o,$(OBJ)) $(LIBS)

init_network.o: test_pcap.h
grab_packet.o: test_pcap.h
ip_headers.o: test_pcap.h
print.o: test_pcap.h
pcap.o: test_pcap.h
socket.o: test_pcap.h
layer4_headers.o: test_pcap.h
%.o: %.c
	@mkdir -p $(ODIR)
	$(CC) -c $(CFLAGS) $< $(HFLAGS) -o $(ODIR)/$@

$(ODIR):
	mkdir -p $@

############################## CLEANUP #########################################

clean:
	rm -rf $(ODIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
