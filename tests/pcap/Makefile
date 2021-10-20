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

SRCC			=	pcap.c\

ODIR			=	obj
OBJ				=	$(patsubst %.c,%.o,$(SRCC))

vpath			%.o	$(ODIR)
vpath			%.h	$(HDIR)
vpath			%.c	$(SRCDIR)

############################## BUILD ###########################################

all: $(NAME)

$(NAME): $(ODIR) $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(patsubst %.o,$(ODIR)/%.o,$(OBJ)) $(LIBS)

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
