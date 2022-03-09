#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define	BUF_SIZE	512

int	main(int argc, char **argv)
{
	struct addrinfo	hints = { 0 }, *result, *rp;
	int				sfd, j, s;
	size_t			len;
	ssize_t			nread;
	char			buf[BUF_SIZE];

	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s host port msg...\n", argv[0]);
		return (EXIT_FAILURE);
	}

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if ((s = getaddrinfo(argv[1], argv[2], &hints, &result)))
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		return (EXIT_FAILURE);
	}

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		if ((sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0)
			continue;
		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;
		close(sfd);
	}

	if (rp == NULL)
	{
		freeaddrinfo(result);
		fprintf(stderr, "Could not connect\n");
		return (EXIT_FAILURE);
	}
	freeaddrinfo(result);

	for (j = 3; j < argc; ++j)
	{
		if ((len = strlen(argv[j]) + 1) >= BUF_SIZE)
			continue;
		if (write(sfd, argv[j], len) != len)
		{
			fprintf(stderr, "partial/failed write\n");
			return (EXIT_FAILURE);
		}

		if ((nread = read(sfd, buf, BUF_SIZE)) < 0)
		{
			perror("read");
			return (EXIT_FAILURE);
		}
		printf("Received %zd bytes: %s\n", nread, buf);
	}
	return (EXIT_SUCCESS);
}
