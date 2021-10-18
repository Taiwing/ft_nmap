#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	struct in_addr	ipv4 = { 0 };
	struct in6_addr	ipv6 = { 0 };
	char			bufv4[INET_ADDRSTRLEN] = { 0 };
	char			bufv6[INET6_ADDRSTRLEN] = { 0 };

	if (argc != 2)
	{
		fprintf(stderr, "%s <dotted-address>\n", argv[0]);
		return (EXIT_FAILURE);
	}

	int ret4 = inet_pton(AF_INET, argv[1], &ipv4);
	int ret6 = inet_pton(AF_INET6, argv[1], &ipv6);

	printf("ipv4 (ret = %d): %s\n", ret4,
			inet_ntop(AF_INET, (void *)&ipv4, bufv4, INET_ADDRSTRLEN));
	printf("ipv6 (ret = %d): %s\n", ret6,
			inet_ntop(AF_INET6, (void *)&ipv6, bufv6, INET6_ADDRSTRLEN));
	return (EXIT_SUCCESS);
}
