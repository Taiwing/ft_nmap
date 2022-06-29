# ft\_nmap

This is a re-implementation of the nmap utility in C. This program acts as a
network scanner and a port mapper. It can be used to diagnostic networking
issues or to gather infromations on a given network in an offensive security
setting.

## Setup

```shell
# clone it with the libft submodule
git clone --recurse-submodules https://github.com/Taiwing/ft_nmap
# build it
cd ft_nmap/ && make
# run it
sudo ./ft_nmap example.com
```

As shown above this program needs sudo rights. This is because ft\_nmap uses raw
sockets for crafting custom ip packets and read responses. If you do not have
root access on your machine but docker is available, then execute the following
commands to run ft\_nmap:

```shell
# build docker image and run it
./setup-docker.bash
# run ft_nmap inside the container
./ft_nmap example.com
```
