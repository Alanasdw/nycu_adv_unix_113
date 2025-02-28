FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386
RUN dpkg --add-architecture amd64
RUN dpkg --add-architecture arm64
RUN apt-get update && apt-get install -y tini locales \
	procps iproute2 iputils-ping net-tools netcat-openbsd openssh-server \
	sudo htop vim gawk rsync tmux diffutils file less tcpdump \
	wget curl git zsh man manpages manpages-dev bison flex pkg-config gdb \
	autoconf automake build-essential yasm nasm libcapstone-dev libc6-dbg dpkg-dev \
	python3 python3-pip python3-virtualenv python3-pwntools python3-dev \
	crossbuild-essential-i386 crossbuild-essential-amd64 crossbuild-essential-arm64 \
	libssl-dev:amd64 libpcre2-dev:amd64 zlib1g-dev:amd64 \
	libssl-dev:arm64 libpcre2-dev:arm64 zlib1g-dev:arm64 \
	libssl-dev:i386 libpcre2-dev:i386 zlib1g-dev:i386 \
	qemu-user-static
# /var/run/sshd: required on debian/ubuntu
RUN mkdir -p /var/run/sshd

# locale
RUN echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
RUN /usr/sbin/locale-gen
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8
ENV EDITOR=vim

# allow sudo without password
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

# run the service
EXPOSE 22
ENTRYPOINT [ "/usr/bin/tini", "--" ]
CMD [ "/entrypoint.sh" ]
