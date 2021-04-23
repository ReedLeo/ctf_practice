FROM ubuntu:16.04

RUN  sed -i s@/archive.ubuntu.com/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list
RUN  sed -i s@/security.ubuntu.com/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list
RUN  apt-get clean
RUN  apt-get update

ENV DEBIAN_FRONTEND noninteractive
ENV TZ Asia/Shanghai

RUN dpkg --add-architecture i386 && \
    apt-get -y update && \
    apt install -y \
    libc6:i386 \
    libc6-dbg:i386 \
    build-essential \
    libc6-dbg \
    lib32stdc++6 \
    g++-multilib \
    cmake \
    gcc \
    ipython3 \
    vim \
    net-tools \
    curl \
    libffi-dev \
    libssl-dev \
    python3-dev \
    tmux \
    glibc-source \
    cmake \
    strace \
    ltrace \
	locales-all \
    nasm \
    wget \
    radare2 \
    gdb \
    gdb-multiarch \
    netcat \
    socat \
    git \
    patchelf \
    gawk \
    file \
    zsh \
    qemu \
    gcc-multilib \
    binwalk \
    libseccomp-dev \
    libseccomp2 \
    seccomp	\
	tzdata \
	bison \
	autojump \
	software-properties-common

RUN ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN apt-add-repository ppa:brightbox/ruby-ng && \
	apt autoremove ruby && \
    apt update &&\
	apt install -y ruby2.4 &&\
	apt install -y ruby2.4-dev

RUN ulimit -c 0
RUN gem install one_gadget 
RUN gem install seccomp-tools 

RUN wget https://bootstrap.pypa.io/pip/3.5/get-pip.py && \
    python3 get-pip.py && \
    rm get-pip.py


# Oh-my-zsh
RUN chsh -s /bin/zsh
RUN sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

# install zsh-autosuggestions
RUN git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions

# config dotfiles
RUN git clone https://gitee.com/RenGongZhiZhang/dotfiles.git && \
	cd dotfiles && ./setup_symlinks.sh && \
	cd ..

RUN python3 -m pip install -U pip &&\
    python3 -m pip install --no-cache-dir --default-timeout=100 \
    -i https://pypi.tuna.tsinghua.edu.cn/simple \
    ropper \
    unicorn \
    capstone \
    zio \
    smmap2 \
    z3-solver \
    ropgadget \
    pwntools

RUN git clone https://github.com/niklasb/libc-database.git libc-database && \
    cd libc-database && ./get || echo "/libc-database/" > ~/.libcdb_path && cd ..

RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && ./setup.sh && cd ..

WORKDIR /ctf/work/

#COPY --from=skysider/glibc_builder64:2.19 /glibc/2.19/64 /glibc/2.19/64
#COPY --from=skysider/glibc_builder32:2.19 /glibc/2.19/32 /glibc/2.19/32

#COPY --from=skysider/glibc_builder64:2.23 /glibc/2.23/64 /glibc/2.23/64
#COPY --from=skysider/glibc_builder32:2.23 /glibc/2.23/32 /glibc/2.23/32

COPY linux_server linux_server64 /ctf/
RUN chmod a+x /ctf/linux_server /ctf/linux_server64

RUN	echo export TERM=screen-256color  >> ~/.zshrc && \
	echo export LC_ALL=en_US.UTF-8 >> ~/.zshrc && \
	echo export LANG=en_US.UTF-8 >> ~/.zshrc

ENTRYPOINT ["/bin/zsh"]
