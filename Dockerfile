FROM debian:buster-slim

MAINTAINER TH3XACE <BLALAA> 
LABEL description="This docker was created for testing the tool SUDO_KILLER available on github. The tool was developped to identify and exploit misconfigurations within sudo rules as well as vulnerable version of sudo itself. \
Several scenarios are included in the docker so as to illustrate some of the vulnerable configurations and a vulnerable version if sudo."

# install debian stuff
RUN apt-get update && \
    apt-get install -y git && \
    apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    wget vim build-essential curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# configure vuln application
RUN wget https://www.sudo.ws/dist/sudo-1.8.4.tar.gz -O /tmp/sudo.tar.gz && \
    tar xfz /tmp/sudo.tar.gz -C /tmp/ && \
    cd /tmp/sudo-1.8.4 && \
    ./configure && \
    make && make install
RUN rm -rf /tmp/sudo*

# create default user
RUN useradd -d /home/user \
    -s /bin/bash \
    -ms /bin/bash user
    
# create victim user
RUN useradd -d /home/victim \
    -s /bin/bash \
    -ms /bin/bash victim

# add sudoers entry
RUN echo 'Defaults pwfeedback' >> /etc/sudoers && \
    echo 'Defaults env_reset' >> /etc/sudoers && \
    echo 'Defaults env_keep += LD_PRELOAD' >> /etc/sudoers && \
    echo 'Defaults env_keep += LD_LIBRARY_PATH' >> /etc/sudoers && \
    echo 'user ALL=NOPASSWD: sudoedit /home/*/*/esc.txt' >> /etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: /home/user/directory/user*/setup.sh' >> /etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: /bin/chown -hR * /home/user/directory/* ' >> /etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: /bin/chown -hR * *.txt' >> /etc/sudoers && \  
    echo 'user ALL=(root) NOPASSWD: /bin/chown -HR * *.txt' >> /etc/sudoers && \   
    echo 'user ALL=NOPASSWD: /home/user/support/start.sh, /home/user/support/stop.sh, /home/user/support/restart.sh, /usr/sbin/lsof' >> /etc/sudoers && \  
    echo 'user ALL=(root) NOPASSWD: /direc/*/user' >> /etc/sudoers && \ 
    echo 'user ALL=(ALL, !root) NOPASSWD: /bin/bash' >> /etc/sudoers && \
    echo 'user ALL=(ALL, !root) NOPASSWD: /usr/bin/id' >> /etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: /usr/local/bin/sudoedit /etc/printcap' >> /etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: /bin/cp *' >> /etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: /bin/ping' >> /etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: /usr/bin/ping' >> /etc/sudoers && \    
    echo 'user ALL=(victim) NOPASSWD: /usr/bin/find *' >> /etc/sudoers && \
    echo 'user ALL=(victim) NOPASSWD: /usr/bin/cpan *' >> /etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: sudoedit /' >> /etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: /usr/sbin/start-stop-daemon *' >> /etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: /usr/bin/csvtool * --help' >> //etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: /usr/sbin/apache2' >> //etc/sudoers && \
    echo 'user ALL=(root) NOPASSWD: /bin/kill, /usr/bin/cat, /usr/bin/tail' >> /etc/sudoers

# create vulnerable scripts
RUN mkdir -p /home/user/support && \  
    cd /home/user/support && \
    touch restart.sh && \
    touch start.sh && \
    chmod u+rwx restart.sh && \
    chmod g+xr restart.sh && \
    chmod o+x restart.sh && \
    chown user:user start.sh && \  
    chmod u+rwx start.sh && \
    chmod g+xr start.sh && \
    chmod o+x start.sh && \
    cd ../ && \
    chown user:user support/

#COPY exploit.sh /home/user/
RUN cd /home/user/ && \
    git clone https://github.com/TH3xACE/SUDO_KILLER.git && \
    chown -R user:user SUDO_KILLER && \
    cd SUDO_KILLER && \
    chmod +x *.sh

# run interactive shell
# with user privileges
CMD ["su", "-", "user"]
