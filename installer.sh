#!/bin/bash
# created by man20820

# pergi ke root
cd

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
MYPORT="s/85/99/g";

#FIGlet In Linux
sudo apt-get install figlet
yum install figlet

# mematikan ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# update repo
apt-get update;

# install wget and curl
apt-get update;apt-get -y install wget curl;

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# set repo
wget -O /etc/apt/sources.list "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/main/API/sources.list.debian8"
wget "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/main/API/dotdeb.gpg"
wget "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/main/API/jcameron-key.asc"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# install webserver
cd
apt-get -y install nginx php5 php5-fpm php5-cli php5-mysql php5-mcrypt
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/main/API/nginx.conf"
mkdir -p /home/vps/public_html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/vps.conf"
sed -i 's/cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /etc/php5/fpm/php.ini
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
sed -i $MYPORT /etc/nginx/conf.d/vps.conf;
useradd -m vps && mkdir -p /home/vps/public_html
rm /home/vps/public_html/index.html && echo "<?php phpinfo() ?>" > /home/vps/public_html/info.php
chown -R www-data:www-data /home/vps/public_html && chmod -R g+rw /home/vps/public_html
service php5-fpm restart && service nginx restart

# install essential package
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install build-essential

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i venet0
service vnstat restart

# install neofetch
echo "deb http://dl.bintray.com/dawidd6/neofetch jessie main" | sudo tee -a /etc/apt/sources.list
curl -L "https://bintray.com/user/downloadSubjectPublicKey?username=bintray" -o Release-neofetch.key && sudo apt-key add Release-neofetch.key && rm Release-neofetch.key
apt-get update
apt-get install neofetch

# install screenfetch
cd
wget https://github.com/KittyKatt/screenFetch/archive/master.zip
apt-get install -y unzip
unzip master.zip
mv screenFetch-master/screenfetch-dev /usr/bin
cd /usr/bin
mv screenfetch-dev screenfetch
chmod +x /usr/bin/screenfetch
chmod 755 screenfetch
cd
echo "clear" >> .bash_profile
echo "screenfetch" >> .bash_profile

# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/nginx.conf"
mkdir -p /home/webserver/public_html
echo "<pre>Setup by man20820 | https://man20820.com | https:// tkjpedia.com </pre>" > /home/webserver/public_html/index.html
echo "<?php phpinfo(); ?>" > /home/webserver/public_html/info.php
wget -O /etc/nginx/conf.d/webserver.conf "https://raw.githubusercontent.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/webserver.conf"
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
service php5-fpm restart
service nginx restart

# install openvpn
wget -O /etc/openvpn/openvpn "https://rawgit.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/openvpn/ca.crt"
wget -O /etc/openvpn/openvpn "https://rawgit.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/openvpn/dh1024.pem"
wget -O /etc/openvpn/openvpn "https://rawgit.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/openvpn/openvpn.conf"
wget -O /etc/openvpn/openvpn "https://rawgit.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/openvpn/server.conf"
wget -O /etc/openvpn/openvpn "https://rawgit.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/openvpn/server.crt"
wget -O /etc/openvpn/openvpn "https://rawgit.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/openvpn/server.key"
wget -O /etc/openvpn/openvpn "https://rawgit.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/openvpn/update-resolf-conf"
cd /etc/openvpn/
service openvpn restart
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
wget -O /etc/iptables.up.rules "https://raw.githubusercontent.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/iptables.up.rules"
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
MYIP=`curl -s ifconfig.me`;
MYIP2="s/xxxxxxxxx/$MYIP/g";
sed -i $MYIP2 /etc/iptables.up.rules;
iptables-restore < /etc/iptables.up.rules
service openvpn restart

#konfigurasi openvpn
cd /etc/openvpn/
wget -O /etc/openvpn/client.ovpn "https://raw.githubusercontent.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/openvpn/client.ovpn"
sed -i $MYIP2 /etc/openvpn/client.ovpn;
PASS=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 15 | head -n 1`;
useradd -M -s /bin/false man20820
echo "man20820$PASS" | chpasswd
echo "man20820" > pass.txt
echo "$PASS" >> pass.txt
tar cf client.tar client.ovpn pass.txt
cp client.tar /home/vps/public_html/

# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/badvpn-udpgw"
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# install mrtg
wget -O /etc/snmp/snmpd.conf "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/snmpd.conf"
wget -O /root/mrtg-mem.sh "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/mrtg-mem.sh"
chmod +x /root/mrtg-mem.sh
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# setting port ssh
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  22/g' /etc/ssh/sshd_config
service ssh restart

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=20820/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
service ssh restart
service dropbear restart

# install stunnel 
apt-get install stunnel4 -y
wget -O /etc/stunnel/stunnel.conf "https://raw.githubusercontent.com/man20820/script-autoinstaller-ssh-ssl-stunnel-vps-debian-7/master/stunnel.conf"
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart

# install vnstat gui
cd /home/vps/public_html/
wget http://www.sqweek.com/sqweek/files/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i 's/eth0/venet0/g' config.php
sed -i "s/\$iface_list = array('venet0', 'sixxs');/\$iface_list = array('venet0');/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
cd

# install fail2ban
apt-get -y install fail2ban;service fail2ban restart


# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

#install squid3
apt-get -y install squid3
wget -O /etc/squid3/squid.conf "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/squid3.conf"
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

# install webmin
cd
wget -O webmin-current.deb "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/webmin-current.deb"
dpkg -i --force-all webmin-current.deb;
apt-get -y -f install;
rm /root/webmin-current.deb
service webmin restart

# download script
cd /usr/bin
wget -O menu "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/menu.sh"
wget -O usernew "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/usernew.sh"
wget -O trial "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/trial.sh"
wget -O hapus "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/hapus.sh"
wget -O cek "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/user-login.sh"
wget -O member "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/user-list.sh"
wget -O resvis "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/resvis.sh"
wget -O speedtest "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/speedtest_cli.py"
wget -O info "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/info.sh"
wget -O about "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/about.sh"

echo "0 0 * * * root /sbin/reboot" > /etc/cron.d/reboot

chmod +x menu
chmod +x usernew
chmod +x trial
chmod +x hapus
chmod +x cek
chmod +x member
chmod +x resvis
chmod +x speedtest
chmod +x info
chmod +x about

#Blockir Torrent
iptables -A OUTPUT -p tcp --dport 6881:6889 -j DROP
iptables -A OUTPUT -p udp --dport 1024:65534 -j DROP
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

# finishing
cd
chown -R www-data:www-data /home/vps/public_html
service nginx start
service openvpn restart
service cron restart
service ssh restart
service dropbear restart
service squid3 restart
service webmin restart
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# install myweb
cd /home/vps/public_html/
wget -O /home/vps/public_html/myweb.tar "https://raw.githubusercontent.com/Zahyy20/SSH-OpenVPN/master/API/myweb.tar"
cd /home/vps/public_html/
tar xf myweb.tar

# Setting web
echo -e "\033[01;31mIP User And Pass 'ROOT' Only \033[0m"
read -p "IP : " MyIPD
read -p "Username : " Login
read -p "Password : " Passwd
MYIPS="s/xxxxxxxxx/$MyIPD/g";
US1="s/thaivpnuser/$Login/g";
PS2="s/thaivpnpass/$Passwd/g";
sed -i $MYIPS /home/vps/public_html/index.php;
sed -i $US1 /home/vps/public_html/index.php;
sed -i $PS2 /home/vps/public_html/index.php;

#RM file
rm -f myweb.tar
cd
rm -f install.sh

# info
clear
figlet "ZAHYYSTORE"
echo "Script WebSSH Auto Install"
echo "OpenSSH  : 22, 143"
echo "Dropbear : 80, 443"
echo "Squid3   : 8080, 3128 (limit to IP SSH)"
echo "OpenVPN  : TCP 1194 (client config : http://$MYIP:99/client.ovpn)"
echo "Squid     :  http://$MYIP:8080"
echo "Nginx      :  http://$MYIP:99"
echo "Web    :  http://$MYIP:99"
echo "Webmin   : http://$MYIP:10000/"
echo "IPv6     : [off]"
echo "Modified by ZAHYYSTORE"
echo "VPS AUTO REBOOT TIAP JAM 12 MALAM"
echo "==========================================="
figlet "ZAHYYSTORE"
cd
rm -f /root/debian8.sh
