#!/bin/bash

rm -f $0

apt update
apt install curl -y
apt install wget -y
apt install jq -y

NC='\033[0m'
rbg='\033[41;37m'
r='\033[1;91m'
g='\033[1;92m'
y='\033[1;93m'
u='\033[0;35m'
c='\033[0;96m'
w='\033[1;97m'

if [ "${EUID}" -ne 0 ]; then
echo "${r}You need to run this script as root${NC}"
sleep 2
exit 0
fi

if [[ ! -f /root/.isp ]]; then
curl -sS ipinfo.io/org?token=7a814b6263b02c > /root/.isp
fi
if [[ ! -f /root/.city ]]; then
curl -sS ipinfo.io/city?token=7a814b6263b02c > /root/.city
fi
if [[ ! -f /root/.myip ]]; then
curl -sS ipv4.icanhazip.com > /root/.myip
fi

export IP=$(cat /root/.myip);
export ISP=$(cat /root/.isp);
export CITY=$(cat /root/.city);
source /etc/os-release

function lane_atas() {
echo -e "${c}┌──────────────────────────────────────────┐${NC}"
}
function lane_bawah() {
echo -e "${c}└──────────────────────────────────────────┘${NC}"
}

apt update
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")
url_izin="https://raw.githubusercontent.com/Andyyuda/izin/main/ip"
client=$(curl -sS $url_izin | grep $IP | awk '{print $2}')
exp=$(curl -sS $url_izin | grep $IP | awk '{print $3}')
today=`date -d "0 days" +"%Y-%m-%d"`
time=$(printf '%(%H:%M:%S)T')
date=$(date +'%d-%m-%Y')
d1=$(date -d "$exp" +%s)
d2=$(date -d "$today" +%s)
certifacate=$(((d1 - d2) / 86400))
checking_sc() {
  useexp=$(curl -s $url_izin | grep $IP | awk '{print $3}')
  if [[ $date_list < $useexp ]]; then
    echo -ne
  else
    clear
    echo -e "\033[96m────────────────────────────────────────────\033[0m"
    echo -e "\033[41;37m             Expired Autoscript             \033[0m"
    echo -e "\033[96m────────────────────────────────────────────\033[0m"
    echo -e ""
    echo -e " \033[31mIP Address access is not allowed\033[0m"
    echo -e ""
    echo -e "  Price For 1 Month"
    echo -e ""
    echo -e "   1 IP Address : 8.000 Rp"
    echo -e "   5 IP Address : 30.000 Rp"
    echo -e "   10 IP Address : 50.000 Rp"
    echo -e ""
    echo -e ""
    echo -e " \033[34mWhatsapp  : +6285935195701 \033[0m"
    echo -e " \033[34mTelegram  : @andyyuda_store \033[0m"
    echo -e " \033[34mChannel   : @andyyuda_vpn \033[0m"
    echo -e " \033[34mGroup     : @klmpk_tunnel \033[0m"
    echo -e "\033[96m────────────────────────────────────────────\033[0m"
    exit 0
  fi
}
checking_sc

if [[ "$( uname -m | awk '{print $1}' )" == "x86_64" ]]; then
echo -ne
else
echo -e "${r} Your Architecture Is Not Supported ( ${y}$( uname -m )${NC} )"
exit 1
fi

if [[ ${ID} == "ubuntu" || ${ID} == "debian" ]]; then
echo -ne
else
echo -e " ${r}This Script only Support for OS"
echo -e ""
echo -e " - ${y}Ubuntu 20.04${NC}"
echo -e " - ${y}Ubuntu 21.04${NC}"
echo -e " - ${y}Ubuntu 22.04${NC}"
echo ""
echo -e " - ${y}Debian 10${NC}"
echo -e " - ${y}Debian 11${NC}"
echo -e " - ${y}Debian 12${NC}"
Credit_Sc
exit 0
fi

if [[ ${VERSION_ID} == "10" || ${VERSION_ID} == "11" || ${VERSION_ID} == "20.04" || ${VERSION_ID} == "21.04" || ${VERSION_ID} == "22.04" || ${VERSION_ID} == "12" ]]; then
echo -ne
else
echo -e " ${r}This Script only Support for OS"
echo -e ""
echo -e " - ${y}Ubuntu 20.04${NC}"
echo -e " - ${y}Ubuntu 21.04${NC}"
echo -e " - ${y}Ubuntu 22.04${NC}"
echo ""
echo -e " - ${y}Debian 10${NC}"
echo -e " - ${y}Debian 11${NC}"
echo -e " - ${y}Debian 12${NC}"
Credit_Sc
exit 0
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
echo "OpenVZ is not supported"
exit 1
fi

function pointing() (
apt update
apt install jq curl -y
dns=${sub}.${DOMAIN}
CF_KEY=301290ce75b57c389434bbf3547a8cb9f7454
CF_ID=padliapandi459@gmail.com
set -euo pipefail
echo ""
echo "Proses Pointing Domain ${dns}..."
sleep 1
ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

RECORD=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?name=${dns}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

if [[ "${#RECORD}" -le 10 ]]; then
     RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${dns}'","content":"'${IP}'","ttl":120,"proxied":false}' | jq -r .result.id)
fi

RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records/${RECORD}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${dns}'","content":"'${IP}'","ttl":120,"proxied":false}')

echo "$dns" > /etc/xray/domain
echo ""
sleep 1
echo -e " Subdomain kamu adalah ${dns}"
cd
sleep 2
)

function pasang_domain() {
mkdir -p /etc/xray
mkdir -p /var/lib/ >/dev/null 2>&1
echo "IP=" >> /var/lib/ipvps.conf
touch /etc/.{ssh,noobzvpns,vmess,vless,trojan,shadowsocks}.db
mkdir -p /etc/{xray,bot,vmess,vless,trojan,shadowsocks,ssh,noobzvpns,limit,usr}
touch /etc/noobzvpns/users.json
mkdir -p /etc/xray/limit
mkdir -p /etc/xray/limit/{ssh,vmess,vless,trojan,shadowsocks}

inpusub() {
read -p " Input Subdomain Example : andyyuda1038 ( x for exit ) : " sub
if [[ -z $sub ]]; then
inpusub
fi
if [[ $sub == "x" ]]; then
pasang_domain
fi
}

clear
lane_atas
echo -e "${c}│ ${w}             ADD DOMAIN MENU             ${c}│${NC}"
lane_bawah
lane_atas
echo -e "${c}│${NC} 1. ${w}Gunakan Domain Sendiri/Domainmu ${NC}"
echo -e "${c}│${NC} 2. ${w}Gunakan Domain Dari SC (vip-server.me) ${NC}"
echo -e "${c}│${NC} 3. ${w}Gunakan Domain Dari SC (xdtunnel.me) ${NC}"
#echo -e "${c}│${NC} 4. ${w}Gunakan Domain Dari SC (vpn-prem.biz.id) ${NC}"
lane_bawah
read -p " Chose Options [ 1 - 3 ] : " host
echo ""
if [[ $host == "1" ]]; then
echo -e ""
echo -e ""
read -p "  Input Your Domain : " host1
if [[ -z $host1 ]]; then
echo -e "Masukan Domain nya !!!"
sleep 2
pasang_domain
fi
echo $host1 > /etc/xray/domain
sleep 2
elif [[ $host == "2" ]]; then
echo -e ""
inpusub
DOMAIN=vip-server.me
pointing
sleep 2
elif [[ $host == "3" ]]; then
echo -e ""
inpusub
DOMAIN=xdtunnel.me
pointing
sleep 2
elif [[ $host == "4" ]]; then
echo -e ""
inpusub
DOMAIN=vpn-prem.biz.id
pointing
sleep 2
else
echo -e " Pilih Opsi hanya 1 - 3 !!! "
sleep 2
pasang_domain
fi
}

function Dependencies() {
cd
wget https://raw.githubusercontent.com/kipasu/f/main/tools.sh &> /dev/null
chmod +x tools.sh 
bash tools.sh

wget -q -O /etc/port.txt "https://raw.githubusercontent.com/kipasu/f/main/port.txt"

clear
start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
apt install git curl -y >/dev/null 2>&1
apt install python -y >/dev/null 2>&1
}

function Installasi(){
animation_loading() {
    CMD[0]="$1"
    CMD[1]="$2"
    
    (
        # Hapus file fim jika ada
        [[ -e $HOME/fim ]] && rm -f $HOME/fim
        
        # Jalankan perintah di background dan sembunyikan output
        ${CMD[0]} -y >/dev/null 2>&1
        ${CMD[1]} -y >/dev/null 2>&1
        
        # Buat file fim untuk menandakan selesai
        touch $HOME/fim
    ) >/dev/null 2>&1 &

    tput civis # Sembunyikan kursor
    echo -ne "  \033[0;33mProcessed Install \033[1;37m- \033[0;33m["
    
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "\033[0;32m#"
            sleep 0.1
        done
        
        # Jika file fim ada, hapus dan keluar dari loop
        if [[ -e $HOME/fim ]]; then
            rm -f $HOME/fim
            break
        fi
        
        echo -e "\033[0;33m]"
        sleep 1
        tput cuu1 # Kembali ke baris sebelumnya
        tput dl1   # Hapus baris sebelumnya
        echo -ne "  \033[0;33mProcessed Install \033[1;37m- \033[0;33m["
    done
    
    echo -e "\033[0;33m]\033[1;37m -\033[1;32m Succes !\033[1;37m"
    tput cnorm # Tampilkan kursor kembali
}


inssh() {
wget https://raw.githubusercontent.com/kipasu/f/main/ssh/ssh-vpn.sh && chmod +x ssh-vpn.sh && ./ssh-vpn.sh

# installer gotop
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb

clear
} 

insxray() {
wget https://raw.githubusercontent.com/kipasu/f/main/xray/ins-xray.sh && chmod +x ins-xray.sh && ./ins-xray.sh
clear
}

insws() {
wget https://raw.githubusercontent.com/kipasu/f/main/ws/install-ws.sh && chmod +x install-ws.sh && ./install-ws.sh
clear
}

insbkp() {
apt install rclone
printf "q\n" | rclone config
wget -O /root/.config/rclone/rclone.conf "https://raw.githubusercontent.com/kipasu/f/main/ssh/rclone.conf"
git clone  https://github.com/zhets/wondershaper.git
cd wondershaper
make install
cd
rm -rf wondershaper
    
rm -f /root/set-br.sh
rm -f /root/limit.sh
}

insohp() {
wget https://raw.githubusercontent.com/kipasu/f/main/ws/ohp.sh && chmod +x ohp.sh && ./ohp.sh
clear
}

menu() {
wget https://raw.githubusercontent.com/andyyudaklmpk/andy/main/menu/update.sh && chmod +x update.sh && ./update.sh
clear
}

insdns() {
wget https://raw.githubusercontent.com/kipasu/f/main/slowdns/installsl.sh && chmod +x installsl.sh && bash installsl.sh
clear
}

insudp() {

cd
mkdir -p /etc/udp

wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1_VyhL5BILtoZZTW4rhnUiYzc4zHOsXQ8' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1_VyhL5BILtoZZTW4rhnUiYzc4zHOsXQ8" -O /etc/udp/udp-custom && rm -rf /tmp/cookies.txt
chmod +x /etc/udp/udp-custom

wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1_XNXsufQXzcTUVVKQoBeX5Ig0J7GngGM' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1_XNXsufQXzcTUVVKQoBeX5Ig0J7GngGM" -O /etc/udp/config.json && rm -rf /tmp/cookies.txt
chmod 644 /etc/udp/config.json

if [ -z "$1" ]; then
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/etc/udp/udp-custom server
WorkingDirectory=/etc/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
else
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/etc/udp/udp-custom server -exclude $1
WorkingDirectory=/etc/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
fi

systemctl restart udp-custom
systemctl enable udp-custom

clear
}
if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
echo -e "${g}Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${NC}"
setup_ubuntu
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
echo -e "${g}Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${NC}"
setup_debian
else
echo -e " Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${FONT} )"
fi
}


function setup_debian(){
lane_atas
echo -e "${c}│      ${g}PROCESS INSTALLED SSH & OPENVPN${NC}     ${c}│${NC}"
lane_bawah
animation_loading 'inssh'

lane_atas
echo -e "${c}│           ${g}PROCESS INSTALLED XRAY${NC}         ${c}│${NC}"
lane_bawah
animation_loading 'insxray'

lane_atas
echo -e "${c}│       ${g}PROCESS INSTALLED WEBSOCKET SSH${NC}    ${c}│${NC}"
lane_bawah
animation_loading 'insws'

lane_atas
echo -e "${c}│       ${g}PROCESS INSTALLED BACKUP MENU${NC}${c}      │${NC}"
lane_bawah
animation_loading 'insbkp'

lane_atas
echo -e "${c}│           ${g}PROCESS INSTALLED OHP${NC}${c}          │${NC}"
lane_bawah
animation_loading 'insohp'

lane_atas
echo -e "${c}│           ${g}DOWNLOAD EXTRA MENU${NC}${c}            │${NC}"
lane_bawah
animation_loading 'menu'

lane_atas
echo -e "${c}│           ${g}DOWNLOAD SYSTEM${NC}${c}                │${NC}"
lane_bawah
animation_loading 'insdns'

lane_atas
echo -e "${c}│           ${g}DOWNLOAD UDP CUSTOM${NC}${c}            │${NC}"
lane_bawah
animation_loading 'insudp'
}

function setup_ubuntu(){
lane_atas
echo -e "${c}│      ${g}PROCESS INSTALLED SSH & OPENVPN${NC}     ${c}│${NC}"
lane_bawah
inssh

lane_atas
echo -e "${c}│           ${g}PROCESS INSTALLED XRAY${NC}         ${c}│${NC}"
lane_bawah
insxray

lane_atas
echo -e "${c}│       ${g}PROCESS INSTALLED WEBSOCKET SSH${NC}    ${c}│${NC}"
lane_bawah
insws

lane_atas
echo -e "${c}│       ${g}PROCESS INSTALLED BACKUP MENU${NC}${c}      │${NC}"
lane_bawah
insbkp

lane_atas
echo -e "${c}│           ${g}PROCESS INSTALLED OHP${NC}${c}          │${NC}"
lane_bawah
insohp

lane_atas
echo -e "${c}│           ${g}DOWNLOAD EXTRA MENU${NC}${c}            │${NC}"
lane_bawah
menu

lane_atas
echo -e "${c}│           ${g}DOWNLOAD SYSTEM${NC}${c}                │${NC}"
lane_bawah
insdns

lane_atas
echo -e "${c}│           ${g}DOWNLOAD UDP CUSTOM${NC}${c}            │${NC}"
lane_bawah
insudp
}

# Tentukan nilai baru yang diinginkan untuk fs.file-max
NEW_FILE_MAX=65535  # Ubah sesuai kebutuhan Anda

# Nilai tambahan untuk konfigurasi netfilter
NF_CONNTRACK_MAX="net.netfilter.nf_conntrack_max=262144"
NF_CONNTRACK_TIMEOUT="net.netfilter.nf_conntrack_tcp_timeout_time_wait=30"

# File yang akan diedit
SYSCTL_CONF="/etc/sysctl.conf"

# Ambil nilai fs.file-max saat ini
CURRENT_FILE_MAX=$(grep "^fs.file-max" "$SYSCTL_CONF" | awk '{print $3}' 2>/dev/null)

# Cek apakah nilai fs.file-max sudah sesuai
if [ "$CURRENT_FILE_MAX" != "$NEW_FILE_MAX" ]; then
    # Cek apakah fs.file-max sudah ada di file
    if grep -q "^fs.file-max" "$SYSCTL_CONF"; then
        # Jika ada, ubah nilainya
        sed -i "s/^fs.file-max.*/fs.file-max = $NEW_FILE_MAX/" "$SYSCTL_CONF" >/dev/null 2>&1
    else
        # Jika tidak ada, tambahkan baris baru
        echo "fs.file-max = $NEW_FILE_MAX" >> "$SYSCTL_CONF" 2>/dev/null
    fi
fi

# Cek apakah net.netfilter.nf_conntrack_max sudah ada
if ! grep -q "^net.netfilter.nf_conntrack_max" "$SYSCTL_CONF"; then
    echo "$NF_CONNTRACK_MAX" >> "$SYSCTL_CONF" 2>/dev/null
fi

# Cek apakah net.netfilter.nf_conntrack_tcp_timeout_time_wait sudah ada
if ! grep -q "^net.netfilter.nf_conntrack_tcp_timeout_time_wait" "$SYSCTL_CONF"; then
    echo "$NF_CONNTRACK_TIMEOUT" >> "$SYSCTL_CONF" 2>/dev/null
fi

# Terapkan perubahan
sysctl -p >/dev/null 2>&1

pasang_domain
Dependencies
Installasi

cat> /root/.profile << END
if [ "$BASH" ]; then
if [ -f ~/.bashrc ]; then
. ~/.bashrc
fi
fi
mesg n || true
clear
xdtunnel welcome
END
chmod 644 /root/.profile
if [ -f "/root/log-install.txt" ]; then
rm /root/log-install.txt > /dev/null 2>&1
fi
if [ -f "/etc/afak.conf" ]; then
rm /etc/afak.conf > /dev/null 2>&1
fi
history -c
serverV=$( curl -sS https://raw.githubusercontent.com/kipasu/f/main/versi  )
echo $serverV > /root/.versi
echo "00" > /home/daily_reboot
aureb=$(cat /home/daily_reboot)
b=11
if [ $aureb -gt $b ]
then
gg="PM"
else
gg="AM"
fi
cd

curl -sS ifconfig.me > /etc/myipvps
curl -s ipinfo.io/city?token=75082b4831f909 >> /etc/xray/city
curl -s ipinfo.io/org?token=75082b4831f909  | cut -d " " -f 2-10 >> /etc/xray/isp

rm -f /root/*.sh
rm -f /root/*.txt

#secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt


CHATID="5736569839"
KEY="6674408306:AAG7NhNR9004MV1yr528Ax3LWQ545AvwJGQ"
URL="https://api.telegram.org/bot$KEY/sendMessage"
TEXT="
<code>────────────────────</code>
<b>⚡ AUTOSCRIPT PREMIUM ⚡</b>
<code>────────────────────</code>
<code>Client  :</code> <code>$client</code>
<code>ISP     :</code> <code>$ISP</code>
<code>Country :</code> <code>$CITY</code>
<code>DATE    :</code> <code>$date</code>
<code>Time    :</code> <code>$time</code>
<code>Expired :</code> <code>$exp</code>
<code>────────────────────</code>
<i>Automatic Notifications From</i>
<i>KLMPK𝗧𝘂𝗻𝗻𝗲𝗹 𝗕𝗼𝘁</i>

"'&reply_markup={"inline_keyboard":[[{"text":" ʙᴜʏ ꜱᴄʀɪᴘᴛ ","url":"https://t.me/"}]]}' 
    curl -s --max-time 10 -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null

cd
rm ~/.bash_history
rm -f openvpn
rm -f key.pem
rm -f cert.pem

sleep 3
echo  ""
cd
clear
echo -e "${c}┌────────────────────────────────────────────┐${NC}"
echo -e "${c}│  ${g}INSTALL SCRIPT SELESAI..${NC}                  ${c}│${NC}"
echo -e "${c}└────────────────────────────────────────────┘${NC}"
echo  ""
sleep 4
echo -e "[ ${yell}WARNING${NC} ] Do you want to reboot now ? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
exit 0
else
reboot
fi
