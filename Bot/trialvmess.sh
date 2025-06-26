#!/bin/bash

# Ambil informasi domain & sistem
source /var/lib/klmpk/ipvps.conf
domain=${IP:-$(cat /etc/xray/domain)}
ISP=$(cat /etc/xray/isp 2>/dev/null || echo "-")
CITY=$(cat /etc/xray/city 2>/dev/null || echo "-")
uuid=$(cat /proc/sys/kernel/random/uuid)

# Otomatis expired dalam 1 jam
masaaktif=60
Quota=1
iplimit=10
user="Trial-VM$(</dev/urandom tr -dc 0-9 | head -c3)"
exp=$(date -d "+60 minutes" +"%Y-%m-%d %H:%M")

# Tambah ke config Xray
sed -i '/#vmess$/a\### '"$user $exp"'\
},{"id": "'"$uuid"'","alterId": 0,"email": "'"$user"'"}' /etc/xray/config.json
sed -i '/#vmessgrpc$/a\### '"$user $exp"'\
},{"id": "'"$uuid"'","alterId": 0,"email": "'"$user"'"}' /etc/xray/config.json

# Encode link VMess
link_tls="vmess://$(echo "{\"v\":\"2\",\"ps\":\"$user\",\"add\":\"$domain\",\"port\":\"443\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$domain\",\"path\":\"/vmess\",\"tls\":\"tls\"}" | base64 -w 0)"
link_ntls="vmess://$(echo "{\"v\":\"2\",\"ps\":\"$user\",\"add\":\"$domain\",\"port\":\"80\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$domain\",\"path\":\"/vmess\",\"tls\":\"none\"}" | base64 -w 0)"
link_grpc="vmess://$(echo "{\"v\":\"2\",\"ps\":\"$user\",\"add\":\"$domain\",\"port\":\"443\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"grpc\",\"type\":\"none\",\"host\":\"$domain\",\"path\":\"vmess-grpc\",\"tls\":\"tls\"}" | base64 -w 0)"

# Cetak link agar bisa di-parse WhatsApp bot
echo "LINK_TLS: $link_tls"
echo "LINK_NTLS: $link_ntls"
echo "LINK_GRPC: $link_grpc"

# Simpan config OpenClash
mkdir -p /var/www/html
cat >/var/www/html/vmess-$user.txt <<-END
# TLS
- name: $user-TLS
  type: vmess
  server: $domain
  port: 443
  uuid: $uuid
  alterId: 0
  cipher: auto
  tls: true
  network: ws
  ws-opts:
    path: /vmess
    headers:
      Host: $domain

# Non-TLS
- name: $user-NTLS
  type: vmess
  server: $domain
  port: 80
  uuid: $uuid
  alterId: 0
  cipher: auto
  tls: false
  network: ws
  ws-opts:
    path: /vmess
    headers:
      Host: $domain

# gRPC
- name: $user-GRPC
  type: vmess
  server: $domain
  port: 443
  uuid: $uuid
  alterId: 0
  cipher: auto
  tls: true
  network: grpc
  grpc-opts:
    grpc-service-name: vmess-grpc
END

# Simpan limit
mkdir -p /etc/vmess /etc/klmpk/limit/vmess/ip
echo "$iplimit" > /etc/klmpk/limit/vmess/ip/$user
echo "$((Quota * 1024 * 1024 * 1024))" > /etc/vmess/$user

# Tambah ke database
sed -i "/\\b$user\\b/d" /etc/vmess/.vmess.db
echo "### $user $exp $uuid $Quota $iplimit" >> /etc/vmess/.vmess.db

# Output informasi ke terminal
echo -e "📡 *XRAY TRIAL VMESS*"
echo -e "━━━━━━━━━━━━━━━━━━━━━━"
echo -e "👤 *Username* : $user"
echo -e "🌐 *Domain*   : $domain"
echo -e "🆔 *UUID*     : $uuid"
echo -e "📅 *Expired*  : $exp"
echo -e "📦 *Quota*    : $Quota GB"
echo -e "🔐 *IP Limit* : $iplimit"
echo -e "━━━━━━━━━━━━━━━━━━━━━━"
echo -e "📁 *OpenClash Config:*"
echo -e "https://$domain:81/vmess-$user.txt"
echo -e "━━━━━━━━━━━━━━━━━━━━━━"
echo -e "🔥 Trial aktif selama *1 jam*"
echo -e "🛡️ *ISP:* $ISP  |  *Kota:* $CITY"
echo -e "🧾 Script by github.com/Andyyuda"

# Auto kill setelah 60 menit
echo "killusr vm $user" | at now + 60 minutes
systemctl restart xray > /dev/null 2>&1
