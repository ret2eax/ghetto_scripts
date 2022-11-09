use strict;
use warnings;
use feature 'say';

my $re_classA = qr/(10)(\.([2]([0-5][0-5]|[01234][6-9])|[1][0-9][0-9]|[1-9][0-9]|[0-9])){3}/;
my $re_classB = qr/(172)\.(1[6-9]|2[0-9]|3[0-1])(\.(2[0-4][0-9]|25[0-5]|[1][0-9][0-9]|[1-9][0-9]|[0-9])){2}/;
my $re_classC = qr/(192)\.(168)(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){2}/;

while(<DATA>) {
    chomp;
    next if /^;/;
    say if /$re_classA/;
    say if /$re_classB/;
    say if /$re_classC/;
}

__DATA__

; <<>> DiG 9.10.6 <<>> google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19663
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;google.com.            IN  A

;; ANSWER SECTION:
google.com.     135 IN  A   192.168.0.1

;; Query time: 38 msec
;; SERVER: 192.168.0.1#53(192.168.0.1)
;; WHEN: Tue May 12 17:40:16 AEST 2020
;; MSG SIZE  rcvd: 55

; <<>> DiG 9.10.6 <<>> transfer.me
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7906
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;transfer.me.           IN  A

;; ANSWER SECTION:
transfer.me.        7200    IN  A   10.216.41.127

;; Query time: 588 msec
;; SERVER: 192.168.0.1#53(192.168.0.1)
;; WHEN: Tue May 12 17:40:36 AEST 2020
;; MSG SIZE  rcvd: 56
