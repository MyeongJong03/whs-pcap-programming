# PCAP TCP 패킷 스니퍼

## 과제 개요

WhiteHat School 네트워크 보안 수업의 PCAP Programming 과제입니다.
C와 libpcap을 사용해서 TCP 패킷을 캡처하고, Ethernet Header, IP Header, TCP Header, HTTP Message 정보를 출력합니다.

## 개발 환경

- Ubuntu / WSL 환경
- C 언어
- gcc
- libpcap
- make

libpcap 개발 패키지가 없다면 Ubuntu 기준으로 아래와 같이 설치할 수 있습니다.

```sh
sudo apt install libpcap-dev
```

## 빌드 방법

```sh
make
```

수동 컴파일도 가능합니다.

```sh
gcc -Wall -Wextra -O2 -o pcap_sniffer pcap_sniffer.c -lpcap
```

## 실행 방법

첫 번째 non-loopback 인터페이스를 자동으로 선택합니다.

```sh
sudo ./pcap_sniffer
```

인터페이스를 직접 지정할 수도 있습니다.

```sh
sudo ./pcap_sniffer eth0
```

## 구현 기능

- PCAP API를 이용한 패킷 캡처
- BPF 필터 `tcp` 적용
- TCP 패킷만 처리
- UDP, ICMP, ARP 등 TCP가 아닌 패킷은 무시
- Ethernet Header의 출발지/목적지 MAC 출력
- IP Header의 출발지/목적지 IP 출력
- TCP Header의 출발지/목적지 Port 출력
- TCP Payload가 있으면 HTTP Message 항목으로 출력
- `ip_header_len = ip->iph_ihl * 4` 방식으로 IP Header 길이 계산
- `tcp_header_len = TH_OFF(tcp) * 4` 방식으로 TCP Header 길이 계산
- 출력 가능한 ASCII 문자는 그대로 출력하고, 그 외의 문자는 `.`으로 출력

## 테스트 방법

먼저 빌드가 되는지 확인합니다.

```sh
make clean
make
```

패킷 캡처 프로그램을 실행한 뒤, 다른 터미널에서 HTTP 요청을 보내면 확인하기 쉽습니다.

```sh
curl --http1.1 http://example.com/
```

정상적으로 캡처되면 `[Ethernet Header]`, `[IP Header]`, `[TCP Header]`, `[HTTP Message]` 형식으로 출력됩니다.

## HTTP/HTTPS 관련 주의점

이 프로그램은 TCP Payload를 사람이 읽을 수 있는 형태로 출력합니다.
HTTP는 평문이라 요청/응답 내용이 보일 수 있지만, HTTPS는 TLS로 암호화되므로 HTTP Message가 평문으로 보이지 않을 수 있습니다.
