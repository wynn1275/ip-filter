# ip-filter
출발지의 IP 정보를 기준으로 접근이 제한된 IP 인지 여부를 판단하는 API 를 제공합니다.

## API spec

### Request
#### URI

| HTTP method | URI |
| --- | --- |
| GET | /ipv4 |

#### 지원하는 Request Header 종류 (선택)

* X-Forwarded-For
* Proxy-Client-IP
* WL-Proxy-Client-IP
* HTTP_CLIENT_IP
* HTTP_X_FORWARDED_FOR

#### Request 예시
[예시1]
```shell script
curl -XGET http://127.0.0.1:8080/ipv4
```

[예시2 - 'X-Forwarded-For' 헤더값이 존재하는 경우]
```shell script
curl -XGET -H "X-Forwarded-For:10.0.0.1" http://127.0.0.1:8080/ipv4
```

### Response
* Content-Type : application/json
* Status code / body
  * 접근 허용된 client IP 인 경우
     * status code : 200 OK
     * body
```json
{
  "resultMessage":"Allow",
  "clientIp":"1.1.1.1"
}
```
  * 접근 차단된 client IP 인 경우
    * status code : 403 FORBIDDEN
    * body
```json
{
  "resultMessage":"Deny",
  "clientIp":"200.0.0.255"
}
```
  * 기타 status code
    * 400 BAD REQUEST : request header 의 client IP 가 잘못된 IP 형식인 경우 (ex. 255.266.266.266)

## 문제 해결 전략
* properties 파일에 등록된 차단 IP 목록 기준으로, 출발지 IP 정보의 접근 허용/차단 방법을 기술합니다.

### properties file load 전략
1. properties 파일에 등록된 차단 IP 목록을 List 로 load.
  - properties 파일 예제
```yml
ip-filter.deny: 
    - 245.59.153.210/9
    - 21.190.201.151/25
    - 16.53.65.231/26
    - 15.7.44.84/30
    - 166.56.186.84/16
    - 154.81.221.242/31
    - 97.240.23.225/9
    - 61.68.213.201/21
    - 223.1.159.33/29
```
2. 읽어들인 차단 IP List 를 순회하며 Subnet 정보로 변환 및 TreeMap 에 저장
  1) CIDR 표기법을 포함한 IP 주소를 읽어와, 해당 IP의 subnet 정보가 담긴 Object 로 변환
    - ex. (String) "245.59.153.210/9" -> (Object) {"시작 IP":4110417920L(245.0.0.0), "마지막 IP"=4118806527L(245.127.255.255), "CIDR bit"=9, "IP 주소"=4114323922L(245.59.153.210)}
  2) TreeMap 에 subnet 정보를 저장
    - key=해당 subnet 의 시작 IP(long), value=subnet 정보
    - TreeMap 에 동일한 key 가 존재하는 경우, 중첩된(nested) subnet 으로 판단하고 더 큰 범위의 subnet 정보로 replace
    - TreeMap 에 저장된 IP 개수가 MAX (3000만 개) 를 넘는 경우 더 이상 저장하지 않고 application start 함. load 를 중지한 차단 IP List 의 시점은 로그로 기록
#### properties file load 예시
```text
* properties 파일에 다음과 같은 순서로 차단 IP 가 저장되어있는 경우
10.0.10.25/24 --> treeMap={10.0.10.0=10.0.10.0/24}
10.0.0.27/16   --> treeMap={10.0.0.0=10.0.0.0/16, 10.0.10.0=10.0.10.0/24}
10.100.0.25/24 ->treeMap={10.0.0.0=10.0.0.0/16, 10.0.10.0=10.0.10.0/24, 10.100.0.0=10.100.0.0/24}
10.0.0.0/8       --> treeMap={10.0.0.0=10.0.0.0/8, 10.0.10.0=10.0.10.0/24, 10.100.0.0=10.100.0.0/24}
10.0.1.2/24     --> treeMap={10.0.0.0=10.0.0.0/8, 10.0.10.0=10.0.10.0/24, 10.100.0.0=10.100.0.0/24}

1) CIDR 표기법을 포함한 IP 주소를 읽어와, 해당 IP의 subnet 정보가 담긴 Object 로 변환
10.0.10.25/24  --> {startIpLong=167774720L(10.0.10.0), endIpLong=167774975L(10.0.10.255), cidr=24, ipLong=167774745L(10.0.10.25)}
10.0.0.27/16   --> {startIpLong=167772160L(10.0.0.0), endIpLong=167837695L(10.0.255.255), cidr=16, ipLong=167772187L(10.0.0.27)}
10.100.0.25/24 --> {startIpLong=174325760L(10.100.0.0), endIpLong=174326015L(10.100.0.255), cidr=24, ipLong=174325785L(10.100.0.25)}
10.0.0.0/8     --> {startIpLong=167772160L(10.0.0.0), endIpLong=184549375L(10.255.255.255), cidr=8, ipLong=167772160L(10.0.0.0)}
10.0.1.2/24    --> {startIpLong=167772416L(10.0.1.0), endIpLong=167772671(10.0.1.255), cidr=24, ipLong=167772418L(10.0.1.2)}

2) TreeMap 에 subnet 정보를 저장
// subnet 정보가 담긴 Object 는 임의로 '{[start IP with CIDR notation]}'' 으로 표기합니다.
10.0.10.25/24  --> treeMap={ 167774720L={10.0.10.0/24} }, countDeny=256
10.0.0.27/16   --> treeMap={ 167772160L={10.0.0.0/16}, 167774720L={10.0.10.0/24} }, countDeny=65792 (256+65536)
10.100.0.25/24 --> treeMap={ 167772160L={10.0.0.0/16}, 167774720L={10.0.10.0/24}, 174325760L={10.100.0.0/24} }, countDeny=66048 (65792+256)
10.0.0.0/8     --> treeMap={ 167772160L={10.0.0.0/8} }, countDeny=16777216 (66048 + 16777216 - 65536 - 256 - 256) // 새로운 범위의 subnet 을 추가하고, 기존 TreeMap 에서 중첩되는 subnet 을 삭제함
10.0.1.2/24    --> treeMap={ 167772160L={10.0.0.0/8} } // 10.0.1.2/24 는 TreeMap 에 들어가있는 "10.0.0.0/8" 에 중첩되므로, 추가하지 않음

--> 최종 load 된 TreeMap = { 167772160L={10.0.0.0/8} }
```

### 출발지 IP 의 접근 허용/차단 여부 판단 전략
1. 출발지 IP 를 long 으로 변환
2. 차단 IP subnet 정보가 담긴 TreeMap 에서 floorKey 를 찾음
  - TreeMap 의 key 가 각 subnet 의 시작 IP 이므로, 출발지 IP(long) 과 같거나 작은(floor) key 의 value(subnet)가 출발지 IP 가 속하거나 그보다 바로 앞의 subnet 
3. 해당 subnet 에 출발지 IP 가 속하는지 여부를 판단. 속하는 경우 차단 IP 이므로 Deny 로 판단. 속하지 않는 경우 Allow 로 판단. 


## 프로젝트 빌드 / 실행 방법
### 빌드 환경
* java 11
* maven 3.6
### 빌드 방법
```text
mvn clean package -P release
```

### 실행 방법
```text
java -jar ip-filter-0.0.1-SNAPSHOT.jar
```

## 성능테스트 결과
(추가)
