# Nessus
## Nessus란? 
#### Nessus는 Tenable에서 개발한 취약점 스캐너(Vulnerability Scanner) 로, 네트워크, 시스템, 웹 애플리케이션 등의 보안 취약점을 자동으로 분석하는 도구 주로 보안 전문가, 침투 테스터, 시스템 관리자 등이 취약점 점검 및 보안 감사를 수행하는 데 사용됩니다.

- ### Nessus Basic Network Scan(환경 : Metasploitable2-Linux)
    #### Metasploitable2-Linux 서버를 통해 Nessus Basic Network Scan 탐지 실시
  검사 결과 
  
  ![image](https://github.com/user-attachments/assets/6d4e93ce-f3a7-419d-b355-ce65fba681c2)

#### 이번 점검을 통해 새로운 정보들을 확인할 수 있었으나, 주요 통신기반 취약점 검사 리스트의 항목들을 모두 탐지하려면 Nessus Professional의 Compliance 기능을 사용하여 .audit 파일을 생성하고 커스텀 점검을 수행해야 했습니다. 그로 인해 완벽한 점검은 이루어지지 않았지만, 주요 통신기반 취약점 검사 리스트를 탐지시 사용 할 .audit 유형들을 정리해보겠습니다.

- ###  주요 통신기반 취약점 검사 리스트의 탐지를 위한 .audit 유형
  참조 : https://docs.tenable.com/nessus/compliance-checks-reference/Content/UnixConfigurationCustomItems.htm
  ```
  ## 해당 파일에 문자열 존재 여부 O
  <custom_item>
  system: "Linux"
  type: FILE_CONTENT_CHECK
  description: "This check reports a problem when the log level setting in the sendmail.cf file is less than the value set in your security policy."
  file: "sendmail.cf"
  regex: ".*LogLevel=.*$"
  expect: ".*LogLevel=9"
  </custom_item>
  ```
  ```
   ## 해당 파일에 문자열 존재 여부 X
  <custom_item>
  type: FILE_CONTENT_CHECK_NOT
  description: "Make sure NIS is not enabled on the remote host by making sure that '+::' is not in /etc/passwd"
  file: "/etc/passwd"
  regex: "^\+::"
  expect: "^\+::"
  file_required: NO
  string_required: NO
  </custom_item>
  ```
  ```
   ## 해당 파일의 소유자, 그룹, 권한 여부 O
  <custom_item>
  system: "Linux"
  type: FILE_CHECK
  description: "Permission and ownership check for /etc/default/cron"
  file: "/etc/default/cron"
  owner: "bin"
  group: "bin"
  mode: "-r--r--r--"
  </custom_item>
  ```
  ```
  ## 해당 파일의 소유자, 그룹, 권한 여부 X
  <custom_item>
  type: FILE_CHECK_NOT
  description: "Make sure /bin/bash does NOT belong to root"
  file: "/bin/bash"
  owner: "root"
  </custom_item>
  ```
  ```
  ## 커맨드를 통한 출력 여부
  <custom_item>
  type: CMD_EXEC
  description: "Make sure that we are running FreeBSD 4.9 or higher"
  cmd: "uname –a"
  timeout: "600"
  expect: "FreeBSD (4\.(9|[1-9][0-9])|[5-9]\.)"
  dont_echo_cmd: YES
  </custom_item>
  ```
  ```
  ## PS 커맨드를 통한 프로세스 체크 
  <custom_item>
  system: "Linux"
  type: PROCESS_CHECK
  name: "auditd"
  status: OFF
  </custom_item>
  ```
