# sshw 상세 참조

[처음 사용하기](../README.ko.md) | [English](reference.md)

옵션의 정확한 동작, 설정 규칙과 오류 처리 방식이 필요할 때 보는 문서입니다. 첫 연결은 README의 순서대로 진행하세요.

- [설정 저장 위치와 프로필](#저장-구조와-profile)
- [비밀번호 인증](#비밀번호-인증)과 [SSH Agent](#ssh-agent-인증)
- [로그인 계정](#서버-account-관리)과 [권한 상승](#권한-상승-명령)
- [명령 목록](#명령)과 [파일 전송](#업로드-보호실시간-출력전송-사전-검사)
- [Windows 경로](#windows-셸-경로)
- [정책](#policy-적용), [감사 기록](#audit-log), [출력 마스킹](#출력-redaction)
- [진단](#doctor)과 [JSON·종료 코드](#json-오류-계약)
- [설정 저장](#파일-권한과-원자성)과 [실행 파일 검증](#실행-파일-검증)


## 저장 구조와 profile

`0.15.0`은 기존 CLI 호출·종료 코드·설정 읽기를 유지하며 진단과 변경 여부 필드를 추가합니다. Rust 라이브러리에서 `PrivilegeConfig`를 직접 구성한다면 `credential: Some(...)`과 `no_password: false`로 기존 비밀번호 설정을 표현하세요. 무비밀번호 sudo는 `credential: None`, `no_password: true`입니다. `ErrorResponse` 구조체를 직접 구성하는 호출자는 새 `mutation` 필드를 반영해야 합니다. `Prompter`의 새 확인 준비 hook은 기본 구현이 있어 기존 구현을 유지할 수 있습니다. 릴리스와 Rust API 이행 내역은 [CHANGELOG.md](../CHANGELOG.md)에서 확인하세요.

모든 상태는 프로젝트별 **home** 아래에 있습니다. home 디렉터리 구성:

```text
<home>/servers.json    서버 endpoint와 등록 account, auth/credential key, account별 privilege metadata
<home>/known_hosts      신뢰한 SSH host key(OpenSSH 형식)
<home>/policy.json      선택적 policy(아래 Policy 참고)
<home>/audit.jsonl      append-only audit log
```

전역 profile registry는 profile 이름을 home에 매핑합니다.

```text
<config_dir>/sshw/profiles.json            registry
<config_dir>/sshw/profiles/default/         내장 default profile home
```

`<config_dir>`는 Windows `%AppData%`, macOS `~/Library/Application Support`, Linux `~/.config`입니다.

신규 credential keyring 키는 purpose, server, user, generation을 포함한 v3 형식을 사용합니다. 따라서 서로 다른 home의 같은 server/user가 충돌하지 않고, 한 서버의 account끼리 credential을 재사용할 수 없으며, login credential을 privilege credential로 재사용할 수도 없습니다.

```text
sshw:v3:<encoded-namespace>:login:<encoded-server>:<encoded-user>:<generation>
sshw:v3:<encoded-namespace>:privilege:<encoded-server>:<encoded-user>:<generation>
```

namespace, server, user는 base64url로 인코딩하며 credential을 갱신할 때마다 새 generation을 발급합니다. legacy v1 키(`sshw:<namespace>:<server>`, `sshw:<namespace>:privilege:<server>`)와 server 범위 v2 키는 active namespace, purpose, server가 일치하고 다른 account와 충돌하지 않을 때만 읽기 호환을 유지하며 신규 저장은 v3를 사용합니다.

`servers.json` schema v2는 각 server 아래 `default_user`와 username-keyed `accounts` map을 저장합니다. schema v1도 계속 읽을 수 있으며 기존 단일 `user`/`auth`와 최상위 `privileges` map의 같은 server 항목을 메모리에서 default account로 해석합니다. v1 server 객체 안의 중첩 `privilege` 필드는 허용하지 않습니다. read-only 명령은 파일을 바꾸지 않고, 다음 config mutation이 성공하면 legacy credential 참조를 유지한 채 schema v2로 저장합니다.

## home 선택

우선순위(높은 순):

1. `--home <path>` — 일회성/프로젝트 로컬 home.
2. `SSHW_HOME` — 환경변수로 동일.
3. `--profile <name>` — 등록된 profile(없으면 에러).
4. registry의 default profile.
5. 내장 default profile home(`<config_dir>/sshw/profiles/default`).

`--home`과 `--profile`은 함께 쓸 수 없습니다(exit code 3). 명시적 `--profile`과 비어 있지 않은 `SSHW_HOME`도 충돌 오류를 반환합니다. profile을 선택하려면 환경변수를 해제하고, 환경변수 home을 쓰려면 `--profile`을 생략하세요. 한쪽이 다른 쪽을 조용히 가리지 않습니다.

선택한 home은 폴더여야 합니다. 파일·파일 아래 경로·경로 검사 실패는 서버 목록이나 정책을 읽기 전에 config/3으로 거절합니다. 아직 없는 폴더는 허용하며 이 검사로 생성하지 않습니다. 상대 경로의 선택과 credential namespace도 유지합니다. 잘못된 현재 home을 복구할 수 있도록 글로벌 `profile` 관리는 계속 사용할 수 있고, `profile add/default`는 저장 전에 대상 home을 검사합니다. doctor의 손상된 registry 복구도 내장 home을 검사하며 잘못 지정한 `--home`/`SSHW_HOME`을 가리지 않습니다.

```bash
sshw --home ./.sshw list
SSHW_HOME=./.sshw sshw list
sshw --profile prod run web "uptime"
```

## profile 관리

미등록 프로필을 `--profile`로 선택하거나 `profile show/default/remove`에 지정하면 config/3 오류가 `sshw profile list`와 이름을 인용한 등록 명령을 안내합니다. 복구 명령에서 실패한 `--profile`을 빼고, `sshw --home '<home>' profile add -- '<name>'`의 placeholder를 실제 값으로 바꾸세요. 등록한 namespace를 사용할 때는 `--home`을 빼고 `SSHW_HOME`을 해제한 뒤 `--profile=<name>`으로 선택합니다. 이름은 개별 마스킹하고 Windows PowerShell/POSIX 셸에 맞게 인용합니다. 등록 프로필이 없는 일반 목록도 등록 방법을 표시하며 JSON은 기존 `[]`를 유지합니다. 이름을 등록하는 것은 선택 사항이며 내장 기본 home을 포함한 기존 home 선택은 계속 사용할 수 있습니다. 오류 안내가 프로필을 등록·전환하거나 namespace를 재사용하지는 않습니다.

```bash
sshw profile add prod --home /srv/prod    # home은 전역 --home 플래그에서 가져옵니다
sshw profile list
sshw profile list --json
sshw profile show prod
sshw profile show prod --json
sshw profile default prod
sshw profile remove prod                  # registry 항목만 제거. home 디렉터리와 credential은 보존
```

각 profile은 stable id와 home 경로를 저장합니다. 처음 추가한 profile이 default가 됩니다. 정규화된 home이 같으면 `profile add --force`는 기존 id를 보존하고, 다른 home으로 바꾸면 새 namespace를 만듭니다. profile 선택 방식 자체가 credential 경계이므로 profile 소유 디렉터리를 `--home`으로 열어도 그 profile credential을 재사용하지 않습니다. profile을 제거하면 디렉터리와 native keyring 항목은 물리적으로 남지만 신뢰된 namespace 연결은 사라집니다. 제거한 profile을 다시 추가하면 새 credential namespace가 만들어지므로 credential을 다시 등록해야 합니다. 같은 profile/home 갱신에는 remove/re-add 대신 `--force`를 사용하세요.

`profile add --force`는 대상 검증 후 계산한 전체 registry가 이전과 같으면 저장을 생략하고 원본 bytes/mtime를 보존합니다. 일반 출력은 (unchanged), JSON은 `changed:false`/`change:"unchanged"`를 표시합니다. 실제 변경은 `changed:true`와 `change:"added"` 또는 `"updated"`입니다. 기존 action/id/home/namespace 필드·force 필요·lock/audit를 유지하며 기본값이나 저장 경로 등 내용이 달라지면 기존 CAS/atomic 저장을 수행합니다.

`profile default <name>`은 등록된 credential namespace로 대상 설정과 home 경로를 다시 검사한 뒤 기본값을 저장합니다. 잘못된 설정이나 호환되지 않는 자격 증명 참조는 config/3으로 거부하고 이전 기본값을 보존합니다. 빈 home은 허용하며 현재 프로필이 손상됐더라도 정상 대상으로 전환할 수 있습니다. 검사는 비밀 조회·SSH 접속·대상 파일 재저장·namespace 변경을 수행하지 않습니다.

기본 프로필을 삭제할 때도 이름순으로 자동 선택되는 다음 프로필의 로컬 설정을 검사합니다. 삭제는 기존처럼 성공하며, 새 기본값을 검사할 수 없으면 일반 출력과 JSON `default_target_warning`에 이름·home·마스킹된 원인·복구 방법을 `default_change`와 함께 표시합니다. 해당 home을 복구하거나 `sshw profile list`와 `sshw profile default <정상-이름>`으로 전환하세요. 기본값이 아닌 항목 삭제·빈 대상 home·마지막 프로필 삭제에는 이 경고가 없습니다. 비밀 조회나 SSH 접속은 검사하지 않습니다.

프로필 추가·갱신은 사용할 namespace로 대상 `servers.json`의 형식·기본값·계정·자격 증명 참조를 검사하고, 실제 변경이 있을 때 registry를 저장합니다. 호환되지 않으면 경로와 원인을 안내하고 기존 연결과 기본값을 보존하며, `--force`로도 검사를 건너뛰지 않습니다. 없는 home과 호환되는 agent/무비밀번호 설정은 허용하지만 경로의 기존 부분이 파일이면 거부합니다. 검사는 대상 파일을 바꾸거나 비밀번호/keyring/SSH를 조회하지 않으며, 이후 파일 변경은 실행 시 다시 검증합니다.

결과는 신규 `added`와 기존 항목 갱신 `updated`를 구분합니다. JSON에는 `id`·`namespace_changed`를 추가하고, 경로 이동으로 namespace가 바뀌면 `previous_home`과 재등록 안내 `warning`도 제공합니다. 같은 home의 갱신은 namespace를 보존합니다. 경로 변경은 서버 파일이나 비밀을 옮기지 않으며 이전 home/keyring은 남습니다. 복사한 비밀번호 설정이 호환되지 않으면 빈 home 또는 호환되는 설정을 선택하고 필요한 비밀번호를 새 연결에서 등록하세요.

registry는 엄격하게 검증합니다. 이전 릴리스가 상대경로 profile home을 저장한 경우 일반 선택/list/show/default 작업은 fail-closed합니다. `sshw doctor`는 `registry_valid: false`와 조치 가능한 `registry_message`를 보고합니다. 유일한 복구 예외인 `sshw profile remove <문제-profile>`은 그 항목을 제거한 뒤 나머지 registry가 완전히 유효할 때만 성공하며, 상대경로를 현재 작업 디렉터리 기준으로 해석하거나 자동 이동하지 않습니다.

## 비밀번호 인증

```bash
sshw add server-alpha --host 192.0.2.10 --port 2222 --user deploy
```

비밀번호 인증이 기본값입니다. `sshw`는 숨김 입력으로 비밀번호를 받아 활성 credential backend의 home namespace 키로 저장합니다.

등록 시 빈 호스트·공백만 있는 호스트·호스트의 제어 문자·포트 `0`은 확인 질문이나 비밀번호 입력 전에 `config`/종료 코드 `3`으로 거부합니다. 포트 범위는 `1..65535`입니다. v1/v2 설정 로딩에도 같은 검사를 적용하며, `doctor`는 잘못된 설정의 서버 이름과 원인을 표시합니다. IPv6를 포함한 호스트 입력값은 그대로 유지하고 DNS 조회나 연결 검사는 하지 않습니다. 잘못 저장된 주소는 안내된 `servers.json` 경로에서 수정하세요.

비대화형 등록에서는 secret manager 출력에서 비밀번호를 pipe로 전달할 수 있습니다.

```bash
secret-manager-read deploy/server-alpha | sshw add server-alpha --host 192.0.2.10 --port 2222 --user deploy --password-stdin
```

`--password-stdin`은 password auth에서만 유효합니다. stdin을 한 번 읽고 마지막 LF 또는 CRLF 하나만 제거하며, 빈 입력은 거부합니다. 이 경로는 비밀번호를 argv나 shell history에 남기지 않기 위한 것이며, `sshw`는 의도적으로 `--password <value>` 인자를 제공하지 않습니다.

`add`·`account add`·`privilege set`이 제어 터미널에서 비밀번호를 읽지 못하면 auth/4 오류에 원래 OS 원인과 대화형 터미널 또는 비밀 관리자 pipe를 통한 `--password-stdin` 사용법을 안내합니다. stdin 리디렉션만으로 비밀번호를 자동 입력하지 않으므로 옵션을 명시하세요. 제어 터미널이 정상이라면 stdin이 리디렉션돼 있어도 숨김 비밀번호 입력을 사용할 수 있습니다.

Linux의 native backend는 동작하는 Secret Service provider(GNOME Keyring, KWallet)가 필요합니다. `sshw doctor`가 가용성을 보고하며, 평문 저장으로 fallback하지 않습니다.

## SSH Agent 인증

```bash
sshw add server-beta --host 192.0.2.11 --port 2222 --user deploy --auth agent
```

agent auth는 비밀을 저장하지 않고 활성 SSH agent를 사용합니다.

`add/account add`로 agent 서버·계정을 재등록할 때도 확인 또는 `--force`가 필요합니다. 최종 전체 설정이 같으면 저장을 생략해 원본 형식·bytes/mtime를 유지하고 일반 출력의 `(unchanged)`와 JSON `changed:false`/`change:"unchanged"`를 표시합니다. 실제 변경은 `true`와 `added/updated`이며 기존 action/대상 필드는 유지합니다. endpoint·기본값·계정·교체 결과도 전체 설정에 포함해 비교합니다. 비밀번호 등록은 credential을 재발급하므로 계속 실제 변경으로 처리합니다. 검증·잠금·감사 및 실제 변경의 동시 수정/atomic 저장·비밀 정리를 유지합니다.

`run`·`put`·`get`의 agent 인증 실패는 선택한 로그인 사용자·host/port·마스킹한 native 원인과 점검 방법을 표시합니다. 같은 home/profile과 실행 환경에서 `sshw doctor`를 실행하고 agent 연결·로드된 키 및 서버의 해당 계정/키 허용을 확인하세요. agent 연결 불가와 키 부재는 원인이 다를 수 있습니다. auth/4·JSON causes와 host key 확인 후 인증 순서를 유지하며 agent 시작·키 로드·비밀번호 fallback을 자동 실행하지 않습니다.

## 서버 account 관리

미등록 서버 오류(config/3)는 등록된 서버를 선택해야 한다는 설명과 `sshw list`·host/login-user placeholder가 있는 등록 명령을 제공합니다. 같은 home/profile을 유지하고 placeholder를 실제 값으로 바꿔 실행하세요. 이름은 민감 값을 마스킹한 뒤 Windows PowerShell/그 외 POSIX 셸에 맞게 인용하며 `--` 뒤에 둡니다. 등록은 기본적으로 비밀번호 숨김 입력이므로 필요한 `--auth agent` 또는 `--password-stdin`을 `--` 앞에 넣으세요. `run`과 대응 policy check는 전체 명령 인용 안내도 유지합니다. 이 진단이 서버를 등록하거나 다른 home에서 선택·접속하지 않습니다.

`run`·`put`·`get`의 비밀번호 SSH 인증 실패도 로그인 사용자·host/port·마스킹한 native 원인을 표시합니다. 같은 home/profile의 `sshw doctor`로 로컬 credential 준비 상태를 검사하고 로그인 비밀번호(세션 전용은 `SSHW_PASSWORD`)·계정의 로그인 허용·서버의 password 인증 설정을 확인하세요. 일반 인증 실패만으로 어느 조건이 문제인지 단정하지 않습니다. 원래 native source/code·auth/4·JSON causes와 host key 확인 후 인증 순서를 유지하며 비밀번호 변경·추가 인증/재시도·agent 전환을 자동 실행하지 않습니다.

미등록 계정 오류(config/3)는 등록된 로그인 계정을 선택해야 한다는 설명과 복사 가능한 `account list`·`account add` 명령을 제공합니다. 같은 home/profile을 사용하세요. 새 등록은 기본적으로 비밀번호 숨김 입력을 사용하며, agent 인증은 안내 명령의 `--` 앞에 `--auth agent`, 비밀번호 pipe/redirection은 `--password-stdin`을 넣습니다. 오류가 계정이나 자격 증명을 자동 변경하지 않으며 이름을 개별 마스킹하고 로컬 셸에 맞게 인용합니다.

각 server endpoint에는 여러 SSH username을 명시적으로 등록할 수 있습니다. `--user`를 생략하면 server의 `default_user`를 사용하고, `--user <name>`은 등록된 account만 선택하며 임의 username override로 동작하지 않습니다.

canonical selector는 명시적 `--user` 플래그입니다. 기존 server alias에는 `@`가 들어갈 수 있어 target 해석이 모호해지므로 `user@alias`는 파싱하지 않습니다.

`account list/show`의 일반 출력은 `sudo -> service (no password)` 또는 `su -> root (password)`처럼 승격 방식·대상 사용자·비밀번호 사용 여부를 함께 표시합니다. 저장 설정에서 대상을 생략하면 기존처럼 `root`이며, 승격 설정이 없으면 `none`입니다. 로그인 계정은 별도로 표시하고 대상의 민감한 패턴은 마스킹합니다. JSON 구조는 유지합니다.

```bash
sshw account add server-alpha ops                         # 비밀번호 prompt
sshw account add server-alpha auditor --auth agent
sshw account list server-alpha
sshw account show server-alpha ops --json
sshw account default server-alpha ops
sshw account remove server-alpha auditor --yes

sshw run server-alpha "whoami"                           # default account
sshw run server-alpha "whoami" --user deploy             # 등록된 deploy account
sshw put server-alpha ./app /srv/app/app --user deploy
sshw get server-alpha /var/log/app.log ./app.log --user deploy
```

password account는 server와 username마다 독립 credential을 저장합니다. account 갱신은 해당 login credential만 rotation하고 account별 privilege 설정은 보존합니다. non-default account 제거는 config에서 먼저 제거한 뒤 해당 login/privilege credential을 삭제합니다. default account는 다른 등록 account를 default로 지정하기 전에는 제거할 수 없습니다. 하나의 endpoint에 속한 모든 account는 같은 host/port host-key 경계를 공유하므로 `trust`는 server-only로 유지됩니다.

## Credential 백엔드

home의 `servers.json`이 `credential_backend`(기본 `native`)로 백엔드를 선택합니다.

- `native` — OS keyring(Windows Credential Manager, macOS Keychain, Linux Secret Service).
- `session_only` — keyring을 쓰지 않습니다. `set_password`는 프로세스 메모리에만 유지됩니다. 실행 시 login 비밀번호는 `SSHW_PASSWORD`, privilege 비밀번호는 `SSHW_PRIVILEGE_PASSWORD`에서 가져오며, 읽은 두 환경변수는 이 프로세스 환경에서 제거합니다. ephemeral/CI에 적합합니다. 환경변수는 `sshw` 시작 전이나 부모 셸에는 노출될 수 있으므로 둘 다 민감하게 취급하세요. `add --auth password`와 `privilege set`은 비밀번호가 영속되지 않는다고 경고합니다.

external-helper 백엔드는 동일한 `CredentialStore` trait 뒤의 후속 확장점입니다.

## 권한 상승 명령

```bash
secret-manager-read root/server-alpha | sshw privilege set server-alpha --method sudo --password-stdin
secret-manager-read root/server-alpha-ops | sshw privilege set server-alpha --account ops --method sudo --password-stdin
sshw privilege show server-alpha
sshw privilege show server-alpha --account ops
sshw privilege clear server-alpha --yes
sshw run server-alpha "systemctl restart app" --user ops --as-root --yes
```

privilege metadata는 선택된 login account별로 분리됩니다. `privilege set/show/clear --account <login-user>`는 account를 명시하고, 생략하면 server default account를 사용합니다. `privilege set`은 method, 대상 user(기본 `root`), credential key metadata만 `servers.json`에 저장합니다. sudo/root 비밀번호는 활성 credential backend에만 저장되며 CLI 인자나 평문 config에는 들어가지 않습니다. 비밀번호 방식에서 `--password-stdin`을 쓰지 않으면 숨김 입력 프롬프트로 받습니다. 무비밀번호 설정은 credential 참조 없이 `no_password:true`를 저장하고 기존 설정은 비밀번호 방식으로 읽습니다. 일반 set/show/clear 출력과 확인 질문은 로그인 계정과 승격 대상을 구분합니다. JSON에는 `no_password`가 추가되며 무비밀번호 설정의 `credential`은 null입니다.

`run --as-root`(별칭 `--elevate`) 자체가 명시적 권한 상승 요청입니다. 원래 명령이 위험 작업 확인 대상인 경우에만 별도 `--yes`가 필요합니다. 비밀번호 sudo 설정에서는 원래 명령에 기존 safety/policy 검사를 먼저 적용한 뒤, SSH channel stdin으로만 privilege 비밀번호를 전달하는 `sudo -S` 경로를 사용합니다. 비밀번호는 원격 command string이나 audit detail에 들어가지 않습니다. 대상 user에 `NOPASSWD` sudoers 규칙이 있으면 `sudo`가 비밀번호를 소비하지 않으므로, 저장된 비밀번호의 정확성과 무관하게 명령이 실행됩니다 — 이 경우 저장 비밀번호는 추가 게이트가 아닙니다. sudo 비밀번호 거부는 원격에서 실행된 `sudo` 명령의 non-zero 상태로 보고되므로 sshw exit `8`이며, 실제 상태는 `run --json`의 `exit_status`에 들어갑니다. `method=su`는 `su - <user> -c ...`를 PTY로 실행하고 `Password:` 프롬프트가 나오면 저장된 비밀번호를 주입합니다(echo 비활성화, `LC_ALL=C`로 프롬프트를 영어로 고정). 명령 출력과 exit code는 marker로 정확히 추출되어 출력 라인이 누락되지 않습니다. `sudo`보다 환경에 민감하며, 프롬프트를 인식하지 못하면 무한 대기 대신 타임아웃으로 fail-closed됩니다. completion marker 전에 발생한 `su` 프롬프트/인증 실패는 sshw의 auth/setup 실패로 간주되어 exit code `4`에 매핑됩니다.

서버가 이미 무비밀번호 sudo를 허용한다면 `sshw run web "id -u" --as-root --no-password`를 사용하세요. 저장된 privilege 비밀번호를 읽거나 입력받지 않고 `sudo -n`을 실행합니다. 등록된 sudo 대상 계정을 사용하며 설정이 없으면 root입니다. su 설정이 있으면 거부하고 실제 권한은 원격 sudoers가 결정합니다. `privilege set --account`는 `--login-user`, 대상 `--user`는 `--target-user` 별칭도 지원합니다.

`run --as-root`는 로그인 비밀번호 조회 전에 필요한 승격 설정과 su/`--no-password` 충돌을 검사합니다. 로그인 비밀번호가 없어도 로컬 승격 설정 오류(config/3)를 먼저 안내합니다. 기존 safety/policy/account 선택과 stream/su 검사는 더 먼저 실행합니다. 일반 로그인 오류는 auth/4이며, 저장된 승격 설정 없이 `--as-root --no-password`를 사용하는 의미도 유지합니다.

같은 `privilege set --no-password` 설정을 재적용할 때도 확인 또는 `--force`가 필요합니다. 최종 전체 설정이 같으면 저장을 생략해 원본 bytes/mtime를 보존하고 일반 출력의 `(unchanged)`와 JSON `changed:false`/`change:"unchanged"`를 표시합니다. 신규·실제 변경은 `true`와 `added/updated`이며 기존 대상/credential 필드를 유지합니다. 비밀번호 등록은 계속 credential을 재발급합니다. 검증·잠금·감사 및 실제 변경의 동시 수정/atomic 저장·비밀 정리를 유지하며 비교 대상은 로컬 metadata로, 서버 sudoers를 검사하지 않습니다.

로그인 계정별 무비밀번호 sudo 대상을 저장하려면 다음과 같이 실행합니다.

```bash
sshw privilege set web --account ops --user service --no-password
sshw run web "id -un" --user ops --as-root
```

이후 `--as-root`는 저장된 설정에 따라 `sudo -n`을 사용하며 privilege 비밀번호를 입력·저장·조회하지 않습니다. 일반 실행은 계속 로그인 계정을 사용합니다. `privilege set --no-password`는 `--method su`, `--password-stdin`과 함께 쓸 수 없습니다. 다시 비밀번호 방식으로 바꾸려면 set에서 `--no-password`를 생략하세요. 기존 설정 변경에는 확인 또는 `--force`가 필요하며, 이전 비밀번호는 설정 저장이 성공한 뒤에만 정리합니다. doctor와 삭제 명령은 존재하지 않는 비밀번호 항목을 조회·삭제하지 않습니다. 실제 sudo 권한은 서버에서 허용해야 하며, 거부되면 비밀번호 방식으로 재시도하지 않고 기존 원격 실패 상태를 반환합니다.

## Host Trust Flow

Host key 검증은 fail-closed이며, 알 수 없거나 변경된 key는 조용히 허용하지 않습니다. 신뢰한 key는 활성 home의 `known_hosts`에 저장됩니다.

```bash
sshw trust server-alpha
sshw trust server-alpha --yes
```

`trust`는 algorithm과 SHA256 fingerprint를 출력하고 `--yes`가 없으면 확인하며, 쓰기 직전에 fingerprint를 다시 검증합니다. 흐름 중 key가 바뀌면 새 key를 저장하지 않고 실패합니다.

`--yes`가 없으면 서버 조회 뒤·SSH 접속 전에 확인 가능 여부를 검사합니다. 비대화형 stdin은 접속할 수 없는 서버에서도 먼저 config/3과 interactive terminal/`--yes` 안내로 중단합니다. `--yes`의 연결 및 지문 재검증은 유지합니다. 라이브러리의 `Prompter`는 입력을 읽지 않는 기본 `ensure_confirmation_available` hook을 재정의할 수 있으며 기존 구현은 그대로 사용할 수 있습니다.

## 명령

```bash
sshw add <name> --host <host> [--port <port>] --user <user> [--auth password|agent] [--password-stdin] [--force] [--replace] [--json]
sshw list [--json]
sshw show <name> [--json]
sshw default [<name>] [--json]
sshw trust <name> [--yes] [--json]
sshw run [<name>] "<command>" [--user <registered-user>] [--json|--stream] [--yes] [--as-root [--no-password]]
sshw put [<name>] <local> <remote> [--user <registered-user>] [--atomic] [--mode <octal>] [--json] [--yes]
sshw get [<name>] <remote> <local> [--user <registered-user>] [--json] [--yes]
sshw remove <name> [--yes] [--json]
sshw doctor [--json]
sshw account add <name> <user> [--auth password|agent] [--password-stdin] [--force] [--json]
sshw account list <name> [--json]
sshw account show <name> <user> [--json]
sshw account default <name> <user> [--json]
sshw account remove <name> <user> [--yes] [--json]
sshw privilege <set|show|clear> ... [--json]
sshw profile <add|list|show|default|remove> ... [--json]
sshw policy <init|show|enable|disable|allow|remove|check> ... [--json]
```

`add`, `account add`, `profile add`는 `--force`로 갱신을 비대화형 승인합니다. 같은 host/port의 서버를 갱신하면 다른 계정과 해당 계정의 privilege 설정을 보존하고 선택한 login credential만 갱신합니다. host/port 변경은 `--replace`가 필요하며 전체 계정·privilege 설정을 초기화하고 오래된 credential을 정리합니다. 이전 endpoint를 유지하려면 새 서버 이름을 쓰세요. `--force`만으로 endpoint 교체를 승인하지 않습니다.

`add`·`account add`는 확인 입력 전에 `--auth agent --password-stdin` 충돌을 config/3으로 안내합니다. 기존 설정·대상·endpoint 교체 검증의 우선순위는 유지합니다. 유효한 갱신의 확인 또는 `--force`, 비밀번호 입력과 credential 정리는 그대로입니다.

`add --user`는 지정한 계정을 등록하고 기본 로그인 계정으로 선택합니다. 갱신으로 기본 계정이 바뀌면 확인 문구와 human 결과에 이전·새 계정을 표시하고, JSON에 `user` 및 `default_change`(`resource:"account"`, `previous`, `current`)를 추가합니다. 같은 기본 계정의 갱신에는 전환 정보를 붙이지 않습니다. 저장 후 자격 증명 정리만 실패해도 전환은 `mutation.default_change`에 남습니다. 기존 기본값을 유지하며 계정을 추가하려면 `account add`를 사용하세요.

전역 플래그(모든 명령에서 사용): `--home <path>`, `--profile <name>`, `--policy`, `--timeout <seconds>`.

`--timeout`은 연결 수립 이후 `run`/`put`/`get`의 원격 작업 단계에 적용되는 절대 타임아웃(초)이며, 출력이나 전송 진행이 있어도 기한이 연장되지 않습니다. 플래그를 생략하면 기본 900초, `0`은 기한을 명시적으로 해제합니다. DNS 해석, 해석된 모든 주소에 대한 연결 시도, TCP 수립, SSH handshake는 하나의 15초 연결 deadline을 공유합니다. `run`은 입력이 없어도 채널 stdin을 닫고 stdout/stderr를 동시에 배출합니다. 두 출력 합계가 16 MiB를 넘으면 잘린 성공 출력을 반환하지 않고 exit 5로 실패합니다. 원격 명령의 부작용은 이미 발생했을 수 있으므로 비멱등 작업을 무작정 재시도하지 마세요.

`run`/`put`/`get`에서 이름을 생략하면 설정된 기본 서버를 사용합니다. `--user`를 생략하면 해당 server의 default account를 사용합니다.

## 업로드 보호·실시간 출력·전송 사전 검사

일반 `put/get`의 SCP 실패는 원격 파일 열기·데이터 전송·응답/EOF·채널 종료·완료 확인 중 실제 실패 단계와 로그인 계정, endpoint, local/remote 경로, 마스킹한 native 원인을 표시합니다. 원격 경로와 로그인 계정의 읽기/쓰기 권한, 부모 디렉터리, 서버 SCP 지원 등을 확인하세요. SCP 라이브러리의 일반 오류만으로 파일 부재와 권한 거부를 구분할 수는 없습니다. 중간 업로드 실패는 원격 목적지가 변경됐을 수 있으므로 상태를 확인한 뒤 재시도하세요. 기존 오류 타입·코드와 JSON 원인, timeout 및 SCP 완료 확인을 유지하며 다운로드는 검증된 staging을 최종 반영하기 전까지 기존 로컬 파일을 보존합니다. 자동 권한 변경·승격·추가 접속·재시도는 수행하지 않습니다. `--atomic`의 단계별 상세 진단과 Git Bash/MSYS 경로 안내도 유지합니다.

원자적 업로드 오류는 실패 단계·실제 원인·목적지와 임시 경로·정리 및 교체 상태를 함께 표시합니다. 생성 응답이 유실되면 원격 파일이 생겼더라도 생성 성공을 확인할 수 없으므로 해당 경로를 자동 삭제하지 않습니다. 경로와 소유권을 확인한 뒤 재시도하세요. 생성 성공이 확인된 임시 파일만 연결과 권한이 허용하는 범위에서 실패 시 정리합니다.

```bash
sshw policy check-put web ./app /srv/app/app --atomic --json
sshw put web ./app /srv/app/app --atomic --mode 755
sshw policy check-get web /var/log/app.log ./app.log --json
sshw run web "./long-build" --stream
```

`put --atomic`은 목적지 디렉터리의 임시 파일에 올리고 크기·닫기를 확인한 뒤 원자적으로 교체합니다. `posix-rename@openssh.com` 확장을 지원하는 SFTP 서버와 부모 디렉터리 쓰기 권한이 필요하며, 정책도 부모 디렉터리 업로드를 허용해야 합니다. 미지원 서버에서는 일반 덮어쓰기로 후퇴하지 않습니다. 교체 전 실패는 기존 파일을 보존하고 임시 파일을 정리하지만, 연결 단절 시 정리가 실패하거나 교체 결과가 미확정일 수 있습니다. 오류에 나온 경로를 확인한 뒤 재시도하세요. 기존 inode·소유권·ACL은 보존하지 않으며 mode는 기본600 또는 명시한 값입니다. 목적지 symlink는 따라가지 않고 교체합니다. 전원 장애 내구성이나 관리자 권한 상승은 제공하지 않으며 일반 `put`은 기존 SCP 동작을 유지합니다.

`run --stream`은 완성된 줄을 비밀 마스킹 후 실행 중에 출력합니다. 데이터가 여러 번에 나뉘어 도착해도 UTF8·비밀·PEM 블록을 유지해서 처리하고, 개행 없는 줄은 종료까지 기다립니다. 알려진 비밀 자체가 여러 줄이면 보수적으로 버퍼링합니다. 일반 실행과 sudo를 지원하며 JSON·su PTY 조합은 거부합니다. 실패하면 완료 미확정 안내와 함께 비밀을 마스킹한 실제 원인을 표시합니다. 기존16MiB 상한과 exit code는 유지하고 이미 출력한 내용은 실패 시 반복하지 않습니다. 일반 실행과 sudo는 기본 출력·JSON·스트리밍 모두 채널 오류 후 SSH 정리 대기를 짧게 제한합니다. 이것이 원격 프로세스의 종료를 확인했다는 뜻은 아닙니다.

`policy check-put/check-get`은 실제 전송과 같은 인자 순서·`--user`·`--yes`를 사용합니다. 공통 검사는 실제 전송과 같은 순서로 첫 실패를 알려주며, `check-put --atomic`은 임시 파일 디렉터리 정책도 검사합니다. 접근 검사를 통과하면 `put`(`--atomic` 포함)과 `check-put` 모두 업로드 파일을 읽기 전용으로 열어 읽을 수 있는 일반 파일인지 확인하고 내용은 읽지 않습니다. 실제 `put`은 계정 비밀번호 조회 전에 검사하므로 인증 정보가 없어도 잘못된 원본은 먼저 io/6으로 알려줍니다. JSON의 `access_allowed`는 접근 검사, `local_file_checked`·`local_file_ready`는 파일 검사 여부·결과를 구분하며 `allowed`는 평가한 로컬 검사 전체의 결과입니다. 실제 전송은 파일을 다시 열고 해당 handle로 검증·전송하므로 사전 검사가 이후 상태까지 보장하지 않습니다. 사전 검사는 SSH·credential·원격 OS 권한·서버 확장을 확인하지 않습니다. `--yes`는 확인 옵션일 뿐 원격 권한을 부여하지 않습니다.

`get`의 로컬 목적지에는 파일 경로를 지정하세요. 실제 실행과 `policy check-get` 모두 기존 디렉터리 목적지와 잘못된 로컬 부모 경로를 연결 전에 거부하고 해당 경로를 표시합니다. `--yes`는 파일 교체 확인이며 디렉터리를 파일 목적지로 바꾸지 않습니다. 없는 부모 디렉터리는 실제 다운로드 때만 생성합니다. 사전 검사는 파일을 만들거나 로컬 쓰기 권한을 검증하지 않습니다. `--yes`로 목적지 심볼릭 링크를 교체할 때는 링크가 가리키는 원본을 덮어쓰지 않습니다. 임시 파일 쓰기와 최종 반영 전에 목적지를 다시 검사하며, 반영 전 실패하면 기존 목적지를 보존하고 임시 파일을 정리합니다.

## Windows 셸 경로

Git Bash/MSYS는 Windows 네이티브 실행 파일에 전달하는 경로 형태의 인자를 자동 변환합니다. 이 과정에서 `/tmp/artifact.tgz` 같은 원격 POSIX 경로가 `sshw`에 도달하기 전에 로컬 Windows 경로로 바뀔 수 있습니다. 원격 절대경로 앞에 `remote:`를 붙이면 인자를 리터럴로 전달할 수 있습니다. sshw는 prefix를 제거한 뒤 safety, policy, audit, JSON, SSH 처리를 적용합니다.

```bash
sshw put server-alpha 'C:/path/artifact.tgz' 'remote:/tmp/artifact.tgz'
sshw get server-alpha 'remote:/var/log/app.log' 'C:/path/app.log'
```

suffix는 POSIX 절대경로(`remote:/tmp/file`), Windows drive 절대경로(`remote:C:/Data/file` 또는 `remote:C:\Data\file`), UNC 경로여야 합니다. `remote:` 또는 `remote:tmp/file`처럼 비어 있거나 상대경로인 리터럴은 SSH 전에 config 오류 3으로 거부됩니다. prefix가 없는 기존 절대·상대 원격경로 동작은 유지됩니다. 선두 `remote:` 형식은 예약되어 있으므로 실제 상대 파일명이 `remote:`로 시작하면 `./remote:name`으로 작성합니다.

대안으로 Git Bash 호출 전체에 `MSYS2_ARG_CONV_EXCL='*'`를 설정할 수 있습니다. PowerShell에서는 경로 변환이 없으므로 raw 원격 절대경로와 명시적 리터럴을 모두 사용할 수 있습니다.

```powershell
sshw put server-alpha 'C:\path\artifact.tgz' '/tmp/artifact.tgz'
sshw put server-alpha 'C:\path\artifact.tgz' 'remote:/tmp/artifact.tgz'
```

Windows는 로컬 경로로 `C:\path\file`과 `C:/path/file`을 모두 허용합니다. 위 예시는 PowerShell의 네이티브 표기인 역슬래시를 사용했습니다. 로컬 파일이 없거나 읽을 수 없으면 I/O 실패(exit 6)입니다. MSYS가 이미 변환한 raw 원격경로는 이후 SSH 실패(exit 5)로 나타날 수 있으며, 이때 `remote:` 또는 변환 비활성화 힌트를 제공합니다.

추적 중인 소스 트리를 전송할 때는 작업 디렉터리나 `target`을 직접 압축하지 말고 Git에서 아카이브를 생성하세요.

```powershell
$archive = Join-Path $env:TEMP 'sshw-src.tgz'
git archive --format=tar.gz --output="$archive" HEAD
sshw put server-alpha "$archive" 'remote:/tmp/sshw-src.tgz'
```

`git archive`는 선택한 커밋에서 Git이 추적하는 파일만 포함하므로 `.git`, `target`, 미추적 파일, 커밋하지 않은 변경 사항은 제외됩니다. 셸이 `tar`를 Windows bsdtar, Git의 GNU tar, WSL 실행 파일 중 무엇으로 해석하는지에도 의존하지 않습니다.

`run`은 완료 후 모은 출력을 반환합니다. 사람이 사용하는 TTY에는 선택한 home과 작업 시작 안내를 표시합니다. 일반 run/sudo의 읽기 실패·타임아웃에서는 redaction한 `partial_output`과 `completion_confirmed:false`를 제공할 수 있습니다. 여전히 실패이며 무조건 재시도하면 안 됩니다. 알려진 비밀번호가 캡처 경계에서 잘린 경우도 보수적으로 가립니다. su prompt/marker 실패에는 이 부분 출력 계약을 적용하지 않습니다. 로컬 stdin은 원격 명령에 전달하지 않습니다.

실행 파일은 `sshw put web ./app /srv/app/app --mode 755`처럼 권한을 명시하세요. 새 파일의 기본 권한은 600이고 특수 권한 비트는 거부합니다. mode를 명시하면 기존 파일의 권한도 바꾸고 시각 정보는 전송 시각으로 설정합니다. 일반 업로드는 서버의 기존 권한 유지 동작을 따릅니다. 파일 전송 자체의 권한 상승은 제공하지 않습니다. 원격의 기존 파일은 업로드로 교체될 수 있고, 로컬의 기존 파일을 다운로드로 덮어쓰려면 `--yes`가 필요합니다.

## Safety Rails

`rm -rf`, `sudo`, `chmod -R`, `chown -R`, `pm2 delete`, `/etc`에 대한 명백한 쓰기 같은 위험 명령은 `--yes`가 필요합니다. `sshw get`은 `--yes` 없이 기존 로컬 파일을 덮어쓰지 않습니다. `sshw put`은 서버가 SCP mode를 존중하면 owner-only 권한으로 원격 파일을 만듭니다. 이것은 safety rail이지 보안 샌드박스가 아닙니다.

## Policy 적용

JSON을 직접 편집하지 않고 기존 정책 형식을 관리할 수 있습니다.

```bash
sshw policy init
sshw policy allow command "systemctl status app"
sshw policy allow put /srv/app
sshw policy allow account web ops
sshw policy enable
sshw policy check web "systemctl status app" --user ops --json
sshw policy show --json
```

`init`은 비활성 빈 정책을 만들며 기존 파일은 덮어쓰지 않습니다. `allow`는 항목만 추가하고, `remove`는 정확히 일치하는 항목만 제거합니다. 다른 규칙이 남아 있으면 계속 허용될 수 있습니다. `enable`/`disable`은 저장된 정책 활성 설정을 바꿉니다. 수정 결과는 추가됨·이미 있음·삭제됨·항목 없음·변경 없음을 구분하고 JSON에 `changed`와 `change`(`created`, `added`, `already_present`, `removed`, `not_found`, `updated`, `unchanged`)를 표시합니다. 변경 없는 요청도 성공하며 파일 저장을 생략합니다. 변경 명령의 home 잠금과 audit을 유지하고 실제 내용 변경에는 revision 검사와 원자적 저장을 사용하며, 명령 전체를 audit detail에 복사하지 않습니다. 기존 v1 정책은 계속 읽을 수 있고 실제 내용이 바뀔 때 v2로 저장됩니다.

정책 관리 출력은 파일 존재 여부·저장된 `enabled`·현재 호출의 적용 상태를 구분합니다. JSON에는 `present`·`enforced`와 `--policy` 사용 여부인 `forced`가 담깁니다. 파일이 없으면 미설정으로 표시하고 같은 home/profile의 `sshw policy init`을 안내합니다. 파일 없는 상태의 강제 적용은 기존처럼 fail-closed입니다. `disable`은 저장 설정을 바꾸며 `--policy`를 전달한 호출에는 계속 정책이 강제 적용됩니다. 저장된 비활성 설정을 사용하려면 같은 home/profile을 유지하면서 해당 옵션을 제거하세요.

`check`·`check-put`·`check-get`은 human 출력과 JSON의 `policy` 객체(`path`, `enforced`, `forced`, `checks`)에 정책 적용 상태와 매칭 규칙을 표시합니다. 각 판정에는 `allowed`·`reason`이 있고 규칙에 매칭됐다면 `matched_rule`·`match_type`(`program`, `exact`, `prefix`, `path`, `account`)도 있습니다. 파일 순서상 처음 매칭된 규칙을 표시하며, 정책 비활성·기본 계정의 암묵 허용·쉘 구문의 정확한 전체 명령 규칙 요구·규칙 불일치·상위 경로 탐색을 구분합니다. 원자적 업로드는 부모 경로 규칙을 `atomic_parent`로 별도 설명합니다. 실제 검사와 같은 정책 snapshot과 matcher를 사용하고 설명의 비밀도 마스킹합니다. 이 정책 판정은 safety·계정 존재·로컬 파일 준비와 독립적이며, 전체 결과는 기존 `allowed`·`reasons`·종료 코드로 판단합니다. 로컬 검사는 credential·SSH·sudoers를 검증하지 않습니다.

`policy check [server] "<command>"`는 `run`과 같은 인자 순서와 기본 서버를 사용합니다. 예를 들어 `sshw policy check "uptime" --json`으로 기본 서버를 검사할 수 있습니다. 공통 로컬 검사 순서를 실행과 공유하므로 검사한 항목의 첫 실패 이유와 종료 코드가 일치하며, 사전 검사는 추가 차단 이유도 계속 표시합니다. 설정·정책 로딩 오류와 첫 실패인 계정 선택 오류는 기존 오류 형식을 유지합니다. 승격 메타데이터는 비밀번호를 읽지 않고 검사하며 인증·연결 실패 여부는 검사 대상이 아닙니다.


policy는 **기본 off**입니다. 호출별로 `--policy`로 켜거나, home의 `policy.json`에 `"enabled": true`로 영속 적용합니다.

```json
{
  "version": 2,
  "enabled": true,
  "allow_commands": ["uptime", "systemctl status *"],
  "allow_put_paths": ["/srv/app"],
  "allow_get_paths": ["/var/log"],
  "allow_accounts": [
    { "server": "server-alpha", "user": "ops" }
  ]
}
```

적용 시 default account는 계속 허용되지만 non-default `--user`는 구조화된 `allow_accounts`의 exact server/user 항목과 일치해야 합니다. 기존 policy v1은 계속 유효하며 default account만 허용합니다. `run` 명령은 `allow_commands`에, `put`/`get` 경로는 `allow_put_paths`/`allow_get_paths` 하위에 매칭돼야 합니다. 쉘 메타문자(`;`, `&`, `|`, `` ` ``, `$`, `(`, `)`, `<`, `>`)를 포함한 명령은 **정확히 일치하는** allowlist 항목에만 매칭됩니다. `..`를 포함한 전송 경로는 거부됩니다. 거부된 작업은 exit code 7(`policy`)을 반환합니다.

`policy allow put/get`은 아무 접근도 허용하지 않는 `/`·반복 슬래시 규칙을 거절하고 `/srv/app`이나 `/var/log`처럼 구체적인 디렉터리를 지정하도록 안내합니다. 기존 파일의 루트-only 항목은 계속 비활성이며 `policy remove`로 제거할 수 있습니다. Windows drive 절대 경로(`C:\Data`, `C:/Data`)와 `\\`로 시작하는 UNC 경로는 두 구분자의 하위 경로·끝 구분자를 인식하고 대소문자·디렉터리 경계를 유지합니다. POSIX·상대 경로의 역슬래시는 문자 그대로 처리하며 SSH에 전달하는 경로를 바꾸거나 canonicalize하지 않습니다. `put --atomic`의 실제 SFTP 목적지는 계속 forward slash를 요구합니다.

policy는 fail-closed입니다. `--policy`인데 파일이 없으면 에러이고, 파일이 있으나 유효하지 않으면 항상 에러입니다. `"enabled": false`인 비활성 policy도 unknown field나 지원하지 않는 version이 있으면 거부됩니다. 의도적으로 사용하지 않는 잘못된 파일은 원격 작업 전에 이름을 바꾸거나 제거하세요.

명령 규칙에는 세 가지 형태가 있습니다. `systemctl status app` 같은 전체 명령은 정확히 일치해야 하고, `systemctl status *`처럼 끝에 `*`가 있으면 문자열 앞부분으로 매칭합니다. `cat`처럼 프로그램 이름만 허용하면 셸 메타문자가 없는 명령에서 그 프로그램의 모든 인자를 허용합니다. 프로그램 이름 규칙은 접근 가능한 파일·하위 프로세스 등 그 프로그램의 실행권을 위임합니다. 정확한 명령 규칙도 프로그램 내부의 동작을 격리하지는 않습니다. `allow_put_paths`/`allow_get_paths`는 원격 경로를 문자열 앞부분으로 매칭하고 `..`를 거부하지만, 원격 심볼릭 링크를 따라가거나 실제 경로로 검증하지는 않습니다. 허용된 경로 안의 링크가 다른 위치를 가리킬 수 있으므로 경로 허용 목록은 원격 샌드박스가 아닙니다.

## Audit Log

변경/실행 작업(`add`, `remove`, `trust`, `default`, `account add`, `account default`, `account remove`, `profile add`, `profile default`, `profile remove`, `run`, `put`, `get`, `privilege set`, `privilege clear`)은 `audit.jsonl`에 줄당 JSON 객체로 append됩니다. home 범위 작업은 active home의 로그를 사용하고, 전역 profile registry 변경은 추가·선택·제거 대상과 무관하게 내장 default home의 로그에 일관되게 기록됩니다.

```json
{"time_ms":1700000000000,"action":"run","server":"web","user":"ops","status":"ok","exit_code":0,"detail":"uptime"}
```

`user`는 선택된 login account를 기록합니다. `run`의 `detail`은 인자가 아닌 프로그램 이름만 기록합니다. 서버명·user·경로·detail은 best-effort로 redaction됩니다. 시도한 `run`/`put`/`get`의 policy 준비가 실패한 경우도 error 상태로 기록합니다. read-only 명령(`list`, `show`, `account list`, `account show`, `doctor`, `profile list`, `profile show`)은 기록하지 않습니다. audit 쓰기는 best-effort입니다. record lock이 바쁘면 100밀리초 동안 재시도한 뒤 해당 레코드를 생략하며 작업 자체는 실패시키지 않습니다. 파일은 Unix에서 owner-only(Windows는 best-effort)입니다. append-only이지만 tamper-evident가 아닙니다 — 무결성 체인이나 서명이 없고, home을 쓸 수 있는 누구나 항목을 수정·삭제할 수 있습니다. `audit.jsonl`은 민감 파일로 취급하세요.

## 출력 redaction

대화형 원격 작업 시작 메시지에도 home 표시를 마스킹합니다. 인증 뒤 SSH 세션·PTY·명령 입출력·완료 확인이 실패하면 단계와 로그인 계정/endpoint, 원인을 보여주며 원격 명령과 입력 비밀은 진단에 추가하지 않습니다. partial output·원래 오류 분류와 완료 미확정 의미는 유지합니다. `known_hosts`를 읽거나 파싱할 수 없을 때도 원인과 파일 점검 안내를 표시하며 host-key 확인을 우회하거나 자동 교체하지 않습니다.

확인창도 서버·로그인 계정·승격 대상 이름을 각각 마스킹해 작업 설명과 `[y/N]`를 보존합니다. 확인 입력을 읽지 못하면 원래 OS 원인과 해당 작업의 `--yes` 또는 `--force` 옵션을 안내합니다. 이 옵션은 해당 작업을 확인하려는 경우에만 사용하며, 입력이 종료되거나 거절됐다고 자동 승인하지 않습니다.

`run`의 stdout/stderr/JSON에 echo된 command는 best-effort redaction을 거칩니다. PEM 개인키 블록, 흔한 비밀 keyword의 `keyword=value`/`keyword: value`, bearer 토큰을 마스킹합니다. 작업을 위해 읽은 정확한 login 비밀번호와 설정된 privilege 비밀번호가 이 필드에 그대로 나타나면 추가로 마스킹합니다. 매우 짧거나 흔한 비밀번호는 관련 없는 출력까지 과도하게 마스킹할 수 있으며, 이 경우 출력 충실도보다 비밀 보호를 우선합니다. 모든 쉘 표현을 이해하지는 못하고 여러 줄에 걸친 비밀은 마스킹되지 않을 수 있으므로 비밀을 인라인으로 넘기지 마세요.

## Doctor

설정 파일을 읽거나 JSON·형식을 검사하다 실패하면 파일 경로와 원인을 각각 마스킹하고 해당 파일의 접근 권한·UTF-8·구문/지원 필드 점검을 안내합니다. 민감 패턴이 있는 경로 때문에 오류 원인까지 잘리지 않으며, 진단 과정에서 파일을 초기화하거나 형식 검사를 완화하지 않습니다.

`local_checks_passed`는 로컬 검사 결과이고 `issues`에는 문제와 다음 조치가 담깁니다. SSH agent와 누락된 privilege credential도 확인합니다. `connection_tested:false`이며 원격 접속·host key 일치·sudoers를 검사하지는 않습니다. `ok:true`는 진단 실행 성공을 뜻합니다.

감사 파일이 없으면 기존 부모 폴더에 비밀 없는 private 임시 파일을 생성하고 즉시 정리해 새 로그의 생성 권한을 확인합니다. Unix probe는 owner-only이며 기존 `audit.jsonl`이나 없는 부모는 만들지 않습니다. 기존 로그는 append용 열기만 확인하고 내용·권한을 바꾸거나 레코드를 추가하지 않습니다. 실패하면 경로·원인·복구 방법을 표시하고 JSON `audit_message`에 마스킹한 원인을 제공합니다(성공은 null). 파일 생성 probe는 부모 폴더의 mtime을 바꿀 수 있습니다. 이 시점의 준비 상태가 이후 기록/lock 성공을 보장하지는 않으며, 실제 기록 실패의 best-effort 의미와 doctor exit0/`ok:true`는 유지합니다.

host key 로컬 검사는 실제 연결과 공유하는 파서로 활성 home의 `known_hosts`를 읽고 key 데이터와 서버별 등록 여부를 확인합니다. 해시 host와 비표준 포트도 같은 매칭 규칙을 사용합니다. JSON `host_trust`의 `entry_present`는 등록 있음/없음에 true/false, 읽기·파싱·검사 실패에는 null이며 `key_match_checked`는 항상 false입니다. 빈 파일이나 다른 서버의 등록만으로 로컬 검사가 통과하지 않습니다. 읽기 불가·손상 파일은 먼저 수정한 뒤 제안된 trust 명령을 실행하세요. 등록 있음도 현재 원격 key와의 일치를 보장하지 않으며 실제 연결에서는 기존처럼 검증합니다.

`run`·`put`·`get`의 로그인 자격 증명 조회 실패에는 선택한 서버/계정과 마스킹한 백엔드 원인을 표시합니다. 세션 전용 home은 실행 시 `SSHW_PASSWORD`가 필요합니다. 저장 백엔드는 `sshw doctor`로 상태를 확인하고 항목이 없을 때 `account add`로 비밀번호를 재등록하도록 안내합니다. 같은 home/profile을 선택하고 갱신을 확인하세요. 비대화형 입력은 안내 명령의 `--` 앞에 `--force`·`--password-stdin`을 넣어 비밀 관리자 pipe를 사용합니다. 계정의 기존 승격 설정은 유지하며 비밀번호를 명령 인자에 넣지 않습니다.

`run --as-root`의 승격 비밀번호 조회 실패에도 서버/로그인 계정·sudo/su 방식·승격 대상과 마스킹한 백엔드 원인을 표시합니다. 세션 전용은 로그인 비밀번호와 별개인 `SSHW_PRIVILEGE_PASSWORD`가 필요합니다. 저장 백엔드는 `sshw doctor`로 먼저 상태를 확인하고 항목이 없으면 기존 계정·방식·대상을 보존하는 `privilege set` 안내 명령으로 재등록합니다. 같은 home/profile을 선택하고 갱신을 확인하거나 `--` 앞에 `--force`·`--password-stdin`을 넣으세요. 비밀번호는 명령 인자에 넣지 않습니다. 로컬 조회 실패의 auth/4·JSON causes, 무비밀번호 승격 및 원격 sudo/su 동작은 유지합니다.

승격 대상의 빈 값·공백만 있는 값·제어 문자는 등록과 v1/v2 설정 로딩에서 config/3으로 거부합니다. 등록은 확인이나 비밀번호 입력 전에 중단하며, 잘못된 대상이 저장된 기존 파일은 `doctor`의 config 진단과 표시된 경로를 확인해 수정하세요. 같은 설정을 사용하는 사전 검사·실행도 거부합니다. 원격 계정의 존재나 sudoers 허용 여부를 검사하는 기능은 아닙니다.

누락된 승격 비밀번호의 복구 안내는 저장된 로그인 계정·승격 방식·대상을 유지합니다. 저장 가능한 백엔드는 재등록 명령을 제공하며, 기존 `--home`/`--profile` 선택으로 실행하세요. 인용 구문은 Windows에서 PowerShell, 다른 OS에서 POSIX 셸 기준입니다. 갱신 확인이 필요하며 비대화형 실행은 명령의 `--` 앞에 `--force`를 넣습니다. stdin으로 입력하려면 `--password-stdin`도 `--` 앞에 넣으세요. 세션 전용 백엔드는 재등록으로 비밀번호가 유지되지 않으므로 `SSHW_PRIVILEGE_PASSWORD`를 실행 시 제공하도록 안내합니다. 비밀번호를 명령 인자에 넣지 마세요.

```bash
sshw doctor
sshw doctor --json
```

`doctor`는 해석된 home과 선택 경위, registry/config/known_hosts/policy/audit 경로, registry 유효성과 진단(`registry_valid`, `registry_message`), config 파일 존재 여부, 운영체제, 연결된 libssh2 및 OpenSSL 버전/상태, credential namespace, policy present/valid/enabled, audit 쓰기 가능 여부, credential backend 상태, 그리고 누락된 login credential을 `server/user` 항목으로 보고하는 `missing_credentials`를 제공합니다. 손상된 registry도 `doctor` 실행을 막지 않으며, 명시적 home이 이미 해석되지 않았다면 내장 default home에서 registry 오류를 진단합니다. Windows 기본 빌드에서는 libssh2가 OpenSSL 대신 WinCNG를 사용하므로 `openssl_version`이 `not linked (Windows WinCNG backend)`로 표시될 수 있습니다.

## JSON 오류 계약

`run`·`put`·`get`·`trust`의 연결 준비 실패는 주소 해석·TCP 연결·SSH handshake 중 실패한 단계, host/port, 마스킹한 원래 원인과 다음 조치를 표시합니다. 연결 거부라면 주소/포트·SSH 서비스의 수신 상태·네트워크/방화벽 접근을 확인하세요. `connect timeout budget`은 실제 대기 시간이 아닌 최대 연결 예산이며, 실제 타임아웃/연결 거부는 원인에서 구분합니다. ssh/5·JSON causes 및 연결 deadline/retry·host key 확인·인증 동작은 유지합니다.

`--json`을 지원하는 명령(`add`, `list`, `show`, `trust`, `run`, `put`, `get`, `remove`, `doctor`, `account add`, `account list`, `account show`, `account remove`, `profile list`, `profile show`, `privilege set`, `privilege show`, `privilege clear`)은 런타임 실패 시 구조화된 envelope를 반환합니다.

```json
{"ok":false,"error":{"kind":"config","message":"unknown server 'missing'","exit_code":3}}
```

래핑된 source error가 있으면 `error`에 immediate cause부터 바깥쪽 순서로 전체 redacted cause chain을 담은 선택적 `causes` 배열이 추가됩니다. 추가 cause가 없으면 이 필드는 생략됩니다. 이 값은 안정된 기계 판독 taxonomy가 아니라 진단용 문자열로 취급하세요.

| Kind | Exit code | 의미 |
| --- | ---: | --- |
| `safety` | 2 | safety rail이 차단(보통 `--yes` 필요). |
| `config` | 3 | config/registry/profile이 없거나 잘못됐거나 알 수 없는 항목 참조. |
| `auth` | 4 | credential 조회 또는 인증 준비 실패. |
| `ssh` | 5 | SSH 연결, host key, known_hosts, session, 전송 실패. |
| `io` | 6 | 로컬 파일/파일시스템 처리 실패. |
| `policy` | 7 | policy allowlist가 작업을 거부했거나 policy 적용이 fail-closed. |
| `usage` | 9 | CLI 인자가 잘못됨(알 수 없는 플래그/서브커맨드, 인자 누락/초과). 명령 실행 전에 감지. |
| `unknown` | 1 | 안정 카테고리에 매핑되지 않은 실패. |

`put --json`과 `get --json`은 성공 시 전송 요약을 반환합니다.

```json
{"ok":true,"server":"server-alpha","user":"ops","local":"./app","remote":"/tmp/app","bytes":1234}
```

단일 object를 반환하는 `--json` 성공 응답(`add`, `show`, `trust`, `run`, `put`, `get`, `remove`, `doctor`, `account add`, `account show`, `account remove`, `profile show`, `privilege set`, `privilege show`, `privilege clear`)은 모두 `"ok":true`를 포함해 오류 envelope의 `"ok":false`와 대칭을 이루므로, 소비자가 `ok`로 분기할 수 있습니다. `list`, `account list`, `profile list`는 성공 시 JSON 배열을 반환하며(래핑 object 없음), 실패 시에는 동일한 `{"ok":false,...}` envelope를 출력합니다.

`default`, `account default`, profile 상태 변경과 모든 policy 하위 명령도 `--json`을 지원합니다. 기존 list 명령의 성공 배열 형식은 유지합니다. 완료된 `run`의 `ok:true`는 호환성을 위해 유지하므로 원격 성공은 `command_succeeded` 또는 `exit_status == 0`으로 판단하세요. 정책 검사는 `allowed`, doctor는 `local_checks_passed`를 사용하며 실제 원격 연결을 검사한 것은 아닙니다.

등록된 계정의 저장된 승격 설정이 이미 없으면 `privilege clear`는 확인 입력·설정 재저장 없이 성공합니다. JSON은 기존 `action:"cleared"`·server/account와 `changed:false`/`change:"unchanged"`를 표시하고, 실제 해제는 `true`/`"removed"`입니다. unknown target·잘못된 설정 오류와 lock/audit는 유지합니다. 실제 해제의 확인·비밀 삭제·부분 적용 안내는 그대로이며, 저장된 로컬 설정만 해제하므로 서버 sudoers와 기존 승격 옵션 정책은 바꾸지 않습니다.

잠금·설정/프로필 registry 저장 오류는 실패한 경로·작업 단계·마스킹한 원인·복구 방법을 일반/JSON 메시지에 표시합니다. 안내된 파일/부모 권한·파일 종류·파일시스템·잠금 보유 작업을 확인하세요. 기존 exit·JSON causes·timeout·동시 변경 검사·atomic write는 유지합니다. 저장 후 부모 디렉터리 sync가 실패하면 이미 저장됐음을 표시하므로 재시도 전에 상태를 확인하세요. 원래 published marker와 자격 증명 정리 판단도 유지합니다.

`default <이름>`·`account default <서버> <계정>`·`profile default <이름>`은 이미 선택된 기본값이면 설정/registry를 다시 쓰지 않습니다. 일반 출력은 변경 없음을 표시하고, JSON은 기존 action/대상 필드와 함께 `changed:false`/`change:"unchanged"`를 제공합니다. 실제 변경은 `true`/`"updated"`입니다. no-op은 원본 bytes·mtime·v1 형식을 보존하며 대상 검증·lock·감사 기록은 유지합니다. 이미 기본값인 프로필도 대상이 손상됐으면 거절하고, 조회 전용 `default` 응답은 그대로입니다.

빈 값·공백뿐인 원격 명령은 `run`과 `policy check`에서 입력 오류(usage/9)로 거절합니다. 빈 로컬 원본/목적지와 원격 경로도 `put/get`과 `policy check-put/get`에서 자격 증명 조회·SSH 전에 같은 방식으로 거절합니다. 변수를 확인하고 명령·경로를 인용하세요. 예: `sshw run web "uptime"`, `sshw put web ./app /srv/app/app`. 원본 값을 trim하거나 바꾸지 않으며 공백이 들어간 경로와 공백만으로 된 파일명도 문자 그대로 유지합니다. 기존 설정/정책 로딩·서버 선택 오류의 우선순위도 유지합니다.

`--password-stdin`은 비밀 관리자 pipe나 파일 redirection처럼 리디렉션된 stdin만 사용합니다. stdin이 터미널이면 비밀번호를 읽기 전에 auth/4로 거절합니다. 숨김 터미널 입력을 쓰려면 옵션을 생략하세요. 입력 방식을 자동 전환하지 않으며 비밀번호를 인자에 넣으면 안 됩니다. 기존 EOF 처리·마지막 LF/CRLF 하나 제거·로그인 비밀번호 내부 줄바꿈·승격 비밀번호 single-line 검증은 유지합니다.

Doctor JSON의 `credential_checks`는 비밀번호를 사용하는 로그인/승격 항목별로 `server`·로그인 `user`·`purpose`·`status`·`message`와 필요 시 `next_step`을 표시합니다. 상태는 로컬 조회 성공 `ready`, 확인된 항목 부재 `missing`, 부재를 확인하지 못한 조회 실패 `unavailable`, 실행의 승격 검사와 같은 빈 비밀번호·CR/LF 형식 오류 `invalid`입니다. `missing_credentials`의 배열 형식은 유지하며 확인된 로그인 부재만 포함합니다. 백엔드 장애는 접근을 복구하고 doctor를 재실행한 뒤 재등록 여부를 판단하도록 안내합니다. Agent 로그인·무비밀번호 승격은 비밀번호를 조회하지 않습니다. 비밀번호 내용은 출력하지 않으며 로컬 조회 성공이 원격 인증 성공을 뜻하지 않습니다. Doctor의 exit0/`ok:true`는 유지하므로 조치 필요 여부는 `local_checks_passed`와 `issues`로 판단하세요.

필수 작업 인자가 없으면 home 로딩이나 감사 기록 전에 사용법 오류(exit9)로 거부합니다. `run`·`put`·`get`과 대응 policy 검사에서 서버명은 생략할 수 있지만 명령 또는 source/destination은 반드시 필요합니다. JSON 사용 오류 메시지는 누락된 인자 이름·허용 값·수정 제안을 유지하고 전체 사용 구문과 반복 도움말 문구는 제외합니다. 입력 진단은 렌더링 전에 마스킹하며, 명시적인 도움말·버전 요청은 기존처럼 exit0입니다.

잘못된 CLI 인자는 exit code `9`(`usage`)로 끝나며, `safety`(2)와 분리해 에이전트가 "sshw를 잘못 호출함"과 "safety rail이 차단함"을 구분할 수 있습니다. `--json`이면 usage 오류도 동일한 envelope로 stdout에 출력하고(`{"ok":false,"error":{"kind":"usage",...}}`), 아니면 파서 메시지를 stderr로 보냅니다. `--help`/`--version`은 stdout으로 출력하고 exit `0`입니다.

이 코드들은 sshw 자신의 운영 실패입니다. `run`이 연결에 성공하고 원격 명령 자체가 0이 아닌 코드로 끝나면 sshw는 exit code `8`을 반환합니다 — 원격 상태(예: 매치를 못 찾은 원격 `grep`)가 sshw 실패로 오인되지 않도록 분리한 코드입니다. exit `0`은 원격 명령 성공을 뜻합니다. 실제 원격 상태는 `run --json`의 `exit_status`로, human 모드에서는 stderr의 `note: remote command exited with status N` 줄로 보고됩니다.

## 파일 권한과 원자성

새로 만드는 `servers.json`, `policy.json`, `audit.jsonl`, profile registry, mutation lock 파일은 지원 플랫폼에서 owner-only로 생성됩니다. config·registry 저장은 temp 파일의 권한과 sync를 먼저 완료하고 atomic rename한 뒤, 지원 플랫폼에서 parent directory를 sync합니다. rename 성공 뒤 parent sync가 실패하면 state는 공개됐지만 내구성을 확인하지 못했다고 오류를 반환하며, credential 갱신은 crash 뒤 old/new config 어느 쪽에도 대응하도록 두 세대를 보존합니다. Windows에서는 권한과 directory sync가 best-effort입니다.

서로 협력하는 `sshw` 프로세스는 home 변경을 `.sshw.lock`, profile registry 변경을 `.profiles.lock`으로 직렬화하고, 완전한 audit 레코드는 `audit.jsonl` 자체를 잠가 기록합니다. state mutation lock은 최대 5초만 기다린 뒤 config 오류를 반환하며, audit은 위의 더 짧은 best-effort 상한을 사용합니다. config와 registry 저장은 처음 읽은 revision이 바뀌었으면 거부합니다. 잠금은 advisory이므로 이를 무시하는 다른 프로그램이나 동일 사용자 프로세스의 경쟁·사후 편집까지 막는 변조 방지는 아닙니다.

## 실행 파일 검증

태그 릴리스는 `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `x86_64-apple-darwin`, `aarch64-apple-darwin`용 GitHub Release 산출물과 `SHA256SUMS`를 생성합니다. 릴리스 워크플로우는 GitHub Actions를 commit SHA로, 릴리스 컴파일러를 Rust 1.97.0으로 pin합니다. ZIP과 tar.gz는 릴리스 commit timestamp에서 가져온 결정적 metadata로 패키징하므로 같은 바이너리와 timestamp는 같은 archive bytes를 만듭니다. 별도로 컴파일한 바이너리까지 bit-for-bit 재현된다는 보장은 아니며 자세한 내용은 `SECURITY.md`를 참고하세요.

릴리스 산출물에는 GitHub Artifact Attestation도 생성됩니다. checksum은 파일 무결성을 확인하고, attestation은 빌드 출처(repository, workflow, commit, event)를 확인합니다. 릴리스 산출물을 내려받은 디렉터리에서:

```bash
gh release download vX.Y.Z --repo Lv2dev/sshw
sha256sum -c SHA256SUMS

for artifact in sshw-*.tar.gz sshw-*.zip SHA256SUMS; do
  gh attestation verify "$artifact" -R Lv2dev/sshw
done
```
