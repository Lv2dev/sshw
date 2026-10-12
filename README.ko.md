# sshw

[![CI](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml/badge.svg)](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml)

[English](README.md) | [한국어](README.ko.md)

`sshw`는 SSH로 서버에 접속해 명령을 실행하고 파일을 주고받는 도구입니다.

서버를 `web` 같은 이름으로 등록해 두면, 다음부터는 주소 대신 그 이름을 쓰면 됩니다. 비밀번호는 PC의 비밀번호 저장소에 보관합니다. 로컬 코딩 에이전트도 같은 명령으로 서버를 사용할 수 있습니다.

- 서버에서 명령을 실행하고 결과를 확인합니다. JSON으로 받거나 실행 중 출력을 볼 수도 있습니다.
- 파일을 올리고 내려받습니다. 업로드가 끝난 파일로 기존 파일을 한 번에 교체할 수도 있습니다.
- 한 서버에 여러 로그인 계정을 등록하고, 필요하면 sudo나 su를 사용합니다.
- 프로젝트마다 설정을 따로 두고, 허용할 명령과 파일 경로를 정할 수 있습니다. 작업 기록도 남깁니다.

**사용 전에 읽어주세요.** SSH 통신에 사용하는 라이브러리에 [알려진 보안 문제](SECURITY.md#native-ssh-의존성의-알려진-보안-제한-0130)가 남아 있습니다. sshw는 비밀번호가 실수로 노출되는 일을 줄여 줍니다. 다만 에이전트도 로그인한 계정의 권한으로 작업하므로, 서버를 맡기기 전에 [보안 안내](#보안-안내)를 확인하세요.

[설치](#설치) · [첫 연결](#첫-연결) · [자주 쓰는 명령](#자주-쓰는-명령) · [계정과 sudo](#계정과-sudo) · [프로젝트별 설정](#프로젝트별-설정) · [코딩 에이전트](#코딩-에이전트) · [문제 해결](#문제-해결)

## 설치

### 실행 파일 다운로드

Rust 설치 없이 사용할 수 있습니다. [GitHub Releases](https://github.com/Lv2dev/sshw/releases/latest)에서 운영체제에 맞는 압축 파일을 받으세요.

| 환경 | 압축 파일 |
| --- | --- |
| Windows x64 | `sshw-x86_64-pc-windows-msvc.zip` |
| Linux x64 (GNU/glibc) | `sshw-x86_64-unknown-linux-gnu.tar.gz` |
| macOS, Apple Silicon | `sshw-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `sshw-x86_64-apple-darwin.tar.gz` |

압축을 풀고 실행 파일을 `PATH`에 추가하세요. `PATH`는 터미널이 실행 파일을 찾는 폴더 목록입니다.

- **Windows:** `sshw.exe`를 `C:\Tools\sshw` 같은 폴더에 넣으세요. **계정의 환경 변수 편집**을 열고, 사용자 변수 `Path`에 그 폴더를 추가합니다. 그런 다음 터미널을 새로 여세요.
- **Linux/macOS:** 압축을 푼 폴더에서 아래 명령을 실행하세요. 실행 파일을 `~/.local/bin`에 복사하고, 현재 터미널의 `PATH`에 추가합니다.

  ```sh
  mkdir -p "$HOME/.local/bin"
  cp ./sshw "$HOME/.local/bin/sshw"
  export PATH="$HOME/.local/bin:$PATH"
  ```

  새 터미널에서도 쓰려면 마지막 `export` 줄을 사용하는 셸의 시작 설정 파일에 추가하세요. `~/.local/bin`이 이미 `PATH`에 있다면 추가할 필요가 없습니다.

다음 명령으로 버전이 나오면 설치가 끝난 것입니다.

```sh
sshw --version
```

`PATH`를 설정하기 전에 실행해 볼 수도 있습니다. 압축을 푼 폴더에서 Linux/macOS는 `./sshw --version`, PowerShell은 `.\sshw.exe --version`을 실행하세요.

다운로드한 파일이 배포 원본과 같은지, 어느 빌드에서 만들어졌는지 확인하려면 [파일 검증 방법](docs/reference.ko.md#실행-파일-검증)을 참고하세요.

### Cargo로 설치

crates.io 패키지명은 `sshw-agent`이고 실행 파일명은 `sshw`입니다. Rust 1.89 이상과 아래 빌드 도구가 필요합니다.

```sh
cargo install sshw-agent --locked
sshw --version
```

| 환경 | Cargo 설치에 필요한 도구 |
| --- | --- |
| Windows | Rust MSVC 도구 모음과 Visual C++ Build Tools/Windows SDK |
| Linux | C 컴파일 도구, `pkg-config`, OpenSSL 라이브러리·헤더 |
| macOS | Xcode Command Line Tools, 빌드 도구가 찾을 수 있는 OpenSSL 설치 |

업데이트할 때도 같은 Cargo 명령을 사용합니다.

Linux에서 비밀번호를 저장하려면 GNOME Keyring이나 KWallet 같은 Secret Service가 실행 중이어야 합니다. SSH 키로 로그인한다면 SSH Agent를 사용할 수 있습니다.

소스 코드를 직접 빌드하려면 저장소에서 `cargo build --locked --release`를 실행하세요. 실행 파일은 `target/release`에 만들어집니다.

## 첫 연결

접속할 서버 주소와 SSH 로그인 계정을 준비하세요. 서버와 계정은 미리 만들어져 있어야 합니다. 아래 설정은 에이전트에 맡기기 전에 직접 터미널에서 진행하세요.

### 1. 서버 등록

`web`은 이 서버를 부를 이름입니다. 원하는 이름으로 바꿔도 됩니다. 아래의 `192.0.2.10`에는 실제 서버 주소를, `deploy`에는 로그인 계정을 넣으세요.

```sh
sshw add web --host 192.0.2.10 --user deploy
```

질문이 나오면 **SSH 로그인 비밀번호**를 입력하세요. 입력한 글자는 화면에 보이지 않습니다. 비밀번호는 설정 파일에 쓰지 않고 PC의 비밀번호 저장소에 보관합니다.

등록을 마쳐도 아직 로그인이 되는지 확인한 것은 아닙니다. 실제 접속은 다음 단계에서 확인합니다. 서버가 기본 포트 22를 쓰지 않는다면 `--port 2222`처럼 포트 번호도 붙이세요.

SSH 키로 로그인하려면 위 명령 대신 아래 명령을 사용하세요. SSH Agent에 키가 등록되어 있고, 서버에서도 그 키로 `deploy`에 로그인할 수 있어야 합니다.

```sh
sshw add web --host 192.0.2.10 --user deploy --auth agent
```

이 방식은 이미 실행 중인 SSH Agent를 사용합니다. sshw가 개인키 파일을 직접 읽거나 비밀번호를 저장하지는 않습니다.

비밀 관리 도구에서 비밀번호를 받아 등록하려면 [비밀번호 입력 방법](docs/reference.ko.md#비밀번호-인증)을 참고하세요.

### 2. 서버 지문 확인

```sh
sshw trust web
```

접속하려는 서버가 맞는지 확인하는 단계입니다. 화면에 나온 지문을 서버 관리자 등 신뢰할 수 있는 경로에서 받은 지문과 비교하세요. 일치할 때만 승인하세요.

승인한 키는 저장됩니다. 이후 서버의 키가 바뀌면 sshw가 접속을 거부합니다.

### 3. 간단한 명령 실행

```sh
sshw run web "hostname"
sshw run web "whoami"
```

첫 번째 명령은 서버 이름을, 두 번째는 로그인 계정을 보여 줍니다. 둘 다 정상적으로 나오면 사용할 준비가 된 것입니다.

**서버에서 실행할 명령은 전체를 따옴표로 묶으세요.** 오류가 나면 화면의 안내나 [문제 해결](#문제-해결)을 확인하세요.

## 자주 쓰는 명령

아래 예시는 등록한 서버 이름을 `web`이라고 가정합니다. 서버에서 실행하는 명령은 Linux/Unix 기준입니다. 다른 서버에서는 해당 서버의 셸에서 사용할 수 있는 명령으로 바꾸세요.

| 할 일 | 명령 |
| --- | --- |
| 등록 서버 목록 보기 | `sshw list` |
| 서버 설정 보기 | `sshw show web` |
| 원격 명령 실행 | `sshw run web "uptime"` |
| 실행 중 출력 보기 | `sshw run web "journalctl -n 20" --stream` |
| 파일 올리기 | `sshw put web ./report.txt /tmp/report.txt` |
| 파일 내려받기 | `sshw get web /tmp/report.txt ./downloaded-report.txt` |
| 실행 파일 올리기 | `sshw put web ./app /srv/app/app --mode 755` |
| 업로드가 끝난 뒤 한 번에 파일 교체 | `sshw put web ./app /srv/app/app --atomic --mode 755` |

`put`에는 **내 PC의 파일, 서버의 저장 경로** 순서로 적습니다. `get`은 **서버의 파일, 내 PC의 저장 경로** 순서입니다.

내려받을 위치에 파일이 이미 있으면 `--yes`를 붙여야 덮어씁니다. 일반 업로드는 서버의 기존 파일을 덮어쓸 수 있으니 경로를 확인하세요. `/srv/app`에 올리려면 로그인 계정에 그 폴더의 쓰기 권한이 있어야 합니다. `--yes`로 권한을 얻을 수는 없습니다.

`--atomic`을 붙이면 업로드를 마친 뒤 기존 파일을 새 파일로 교체합니다. 서버가 OpenSSH의 POSIX rename 확장을 지원해야 하고, 저장할 폴더의 쓰기 권한도 필요합니다. 기존 파일의 소유자와 추가 접근 권한(ACL)은 유지되지 않습니다. 오류가 났을 때 파일이 어떻게 처리되는지는 [전송 상세](docs/reference.ko.md#업로드-보호실시간-출력전송-사전-검사)를 확인하세요.

`--stream`은 출력이 한 줄씩 완성될 때 보여 줍니다. `--json`이나 su 방식의 실행과 함께 사용할 수 없습니다.

**Windows Git Bash**는 `/tmp/report.txt` 같은 서버 경로를 Windows 경로로 바꿀 수 있습니다. 서버의 절대 경로 앞에 `remote:`를 붙이면 이를 막을 수 있습니다.

```sh
sshw put web 'C:/work/report.txt' 'remote:/tmp/report.txt'
```

PowerShell에서는 `sshw put web 'C:\work\report.txt' '/tmp/report.txt'`처럼 원격 경로를 그대로 사용할 수 있습니다. [Windows 경로 안내](docs/reference.ko.md#windows-셸-경로)를 참고하세요.

## 계정과 sudo

### 다른 로그인 계정 추가

`ops`로 로그인하려면 그 계정을 먼저 등록하세요. 첫 번째 명령에서 `ops`의 SSH 비밀번호를 입력한 뒤, 두 번째 명령으로 로그인 계정을 확인합니다.

```sh
sshw account add web ops
sshw run web "whoami" --user ops
```

SSH 키를 쓰는 계정은 등록할 때 `--auth agent`를 붙이세요. `--user`에는 미리 등록한 계정만 쓸 수 있습니다.

앞으로 `ops`를 기본 계정으로 쓰려면 `sshw account default web ops`를 실행하세요.

### sudo로 실행

서버가 선택한 계정의 무비밀번호 sudo를 이미 허용한다면:

```sh
sshw run web "id -u" --as-root --no-password
```

sudo에 비밀번호가 필요하다면 **sudo 비밀번호**를 먼저 등록하고 실행합니다.

```sh
sshw privilege set web --method sudo
sshw run web "id -u" --as-root
```

로그인 비밀번호와 sudo 비밀번호는 따로 등록합니다. 두 비밀번호가 같아도 등록은 각각 해야 합니다. sudo 실행을 허용할지는 서버의 sudoers 설정이 결정합니다.

다른 로그인 계정의 sudo를 설정하려면 `privilege set`에 `--account ops`를 붙이세요. 실행할 때는 `--user ops`를 사용합니다. 삭제 같은 위험 작업은 추가로 `--yes`가 필요할 수 있습니다.

sudo 설정을 저장하는 다른 방법과 su 사용법은 [권한 설정 안내](docs/reference.ko.md#권한-상승-명령)를 참고하세요.

## 프로젝트별 설정

처음에는 기본 설정을 그대로 사용해도 됩니다. 설정이 어디에 저장되는지 궁금하면 `sshw doctor`를 실행하세요.

프로젝트마다 서버 목록을 따로 관리하고 싶다면 설정 폴더를 지정하세요. 아래 예시는 현재 폴더의 `.sshw`를 사용합니다. **모든 명령에 같은 `--home`을 붙여야 합니다.**

```sh
sshw --home ./.sshw add web --host 192.0.2.10 --user deploy
sshw --home ./.sshw trust web
sshw --home ./.sshw run web "hostname"
```

이 폴더를 선택한 명령은 서버 목록, 승인한 서버 키, 비밀번호, 허용 규칙, 작업 기록을 따로 사용합니다. `.sshw` 폴더가 있다는 이유만으로 자동 선택되지는 않습니다.

설정 폴더에 이름을 붙여 `--profile prod`로 선택할 수도 있습니다. 다만 `--home`과 이름으로 등록한 프로필은 비밀번호를 서로 공유하지 않습니다. 등록할 때 선택한 방식을 계속 사용하세요. [프로필 등록 방법](docs/reference.ko.md#profile-관리)에 자세히 설명되어 있습니다.

## 코딩 에이전트

서버 등록과 지문 확인을 마친 뒤 에이전트에게 서버 별명과 원하는 작업을 알려주세요. 예를 들면:

```text
등록한 서버 web에는 sshw로 접속해.
먼저 sshw run web "hostname && whoami && pwd" --json으로 대상을 확인해.
파일 전송은 sshw put/get을 사용하고, 비밀번호나 개인키를 요구하거나 출력하지 마.
삭제나 서비스 재시작 전에는 실행할 명령을 보여주고 내 승인을 받아.
앞 단계에 의존하는 명령은 &&로 연결하고 실패하면 중단해.
```

에이전트가 결과를 읽을 때는 `--json`을 사용하세요. `run` 결과의 `command_succeeded`가 `true`이거나 `exit_status`가 `0`이면 명령이 성공한 것입니다. `ok:true`는 명령이 끝났다는 뜻이므로 이것만으로 성공을 판단하면 안 됩니다. 서버에서 실행한 명령이 실패하면 sshw는 종료 코드 `8`을 반환합니다.

다른 명령의 결과와 작업 도중 생긴 오류는 [JSON·종료 코드](docs/reference.ko.md#json-오류-계약)를 참고하세요. 에이전트도 서버를 설정할 때 사용한 PC의 비밀번호 저장소나 SSH Agent에 접근할 수 있어야 합니다.

## 문제 해결

오류가 나면 `sshw doctor`를 실행해 보세요. PC에 저장한 설정과 비밀번호를 확인하고 다음에 할 일을 알려 줍니다. 서버 접속까지 시험하는 명령은 아닙니다.

오류가 난 명령에 `--home`이나 `--profile`을 썼다면 doctor에도 같은 옵션을 붙이세요.

| 상황 | 먼저 할 일 |
| --- | --- |
| `sshw` 명령을 찾지 못함 | `PATH`를 확인하거나 압축을 푼 실행 파일의 전체 경로로 실행하세요. |
| 서버·계정이 등록되지 않았다고 나옴 | 같은 설정 위치에서 `sshw list`·`sshw account list web`을 확인하세요. |
| 모르는 호스트 키라고 나옴 | `sshw trust web`으로 지문을 별도 경로와 비교한 뒤 승인하세요. |
| 호스트 키가 바뀌었다고 나옴 | 서버 관리자에게 변경이 맞는지 확인한 뒤 신뢰 설정을 갱신하세요. |
| 비밀번호나 SSH 키로 로그인하지 못함 | `sshw doctor`를 실행하고 계정·비밀번호·키를 확인하세요. 서버가 그 로그인 방식을 허용하는지도 확인해야 합니다. |
| 확인이 필요하다고 나옴 | 작업을 검토한 뒤 승인된 실행에는 `--yes`, 등록 갱신에는 `--force`를 사용하세요. |
| 정책에 의해 거부됨 | `sshw policy check web "uptime"`으로 해당 명령의 규칙을 확인하세요. |
| 시간이 초과됐거나 작업이 끝났는지 알 수 없음 | 다시 실행하기 전에 서버 상태를 확인하세요. 이미 변경이 일어났을 수 있습니다. |

전체 명령은 `sshw --help`로 볼 수 있습니다. 파일 업로드 옵션이 궁금하면 `sshw put --help`를 실행하세요. 다른 명령도 같은 방식으로 확인합니다. 그 밖의 오류는 [진단과 복구 안내](docs/reference.ko.md#doctor)를 참고하세요.

## 보안 안내

- 비밀번호는 Windows Credential Manager, macOS Keychain, Linux Secret Service에 저장합니다. SSH Agent를 쓰면 sshw에 개인키를 저장하지 않습니다. 비밀번호나 토큰을 명령줄, 에이전트 대화, 평문 설정 파일에 적지 마세요.
- 에이전트는 로그인한 SSH 계정의 권한으로 작업합니다. sudo 설정을 저장해도 일반 명령은 그대로 실행됩니다. sudo나 su로 실행하려면 `--as-root`를 붙여야 합니다.
- 허용할 명령과 경로를 정하는 정책 기능은 기본적으로 꺼져 있습니다. 이 기능과 `--yes` 확인만으로 서버를 완전히 격리할 수는 없습니다. 프로그램을 통째로 허용하면 그 프로그램의 다른 기능도 쓸 수 있습니다. 경로 규칙도 서버의 심볼릭 링크가 어디를 가리키는지 확인하지 않습니다.
- 출력에서 비밀을 가리고 작업 기록을 남기지만, 모든 비밀을 잡거나 모든 작업을 기록한다고 보장하지 않습니다. 기록이 수정돼도 감지하지 못합니다. 같은 PC 사용자 권한으로 실행하는 다른 프로그램이 비밀번호 저장소에 접근할 수도 있습니다.
- 오류가 나거나 시간이 초과돼도 서버에서 작업 일부가 실행됐을 수 있습니다. 두 번 실행하면 위험한 작업은 서버 상태부터 확인하세요.

보안 기능의 범위와 SSH 라이브러리에 남은 문제는 [SECURITY.md](SECURITY.md)에 설명되어 있습니다.

## 추가 문서

- [상세 참조](docs/reference.ko.md): 명령과 옵션, 로그인 방식, 설정 폴더, 허용 규칙, JSON, 시간 제한과 파일 저장 방식
- [변경 이력과 Rust API 변경 안내](CHANGELOG.md)
- [개발 참여와 배포 절차](https://github.com/Lv2dev/sshw/blob/master/CONTRIBUTING.md)

보안 문제가 의심되면 [SECURITY.md](SECURITY.md)의 안내에 따라 GitHub Security Advisories로 비공개 제보하세요. 공개 이슈에는 예시 값만 쓰고, 실제 비밀번호나 비공개 서버 정보를 올리지 마세요.

## 라이선스

MIT. [LICENSE](LICENSE)를 참고하세요.
