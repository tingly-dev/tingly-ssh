# 10 · `tingly-ssh ssh` 使用手册

会用 ssh，就会用 `tingly-ssh ssh`：在平时的 ssh 命令前面加上 `tingly-ssh`，其余照旧。
连接走 QUIC 隧道，换网、合盖、短时断网之后会话继续，不用重新登录。

```
ssh            -p 2222 alice@myserver tmux attach
tingly-ssh ssh -p 2222 alice@myserver tmux attach
```

完整路线：

```
① 两端安装 ─▶ ② 服务端起隧道（每台一次）─▶ ③ 客户端 tingly-ssh ssh ─▶ ④ 验证漫游 ─▶ ⑤（可选）写进 ~/.ssh/config
```

## 1. 安装（两端都要）

```bash
# 把 VERSION、OS（linux|darwin）、ARCH（amd64|arm64）换成实际值
curl -LO https://github.com/tingly-dev/tingly-ssh/releases/download/vVERSION/tingly-ssh_VERSION_OS_ARCH.tar.gz
tar xzf tingly-ssh_VERSION_OS_ARCH.tar.gz
sudo install -m 755 tingly-ssh /usr/local/bin/
tingly-ssh version
```

或者 Go 1.26+：`go install github.com/tingly-dev/tingly-ssh/cmd/tingly-ssh@latest`。
客户端还需要 OpenSSH 的 `ssh` 在 `PATH` 里，`tingly-ssh ssh` 最终执行的就是它。

## 2. 服务端（每台服务器一次）

### 2.1 最常见：和 sshd 在同一台机器，用 SSH 密钥认证

隧道白名单就是一份 `authorized_keys`，抄一份现成的即可：

```bash
sudo mkdir -p /etc/tingly
sudo sh -c 'cat ~alice/.ssh/authorized_keys >> /etc/tingly/authorized_keys'

tingly-ssh server --listen :7443 --target 127.0.0.1:22 \
    --authorized-keys /etc/tingly/authorized_keys
# ... msg="server listening" addr=[::]:7443 targets=127.0.0.1:22 pin=sha256:XUYr8w...
```

- **记下 `pin=sha256:…`**，客户端首次连接时核对。
- 防火墙或云安全组放行 **UDP** 7443。
- 长期运行用 systemd，见 [09-migrating-from-ssh.md §2.3](09-migrating-from-ssh.md#23-启动systemd)；
  白名单里哪些 `authorized_keys` 选项生效，见同文 §2.2。
- sshd 不在 22 端口：服务端改 `--target 127.0.0.1:2222`。客户端不用跟着改，见 §3.3。

### 2.2 中转：隧道服务端在前面，sshd 在后面的内网

```
客户端 ══QUIC══▶ relay.example.com:7443 (tingly-ssh server) ──TCP──▶ 10.0.0.5:22 / 10.0.0.6:22
```

```bash
tingly-ssh server --listen :7443 \
    --target 10.0.0.5:22,10.0.0.6:22 \
    --authorized-keys /etc/tingly/authorized_keys
```

`--target` 是**白名单**，服务端只会去连这里列出的地址：

| 服务端 `--target` | 客户端 `--target` |
| --- | --- |
| 只有一个 | 忽略，写不写都连这一个 |
| 多个 | **必须写**，且与白名单某一项字面一致，否则拒绝。客户端默认发的是 `127.0.0.1:22`，不在列表里就会被拒 |

### 2.3 不用 SSH 密钥：每设备 token

适合 CI 或没有 ssh-agent 的环境：

```bash
tingly-ssh keygen --label ci-runner-1 > token     # token 打到 stdout，服务端记录行打到 stderr
chmod 600 token                                   # 把这个文件交给客户端
# 把 stderr 里那行追加到服务端的 credentials 文件，然后：
tingly-ssh server --listen :7443 --target 127.0.0.1:22 --credentials /etc/tingly/credentials
# 已在运行的服务端：kill -HUP <pid> 重新加载；撤销 = 删掉那一行再 HUP
```

`--authorized-keys` 和 `--credentials` 可以同时配，两种客户端共用一台服务端。

## 3. 客户端

### 3.1 准备

```bash
ssh-add -l      # 确认钥匙在 agent 里；没有就 ssh-add
```

`AddKeysToAgent yes` 不能代替这一步：它要等登录成功之后才把钥匙放进 agent，隧道在登录前就要签名。

### 3.2 命令格式

```
tingly-ssh ssh [隧道选项] <ssh 的参数>
```

- **ssh 的参数**：单横线选项、目标、远端命令，写法和 ssh 完全相同。选项放在目标前后都行，
  也支持粘连写法（`-p2222`）、`-vvv` 和 `--`。全部原样交给 ssh。
- **隧道选项**：双横线长选项，必须写在**目标之前**。目标之后出现的 `--xxx` 属于远端命令，不会被拿走。
  写了不认识的长选项会报错：`unknown option --port (ssh's own options take a single dash)`。

### 3.3 隧道选项

| 选项 | 作用 | 默认 |
| --- | --- | --- |
| `--server HOST:PORT` | 隧道服务端地址 | 目标解析后的 HostName（读 `~/.ssh/config`）加 `:7443` |
| `--target HOST:PORT` | 让服务端连哪台 sshd（仅服务端配了多个 target 时有意义，见 §2.2） | `127.0.0.1:22` |
| `--identity FILE` | 隧道用哪把 SSH 钥匙：`.pub`（钥匙在 agent 里）或未加密私钥 | agent 里所有非 FIDO 钥匙 |
| `--token-file FILE` | 改用 token 认证（文件权限 0600），与 `--identity` 二选一 | — |
| `--pin sha256:…` | 预先写死服务端公钥，跳过首次信任；用 token 时必填（除非服务端证书由公共 CA 签发） | — |
| `--known-servers FILE` | 首次信任的记录文件 | Linux `~/.config/tingly-ssh/known_servers`，macOS `~/Library/Application Support/tingly-ssh/known_servers` |
| `--server-name NAME` | TLS 服务名 | `--server` 的主机部分 |
| `--session-linger 60s` | 断网多久之内会话还能恢复 | 60s |
| `--log-level LEVEL` | 隧道日志级别：`debug` / `info` / `warn` / `error` | `warn`，并跟随 ssh 的 `-q`/`-v`（§5） |
| `--insecure` | 不校验服务端证书，**仅限开发** | — |

另有 `--window`、`--max-streams`、`--keepalive`、`--idle-timeout` 等调优选项，完整列表：`tingly-ssh ssh --help`。

注意：sshd 的端口由**服务端**的 `--target` 决定。ssh 的 `-p` / `Port` 只影响 ssh 自己查 `known_hosts`
时用的名字，不会改变隧道连到哪里。

### 3.4 第一次连接

```console
$ tingly-ssh ssh alice@203.0.113.10
level=WARN msg="trusting this server key from now on" server=203.0.113.10:7443 pin="sha256:XUYr8w..." file=...
alice@myserver:~$
```

拿这行的 `pin` 和 §2.1 记下的核对一次。一致就好，之后不再提示，作用相当于 ssh 的 known_hosts 确认。
连接正常时终端上不会有任何多余输出。

## 4. 场景速查

| 场景 | 命令 |
| --- | --- |
| 隧道和 sshd 在同一台、端口 7443 | `tingly-ssh ssh alice@203.0.113.10` |
| 用 `~/.ssh/config` 里的别名 | `tingly-ssh ssh myserver`（隧道地址取别名的 `HostName`） |
| 带 ssh 选项和远端命令 | `tingly-ssh ssh -A -L 8080:localhost:80 myserver tmux attach` |
| 隧道服务端换了端口 | `tingly-ssh ssh --server 203.0.113.10:9000 myserver` |
| 隧道服务端是另一台机器（中转，单 target） | `tingly-ssh ssh --server relay.example.com:7443 alice@10.0.0.5` |
| 中转后面有多台机器 | `tingly-ssh ssh --server relay.example.com:7443 --target 10.0.0.5:22 alice@10.0.0.5` |
| token 认证 | `tingly-ssh ssh --token-file ~/.config/tingly-ssh/token --pin sha256:XUYr8w... alice@host` |
| agent 里钥匙多，只用一把 | `tingly-ssh ssh --identity ~/.ssh/id_ed25519.pub alice@host` |
| 没有 agent、私钥无密码 | `tingly-ssh ssh --identity ~/.ssh/id_ed25519 alice@host` |
| FIDO 钥匙（每个会话只需碰一次） | `tingly-ssh ssh --identity ~/.ssh/id_ed25519_sk.pub alice@host` |
| 1Password / Secretive 等 agent | `SSH_AUTH_SOCK=$HOME/.1password/agent.sock tingly-ssh ssh alice@host`（隧道只看 `SSH_AUTH_SOCK`，不看 `IdentityAgent`） |
| 跳过首次信任 | `tingly-ssh ssh --pin sha256:XUYr8w... alice@host` |
| rsync / git | `rsync -e 'tingly-ssh ssh' src/ host:dst/`、`GIT_SSH_COMMAND='tingly-ssh ssh' git pull`（参数与 ssh 兼容，未纳入自动化验收） |

中转场景下，目标写**真实机器**的名字或别名：sshd 实际连哪台由 `--target` 决定，
目标名只用于 ssh 读 `~/.ssh/config` 和校验 `known_hosts`，写对了主机密钥校验才会对上。

## 5. 它具体做了什么

`tingly-ssh ssh` 不自己实现 SSH。它先拆出参数，再用 `ssh -G`（只解析配置、不建连）查看这台主机的生效配置，然后决定：

| `~/.ssh/config`（或命令行 `-o`）里对这台主机 | 结果 |
| --- | --- |
| 没有 ProxyCommand / ProxyJump | 加上 `-o ProxyCommand=tingly-ssh proxy --server …` 后执行 ssh，**走隧道** |
| ProxyCommand 已经是 `tingly-ssh proxy` | 原样执行 ssh（已经配好了），不提示 |
| 配了 ProxyJump | 原样执行 ssh，**不走隧道**，提示 `<目标> is reached through ProxyJump <跳板>; running ssh without the tunnel` |
| 配了别的 ProxyCommand | 原样执行 ssh，**不走隧道**，提示 `ssh already has a ProxyCommand for <目标>; running it without the tunnel` |
| 没有目标（如 `-V`） | 原样执行 ssh |

- 遇到 ProxyJump 不插手，是因为命令行的 ProxyCommand 会悄悄顶掉配置里的 ProxyJump，ssh 就会直接去连内网地址。
  想让跳板机那一跳走隧道，给**跳板机**配隧道，见 §7。
- 执行 ssh 是替换当前进程（exec），终端、信号、退出码与直接运行 ssh 完全一样。
- 日志级别：用户没写 `--log-level` 时，`-q` 对应 `error`，`-v` 对应 `info`，`-vv` 及以上对应 `debug`，否则为 `warn`。
  `-q` 也会关掉上表里的提示。
- 想看最终执行的命令：`tingly-ssh ssh -G myserver | grep '^proxycommand'`。`-G` 本身就是 ssh 的参数，会原样传给 ssh，输出里能看到注入的 ProxyCommand。

## 6. 验证漫游

```bash
tingly-ssh ssh myserver
# 远端：
while true; do date; sleep 1; done
```

然后在本机切 Wi-Fi 或热点、合盖再打开，或者直接模拟一次换网：

```bash
pkill -USR1 -f 'tingly-ssh proxy'
```

`date` 短暂停顿后继续输出，不丢行，不用重新登录。断网超过 `--session-linger`（默认 60 秒）后会话放弃，ssh 正常退出。
想看每次建链，加 `-v`：每次建链会打印一行 `link established`，行尾 `auth=ssh-key` 表示用钥匙签名，`auth=ticket` 表示用恢复凭证重连。

## 7. 固定下来：写进 `~/.ssh/config`

不想每次加前缀，就把隧道写进 ssh 配置，之后直接用 `ssh`，scp / sftp / rsync / git / IDE 也都会走隧道。
下表左边的命令和右边的配置效果相同：

| `tingly-ssh ssh` | `~/.ssh/config` |
| --- | --- |
| `tingly-ssh ssh myserver` | `ProxyCommand tingly-ssh proxy --server %h:7443` |
| `--server relay.example.com:7443 --target 10.0.0.5:22` | `ProxyCommand tingly-ssh proxy --server relay.example.com:7443 --target %h:%p` |
| `--token-file F --pin P` | `ProxyCommand tingly-ssh proxy --server %h:7443 --token-file F --pin P` |

```sshconfig
Host myserver-roam                 # 先加新别名试用，原来的 Host 不动，随时可以退回
    HostName 203.0.113.10
    User alice
    ProxyCommand tingly-ssh proxy --server %h:7443

Host jump                          # 跳板机：只给第一跳配隧道
    HostName jump.example.com
    ProxyCommand tingly-ssh proxy --server %h:7443
Host internal-*
    ProxyJump jump
```

写进配置后，`tingly-ssh ssh` 对这些主机也照样能用：已经是 tingly 的 ProxyCommand 会被识别并原样放行。
跳板机的更多拓扑见 [08-jump-host-topologies.md](08-jump-host-topologies.md)。

## 8. 排错

| 看到的信息 | 原因 | 怎么办 |
| --- | --- | --- |
| `unknown option --xxx (ssh's own options take a single dash)` | 双横线选项拼错，或把 ssh 选项写成了双横线 | 查 `tingly-ssh ssh --help`；ssh 自己的选项用单横线 |
| `… is reached through ProxyJump …; running ssh without the tunnel` | 配置里有 ProxyJump，按设计不插手 | 给跳板机配隧道（§7），或者就这样直连 |
| `ssh already has a ProxyCommand for …` | 配置或命令行已有别的 ProxyCommand | 确认是否需要；要走隧道就去掉它 |
| `could not resolve the host of …; pass --server HOST:PORT` | `ssh -G` 没给出 HostName | 显式写 `--server` |
| `ssh mode needs the ssh binary in PATH` | 没装 OpenSSH 客户端 | 安装 openssh-client |
| 一直 `reconnect failed … timeout` | UDP 不通，或 `--server` 地址或端口不对 | 检查服务端是否在跑、**UDP** 防火墙规则、`--server` |
| `handshake refused (unauthorized): no offered SSH key is authorized` | 公钥不在隧道白名单 | 管理员加进 `/etc/tingly/authorized_keys` 并 reload |
| `server key changed for …; … delete line N of …/known_servers` | 隧道服务端公钥变了 | 自己换的：核对新 pin 后删第 N 行；否则当作攻击处理 |
| 服务端日志 `rejected stream target` | 服务端有多个 `--target`，客户端没写或写得不一致 | 客户端加 `--target`，与服务端白名单字面一致 |
| ssh 报 `Host key verification failed` | 里层 SSH 的 `known_hosts`，与隧道无关 | 与直连时的处理方式相同；中转场景检查目标名是否写的是真实机器 |

其余错误信息（agent、FIDO、过期、撤销等）见 [09-migrating-from-ssh.md §6](09-migrating-from-ssh.md#6-排错错误信息--原因--怎么办)。

## 9. 限制

- **UDP 被封时连不上**，不会自动退回直连 TCP。保留普通 `ssh` 作为后备。
- 断网超过 `--session-linger` 后会话结束；客户端进程退出（关掉终端）后会话也不能恢复（见 roadmap M4）。
- `scp -S` 只接受一个程序路径、不能带子命令，所以不能写 `scp -S 'tingly-ssh ssh'`；scp 和 sftp 用 §7 的 ssh_config 写法。
- 不支持 Windows。
