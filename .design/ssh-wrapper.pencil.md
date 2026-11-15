# 一条命令直接用：`tingly-ssh ssh`

- 状态：**已实现**（`cmd/tingly-ssh/ssh.go`，验收 E19/E20）
- 日期：2026-11-15
- 关系：建立在 [ssh-key-auth](ssh-key-auth.pencil.md) 之上——零新秘密、TOFU 已经把客户端配置收敛成
  `ProxyCommand tingly-ssh proxy --server %h:7443` 一行；本设计让这一行也可以不写。

## 0. 目标

把使用变简单：**会用 ssh，就会用 `tingly-ssh ssh`**。

```
ssh            -p 2222 -i ~/.ssh/k alice@box tmux attach
tingly-ssh ssh -p 2222 -i ~/.ssh/k alice@box tmux attach     # 只多了前缀
```

用户需要多知道的只有一件事：隧道服务端不在默认位置（`<主机>:7443`）时，加 `--server`。

非目标（刻意不做，避免过度）：不提供缩写或软链接；不自己实现 SSH 客户端（继续 exec OpenSSH，
全部特性原样保留）；不做隧道失败时自动退回直连；不改写跳板机链路；不加 tingly 专用的环境变量。

## 1. 上一版的问题

思路（exec ssh，ProxyCommand 指回自己）不变，问题在于命令行不像 ssh：

1. 用 Go `flag` 解析目标前的参数，`-p 2222`、`-i`、`-o` 写在前面就报错退出——和 ssh 的习惯相反。
2. `--server` 必填，和目标重复。
3. 命令行 `-o ProxyCommand` 会静默覆盖 ssh_config 里的 `ProxyJump`（已用 `ssh -G` 实测），跳板机配置下连错主机。
4. ProxyCommand 里没转义 `%`（ssh 会做 `%` 展开）。

## 2. 用法

```
tingly-ssh ssh [--server HOST:PORT] [隧道选项] <和 ssh 完全一样的参数>
```

- **参数和 ssh 一致**：选项放目标前后都行，粘连写法（`-p2222`、`-oX=Y`）、`-vvv`、`--` 都照常。
- **隧道选项用双横线长选项**，名字和 `proxy` 模式一样（`--server`、`--pin`、`--token-file`、`--identity`、
  `--known-servers`、`--insecure`、`--server-name`），只在目标之前识别。ssh 没有 `--xxx` 选项，所以不会混淆；
  目标之后的远端命令原样不动。
- `--server` 默认 `<HostName>:7443`，HostName 取自 `ssh -G` 解析后的结果，所以 ssh_config 别名直接可用（IPv6 会加方括号）。
- 附带收获：`rsync -e 'tingly-ssh ssh'`、`GIT_SSH_COMMAND='tingly-ssh ssh'` 也能用，因为参数本来就和 ssh 一样。
  不为此做额外设计。

## 3. 实现

```
argv ─▶ ① 拆参数 ─▶ ② 看 ssh 已有配置 ─▶ ③ 注入 ProxyCommand ─▶ syscall.Exec(ssh)
```

① **拆参数**（纯函数）：按 OpenSSH 的 getopt 串
`1246ab:c:e:fgi:kl:m:no:p:qstvxAB:CD:E:F:GI:J:KL:MNO:P:Q:R:S:TVw:W:XYy` 找出目标的位置，
把目标之前的隧道长选项取出来，其余参数原样、原顺序保留。未知的单字母选项当作不带参数，交给 ssh 报错。

② **看已有配置**：跑 `ssh -G <参数>`（不建连），取 `hostname`，并看 `proxycommand` / `proxyjump`：

| 已有配置 | 动作 |
|---------|------|
| 都没有 | 注入隧道 |
| 已经是 `tingly-ssh proxy` | 不注入，直接 exec（已经配好了） |
| 其他 ProxyCommand 或 ProxyJump | 不注入，直接 exec，stderr 打一行说明隧道没生效及原因 |

③ **注入**：`-o ProxyCommand=<本程序> proxy --server ... <用户给的隧道选项>`，放在参数最前（ssh 首个取值生效）。
每个参数先 `%`→`%%`，再 shell 单引号转义。ssh 的 `-q` 映射成 proxy 的
`--log-level=error`，`-v` 映射成 `info`，`-vv` 及以上映射成 `debug`，其余保持 proxy 默认的 warn。

## 4. 测试

- 单元：拆参数表驱动（选项在前/后、粘连、`-vvv`、`--`、远端命令里带 `--server`、`ssh://u@h:p`）；
  ProxyCommand 转义（`%`、空格、单引号）；②的决策表（`ssh -G` 输出打桩）。
- 端到端：E19 改为 `tingly-ssh ssh -F cfg --server ... --token-file ... --pin ... host 'echo ok'`，并带一个写在目标前的 ssh 选项；
  E20：ssh_config 里有 ProxyJump 时不被覆盖，仍能连通。

## 5. 文档

README 第 3 步：确认 `ssh-add -l` 后，`tingly-ssh ssh alice@host`；`~/.ssh/config` 一行的写法作为"想固定下来"的备选。
上一版 diff 里 README 的改法沿用，示例去掉 `--server`。
