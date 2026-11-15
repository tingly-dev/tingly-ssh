package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// defaultTunnelPort is where ssh mode looks for the tunnel server when
// --server is not given: the ssh destination's host, this port.
const defaultTunnelPort = "7443"

// sshOptsWithValue are the ssh(1) options that take a value, from OpenSSH's
// getopt string "1246ab:c:e:fgi:kl:m:no:p:qstvxAB:CD:E:F:GI:J:KL:MNO:P:Q:R:S:TVw:W:XYy".
const sshOptsWithValue = "bceilmopBDEFIJLOPQRSWw"

// sshInvocation is an ssh mode command line split into the two programs it
// addresses.
type sshInvocation struct {
	tunnel  []string // tingly-ssh's own --flags, for the proxy
	ssh     []string // everything else, verbatim and in order, for ssh
	dest    string   // the ssh destination, "" if there is none
	quiet   int      // -q count
	verbose int      // -v count
}

// splitSSHArgs walks a command line the way ssh does: options may come before
// and after the destination, and the first non-option after it starts the
// remote command, which is never looked into. Before the destination it also
// takes out tingly-ssh's flags; ssh has no "--name" options, so the two never
// collide. fs tells which of those flags take a value.
func splitSSHArgs(args []string, fs *flag.FlagSet) (sshInvocation, error) {
	var inv sshInvocation
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case inv.dest == "" && strings.HasPrefix(a, "--") && len(a) > 2:
			name, _, hasValue := strings.Cut(a[2:], "=")
			f := fs.Lookup(name)
			if f == nil && name != "help" && name != "h" {
				return inv, fmt.Errorf("unknown option --%s (ssh's own options take a single dash)", name)
			}
			inv.tunnel = append(inv.tunnel, a)
			if f != nil && !hasValue && !isBoolFlag(f) && i+1 < len(args) {
				i++
				inv.tunnel = append(inv.tunnel, args[i])
			}
		case a == "--":
			// ssh's end of options: the destination follows, then the command.
			inv.ssh = append(inv.ssh, args[i:]...)
			if inv.dest == "" && i+1 < len(args) {
				inv.dest = args[i+1]
			}
			return inv, nil
		case len(a) > 1 && a[0] == '-':
			inv.ssh = append(inv.ssh, a)
			for j := 1; j < len(a); j++ {
				c := a[j]
				if strings.IndexByte(sshOptsWithValue, c) >= 0 {
					// The value is the rest of this word, or the next one.
					if j == len(a)-1 && i+1 < len(args) {
						i++
						inv.ssh = append(inv.ssh, args[i])
					}
					break
				}
				switch c {
				case 'q':
					inv.quiet++
				case 'v':
					inv.verbose++
				}
			}
		case inv.dest == "":
			inv.dest = a
			inv.ssh = append(inv.ssh, a)
		default:
			inv.ssh = append(inv.ssh, args[i:]...)
			return inv, nil
		}
	}
	return inv, nil
}

func isBoolFlag(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

// planSSH turns an ssh mode command line into the argv to exec ssh with, plus
// a notice for the user when the tunnel is left out. resolve runs "ssh -G"
// with the given arguments and returns its key/value output.
//
// The tunnel is wired in as a ProxyCommand pointing back at exe in proxy mode,
// unless ssh_config already routes the destination some other way: a
// command-line ProxyCommand would silently replace a configured ProxyJump and
// connect to the wrong host.
func planSSH(exe string, args []string, resolve func([]string) (map[string]string, error)) (argv []string, notice string, err error) {
	fs := flag.NewFlagSet("ssh", flag.ExitOnError)
	var f clientFlags
	f.bind(fs, true)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: tingly-ssh ssh [--server HOST:PORT] [tunnel options] [ssh arguments]

Runs ssh with the tunnel wired in. Everything with a single dash is ssh's own
argument and is passed through unchanged; the tunnel server defaults to the
destination's host on port `+defaultTunnelPort+`.

Tunnel options (before the destination):
`)
		fs.VisitAll(func(fl *flag.Flag) {
			if fl.Name == "listen" { // client mode only
				return
			}
			kind, usage := flag.UnquoteUsage(fl)
			line := "  --" + fl.Name
			if kind != "" {
				line += " " + kind
			}
			if fl.DefValue != "" && fl.DefValue != "false" {
				usage += " (default " + fl.DefValue + ")"
			}
			fmt.Fprintf(fs.Output(), "%s\n    \t%s\n", line, usage)
		})
	}
	inv, err := splitSSHArgs(args, fs)
	if err != nil {
		return nil, "", err
	}
	if err := fs.Parse(inv.tunnel); err != nil {
		return nil, "", err
	}
	plain := append([]string{"ssh"}, inv.ssh...)
	if inv.dest == "" {
		// -V, -Q, or a mistake: ssh answers or explains it.
		return plain, "", nil
	}
	cfg, err := resolve(append([]string{"-G"}, inv.ssh...))
	if err != nil {
		// The arguments are wrong in a way ssh will report better.
		return plain, "", nil
	}
	if pc := cfg["proxycommand"]; pc != "" && pc != "none" {
		if strings.Contains(pc, "tingly-ssh") {
			return plain, "", nil // already set up in ssh_config
		}
		notice = "ssh already has a ProxyCommand for " + inv.dest + "; running it without the tunnel"
	} else if pj := cfg["proxyjump"]; pj != "" && pj != "none" {
		notice = inv.dest + " is reached through ProxyJump " + pj + "; running ssh without the tunnel"
	}
	if notice != "" {
		if inv.quiet > 0 {
			notice = ""
		}
		return plain, notice, nil
	}

	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	if !set["server"] {
		host := cfg["hostname"]
		if host == "" {
			return nil, "", errors.New("could not resolve the host of " + inv.dest + "; pass --server HOST:PORT")
		}
		fs.Set("server", net.JoinHostPort(host, defaultTunnelPort))
	}
	if !set["log-level"] {
		switch {
		case inv.quiet > 0:
			fs.Set("log-level", "error")
		case inv.verbose == 1:
			fs.Set("log-level", "info")
		case inv.verbose > 1:
			fs.Set("log-level", "debug")
		}
	}
	proxy := []string{proxyArg(exe), "proxy"}
	fs.Visit(func(fl *flag.Flag) {
		proxy = append(proxy, proxyArg("--"+fl.Name+"="+fl.Value.String()))
	})
	return append([]string{"ssh", "-o", "ProxyCommand=" + strings.Join(proxy, " ")}, inv.ssh...), "", nil
}

// proxyArg makes one literal argument safe in a ProxyCommand, which ssh first
// expands %-tokens in and then runs through the shell.
func proxyArg(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runSSH is ssh mode: use it like ssh, and the session survives network
// changes. It replaces this process with ssh, so terminal handling, signals
// and the exit status are exactly plain ssh's.
func runSSH(args []string) error {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh mode needs the ssh binary in PATH: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	argv, notice, err := planSSH(exe, args, func(gArgs []string) (map[string]string, error) {
		return resolveSSHConfig(sshPath, gArgs)
	})
	if err != nil {
		return err
	}
	if notice != "" {
		fmt.Fprintln(os.Stderr, "tingly-ssh: "+notice)
	}
	return syscall.Exec(sshPath, argv, os.Environ())
}

// resolveSSHConfig runs "ssh -G", which prints the effective configuration
// for a destination without connecting.
func resolveSSHConfig(sshPath string, args []string) (map[string]string, error) {
	out, err := exec.Command(sshPath, args...).Output()
	if err != nil {
		return nil, err
	}
	cfg := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok {
			if _, dup := cfg[k]; !dup {
				cfg[k] = v
			}
		}
	}
	return cfg, nil
}
