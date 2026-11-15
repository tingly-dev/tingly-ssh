package main

import (
	"errors"
	"flag"
	"reflect"
	"strings"
	"testing"
)

func TestSplitSSHArgs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		tunnel  []string
		ssh     []string
		dest    string
		quiet   int
		verbose int
	}{
		{
			name: "options before the destination",
			args: []string{"-p", "2222", "-i", "k", "alice@box", "tmux", "attach"},
			ssh:  []string{"-p", "2222", "-i", "k", "alice@box", "tmux", "attach"},
			dest: "alice@box",
		},
		{
			name: "options after the destination, then the command",
			args: []string{"box", "-p2222", "-t", "ls", "-la"},
			ssh:  []string{"box", "-p2222", "-t", "ls", "-la"},
			dest: "box",
		},
		{
			name:    "clustered flags with a trailing value option",
			args:    []string{"-vvAp", "22", "box"},
			ssh:     []string{"-vvAp", "22", "box"},
			dest:    "box",
			verbose: 2,
		},
		{
			name:  "-o with an attached and a separate value",
			args:  []string{"-oBatchMode=yes", "-o", "LogLevel=ERROR", "-q", "box"},
			ssh:   []string{"-oBatchMode=yes", "-o", "LogLevel=ERROR", "-q", "box"},
			dest:  "box",
			quiet: 1,
		},
		{
			name:   "tunnel flags in both forms, mixed with ssh options",
			args:   []string{"--server", "h:1", "-p", "2222", "--pin=sha256:x", "--insecure", "box"},
			tunnel: []string{"--server", "h:1", "--pin=sha256:x", "--insecure"},
			ssh:    []string{"-p", "2222", "box"},
			dest:   "box",
		},
		{
			name: "a tunnel-looking word in the remote command is left alone",
			args: []string{"box", "echo", "--server", "x"},
			ssh:  []string{"box", "echo", "--server", "x"},
			dest: "box",
		},
		{
			// How scp invokes ssh.
			name: "end of options",
			args: []string{"-x", "-oPermitLocalCommand=no", "-l", "u", "-s", "--", "box", "sftp"},
			ssh:  []string{"-x", "-oPermitLocalCommand=no", "-l", "u", "-s", "--", "box", "sftp"},
			dest: "box",
		},
		{
			name: "no destination",
			args: []string{"-V"},
			ssh:  []string{"-V"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv, err := splitSSHArgs(tc.args, sshFlagSet())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(inv.tunnel, tc.tunnel) || !reflect.DeepEqual(inv.ssh, tc.ssh) ||
				inv.dest != tc.dest || inv.quiet != tc.quiet || inv.verbose != tc.verbose {
				t.Errorf("got tunnel=%q ssh=%q dest=%q q=%d v=%d\nwant tunnel=%q ssh=%q dest=%q q=%d v=%d",
					inv.tunnel, inv.ssh, inv.dest, inv.quiet, inv.verbose,
					tc.tunnel, tc.ssh, tc.dest, tc.quiet, tc.verbose)
			}
		})
	}
}

func TestSplitSSHArgsRejectsUnknownLongOption(t *testing.T) {
	_, err := splitSSHArgs([]string{"--port", "2222", "box"}, sshFlagSet())
	if err == nil || !strings.Contains(err.Error(), "--port") {
		t.Fatalf("err = %v, want unknown option --port", err)
	}
}

func sshFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
	var f clientFlags
	f.bind(fs, true)
	return fs
}

func TestProxyArg(t *testing.T) {
	for _, tc := range [][2]string{
		{"plain", "'plain'"},
		{"with space", "'with space'"},
		{"it's", `'it'\''s'`},
		{"/tmp/100%/key", "'/tmp/100%%/key'"},
	} {
		if got := proxyArg(tc[0]); got != tc[1] {
			t.Errorf("proxyArg(%q) = %s, want %s", tc[0], got, tc[1])
		}
	}
}

func TestPlanSSH(t *testing.T) {
	direct := map[string]string{"hostname": "203.0.113.10"}
	for _, tc := range []struct {
		name   string
		args   []string
		cfg    map[string]string
		argv   string // joined with spaces
		notice string // substring
	}{
		{
			name: "tunnel to the destination's host on the default port",
			args: []string{"-p", "2222", "alice@box", "uptime"},
			cfg:  direct,
			argv: "ssh -o ProxyCommand='/bin/t' proxy '--server=203.0.113.10:7443' -p 2222 alice@box uptime",
		},
		{
			name: "IPv6 host",
			args: []string{"box"},
			cfg:  map[string]string{"hostname": "2001:db8::1"},
			argv: "ssh -o ProxyCommand='/bin/t' proxy '--server=[2001:db8::1]:7443' box",
		},
		{
			name: "tunnel flags are passed on; -v raises the proxy log level",
			args: []string{"--server", "relay:9000", "--token-file=/k/100%", "-v", "box"},
			cfg:  direct,
			argv: "ssh -o ProxyCommand='/bin/t' proxy '--log-level=info' '--server=relay:9000' '--token-file=/k/100%%' -v box",
		},
		{
			name: "-q quiets the proxy",
			args: []string{"-q", "box"},
			cfg:  direct,
			argv: "ssh -o ProxyCommand='/bin/t' proxy '--log-level=error' '--server=203.0.113.10:7443' -q box",
		},
		{
			name: "already set up in ssh_config",
			args: []string{"box"},
			cfg:  map[string]string{"hostname": "h", "proxycommand": "tingly-ssh proxy --server %h:7443"},
			argv: "ssh box",
		},
		{
			name:   "a configured ProxyJump is kept",
			args:   []string{"inner"},
			cfg:    map[string]string{"hostname": "10.0.0.5", "proxyjump": "bastion"},
			argv:   "ssh inner",
			notice: "ProxyJump bastion",
		},
		{
			name:   "another ProxyCommand is kept",
			args:   []string{"box"},
			cfg:    map[string]string{"hostname": "h", "proxycommand": "nc %h %p"},
			argv:   "ssh box",
			notice: "ProxyCommand",
		},
		{
			name: "no destination goes straight to ssh",
			args: []string{"-V"},
			argv: "ssh -V",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotG []string
			argv, notice, err := planSSH("/bin/t", tc.args, func(g []string) (map[string]string, error) {
				gotG = g
				return tc.cfg, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(argv, " "); got != tc.argv {
				t.Errorf("argv:\n got %s\nwant %s", got, tc.argv)
			}
			if tc.notice == "" && notice != "" || !strings.Contains(notice, tc.notice) {
				t.Errorf("notice = %q, want %q", notice, tc.notice)
			}
			if tc.cfg != nil && (len(gotG) == 0 || gotG[0] != "-G") {
				t.Errorf("ssh -G args = %q", gotG)
			}
		})
	}
}

func TestPlanSSHFallsBackToSSHWhenConfigFails(t *testing.T) {
	argv, _, err := planSSH("/bin/t", []string{"-Z", "box"}, func([]string) (map[string]string, error) {
		return nil, errors.New("exit status 255")
	})
	if err != nil || strings.Join(argv, " ") != "ssh -Z box" {
		t.Fatalf("argv=%q err=%v, want ssh to report the bad option", argv, err)
	}
}
