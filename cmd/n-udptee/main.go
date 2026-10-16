package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/nishisan-dev/n-udptee/internal/app"
	"github.com/nishisan-dev/n-udptee/internal/config"
)

var version = "0.1.0"
var commit = "unknown"
var buildTime = "unknown"

func execute(args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(out, "Usage: n-udptee {check|run} --config FILE\n       n-udptee version\nLinux passive UDP/IPv4 replication. --config and -c are equivalent.")
		return nil
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return fmt.Errorf("version accepts no arguments")
		}
		fmt.Fprintf(out, "n-udptee %s commit=%s built=%s %s %s/%s\n", version, commit, buildTime, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return nil
	}
	if args[0] != "check" && args[0] != "run" {
		return fmt.Errorf("unknown command %q", args[0])
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(errOut)
	var path string
	f.StringVar(&path, "config", "", "YAML configuration file")
	f.StringVar(&path, "c", "", "YAML configuration file")
	if e := f.Parse(args[1:]); e != nil {
		if e == flag.ErrHelp {
			return nil
		}
		return e
	}
	if path == "" || f.NArg() != 0 {
		return fmt.Errorf("--config FILE required; no positional arguments allowed")
	}
	c, e := config.Load(path)
	if e != nil {
		return e
	}
	if args[0] == "check" {
		fmt.Fprintln(out, "configuration valid (offline Ethernet BPF); interface and ingress validated at run")
		return nil
	}
	var level slog.Level
	_ = level.UnmarshalText([]byte(c.Logging.Level))
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler = slog.NewJSONHandler(errOut, opts)
	if c.Logging.Format == "text" {
		handler = slog.NewTextHandler(errOut, opts)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return app.Run(ctx, c, slog.New(handler))
}
func main() {
	if e := execute(os.Args[1:], os.Stdout, os.Stderr); e != nil {
		fmt.Fprintln(os.Stderr, "n-udptee:", e)
		os.Exit(1)
	}
}
