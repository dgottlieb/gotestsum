module github.com/dgottlieb/gotestsum

require (
	github.com/dnephin/pflag v1.0.7
	github.com/fatih/color v1.13.0
	github.com/fsnotify/fsnotify v1.5.4
	github.com/google/go-cmp v0.5.8
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	golang.org/x/sync v0.0.0-20220601150217-0de741cfad7f
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8
	golang.org/x/term v0.0.0-20220526004731-065cf7ba2467
	golang.org/x/tools v0.1.11
	gotest.tools/gotestsum v0.0.0-00010101000000-000000000000
	gotest.tools/v3 v3.3.0
)

go 1.13

replace gotest.tools/gotestsum => github.com/dgottlieb/gotestsum v0.0.0-20230628165630-2cea2e5504de
