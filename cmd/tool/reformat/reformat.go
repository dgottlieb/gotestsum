package reformat

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dnephin/pflag"
	"gotest.tools/gotestsum/internal/log"
	"gotest.tools/gotestsum/testjson"
)

type options struct {
	jsonfile     string
	filter       string
	outputFormat string
	serialize    bool
	debug        bool
	onlyFailing  bool
}

func Run(name string, args []string) error {
	flags, opts := setupFlags(name)
	switch err := flags.Parse(args); {
	case err == pflag.ErrHelp:
		return nil
	case err != nil:
		usage(os.Stderr, name, flags)
		return err
	}
	return run(opts)
}

func setupFlags(name string) (*pflag.FlagSet, *options) {
	opts := &options{}
	flags := pflag.NewFlagSet(name, pflag.ContinueOnError)
	flags.SetInterspersed(false)
	flags.Usage = func() {
		usage(os.Stdout, name, flags)
	}
	flags.StringVar(&opts.jsonfile, "jsonfile", os.Getenv("GOTESTSUM_JSONFILE"),
		"path to test2json output, defaults to stdin")
	flags.StringVar(&opts.filter, "filter", "",
		"only output log lines for test names that match pass filter")
	flags.StringVar(&opts.outputFormat, "format", "standard-verbose",
		"desired output format. E.g: `debug`, `standard-json`, `standard-quiet`")
	flags.BoolVar(&opts.serialize, "serialize", false,
		"serialize logs from parallel test runs")
	flags.BoolVar(&opts.onlyFailing, "onlyFailing", false,
		"only show logs for failing tests")
	flags.BoolVar(&opts.debug, "debug", false,
		"enable debug logging.")
	return flags, opts
}

func usage(out io.Writer, name string, flags *pflag.FlagSet) {
	fmt.Fprintf(out, `Usage:
    %[1]s [flags]
Flags:
`, name)
	flags.SetOutput(out)
	flags.PrintDefaults()
}

func run(opts *options) error {
	if opts.debug {
		log.SetLevel(log.DebugLevel)
	}

	in, err := jsonfileReader(opts.jsonfile)
	if err != nil {
		return fmt.Errorf("failed to read jsonfile: %v", err)
	}
	defer in.Close()

	format(in, opts)

	return nil
}

func jsonfileReader(v string) (io.ReadCloser, error) {
	switch v {
	case "", "-":
		return ioutil.NopCloser(os.Stdin), nil
	default:
		return os.Open(v)
	}
}

type TestComparator struct {
	testEvents        []testjson.TestEvent
	firstEventPerTest map[string]time.Time
}

func (cmp TestComparator) Len() int {
	return len(cmp.testEvents)
}

func (cmp TestComparator) Less(leftIdx, rightIdx int) bool {
	left := cmp.testEvents[leftIdx]
	right := cmp.testEvents[rightIdx]

	leftTime := cmp.firstEventPerTest[left.Test]
	rightTime := cmp.firstEventPerTest[right.Test]

	return leftTime.Before(rightTime)
}

func (cmp TestComparator) Swap(left, right int) {
	cmp.testEvents[left], cmp.testEvents[right] = cmp.testEvents[right], cmp.testEvents[left]
}

func format(inp io.Reader, opts *options) {
	scanner := bufio.NewScanner(inp)
	writer := testjson.NewEventFormatter(os.Stdout, opts.outputFormat, testjson.FormatOptions{})

	includeFilterMatches := true
	var filterRx *regexp.Regexp
	testEvents := make([]testjson.TestEvent, 0)
	firstEventPerTest := make(map[string]time.Time)
	failedTests := make(map[string]bool)

	if opts.filter != "" {
		if opts.filter[0] == '!' {
			includeFilterMatches = false
			opts.filter = opts.filter[1:]
		}
		filterRx = regexp.MustCompile(opts.filter)
	}

	for scanner.Scan() {
		raw := scanner.Bytes()
		event, err := parseEvent(raw)
		if err != nil {
			panic(err)
		}

		if filterRx != nil {
			switch includeFilterMatches {
			case false && filterRx.MatchString(event.Test):
				continue
			case true && !filterRx.MatchString(event.Test):
				continue
			}
		}

		if event.Action == testjson.ActionFail {
			failedTests[event.Test] = true
		}

		if opts.serialize || opts.onlyFailing {
			testEvents = append(testEvents, event)
			// Track the time of the first log line for each test. This is used to sort logs keeping
			// adjacent test logs next to each other without interleaving with other test logs.
			if _, exists := firstEventPerTest[event.Test]; opts.serialize && !exists {
				firstEventPerTest[event.Test] = event.Time
			}
			continue
		}

		// There were no options that require buffering input. We can just write the results immediately.
		writer.Format(event, nil)
	}

	if len(testEvents) == 0 {
		// We didn't use any features that required buffering events.
		return
	}

	if opts.serialize {
		// All logs for a single test have the same timestamp key. Use a stable sort such that the
		// logs for a given test are kept in the relative order they appear.
		sort.Stable(TestComparator{testEvents, firstEventPerTest})
	}

	pausedTests := make(map[string]bool)
	for idx := 0; idx < len(testEvents); idx++ {
		event := testEvents[idx]

		if event.Test == "" || opts.onlyFailing && !failedTests[event.Test] {
			// Lines without a `event.Test` field that we want to skip over:
			//   {"Time":"2023-06-27T19:00:41.047964705Z","Action":"output","Package":"go.viam.com/rdk/components/board/genericlinux","Output":"PASS\n"}
			//   {"Time":"2023-06-27T19:00:41.054056699Z","Action":"output","Package":"go.viam.com/rdk/components/board/genericlinux","Output":"coverage: 17.1% of statements\n"}
			//   {"Time":"2023-06-27T19:00:41.068046269Z","Action":"output","Package":"go.viam.com/rdk/components/board/genericlinux","Output":"ok  \tgo.viam.com/rdk/components/board/genericlinux\t0.234s\tcoverage: 17.1% of statements\n"}
			continue
		}

		if opts.serialize && event.Action == "output" {
			// The `=== PAUSE` and CONT log lines with the `output` action come some time after the
			// `ActionPause` and `ActionCont` json events.
			if strings.HasPrefix(event.Output, "=== PAUSE") ||
				strings.HasPrefix(event.Output, "=== CONT") {
				// When the logs are serialized, the log lines have little meaning. Knowing there
				// was a pause due to scheduling could be interesting. But a bunch of consecutive
				// pause->cont log lines without any test logs between them are of little diagnostic
				// value.
				if !pausedTests[event.Test] {
					fmt.Println("=== Paused")
				}
				pausedTests[event.Test] = true
				continue
			}
		}

		if event.Action == "output" {
			// Only flip this when we actually output a test log line.
			pausedTests[event.Test] = false
		}

		writer.Format(event, nil)
	}
}

// Copied from `testjson/execution.go` with one edit. `TestEvent has a private `raw` field, our copy
// will not set that field.
func parseEvent(raw []byte) (testjson.TestEvent, error) {
	// TODO: this seems to be a bug in the `go test -json` output
	if bytes.HasPrefix(raw, []byte("FAIL")) {
		log.Warnf("invalid TestEvent: %v", string(raw))
		return testjson.TestEvent{}, errBadEvent
	}

	event := testjson.TestEvent{}
	err := json.Unmarshal(raw, &event)
	return event, err
}

var errBadEvent = errors.New("bad output from test2json")
