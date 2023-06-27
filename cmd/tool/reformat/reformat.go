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

	return nil
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

		if opts.serialize {
			testEvents = append(testEvents, event)
			if _, exists := firstEventPerTest[event.Test]; !exists {
				firstEventPerTest[event.Test] = event.Time
			}
			continue
		}

		writer.Format(event, nil)
	}

	if opts.serialize {
		sort.Stable(TestComparator{testEvents, firstEventPerTest})
		for idx := 0; idx < len(testEvents); idx++ {
			event := testEvents[idx]
			// fmt.Printf("DBG. Action: %v\n", event.Action)
			// fmt.Printf("\t%+v\n", event)
			/*
				The code I wanted to write:
						if event.Action == testjson.ActionPause ||
							event.Action == testjson.ActionCont {
							continue
						}
			*/

			if event.Action == "output" &&
				(strings.HasPrefix(event.Output, "=== PAUSE") ||
					strings.HasPrefix(event.Output, "=== CONT")) {
				continue
			}

			writer.Format(event, nil)
		}
	}
}

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
