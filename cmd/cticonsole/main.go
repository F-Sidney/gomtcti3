package main

import (
	"CtiConsole/pkg/ipo"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/c-bata/go-prompt"
)

var consoleWriter prompt.ConsoleWriter

func AsyncWrite(logStr string) {
	w := tabwriter.NewWriter(os.Stdout, 10, 1, 5, ' ', 0)
	fmt.Fprintln(w, logStr)
	w.Flush()
}

func completer(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "Login", Description: "login to ipo via MTCTI3 and websocket"},
		{Text: "QueryLines", Description: "query and subscribe all lines from ipo "},
		{Text: "QueryUsers", Description: "query and subscribe all users from ipo "},
		{Text: "QueryQueues", Description: "query and subscribe all queues from ipo "},
		{Text: "ShowLines", Description: "show all lines information in tab"},
		{Text: "ShowUsers", Description: "show all users details"},
		{Text: "ShowQueues", Description: "show all queues details"},
		{Text: "Q", Description: "exit"},
		{Text: "Exit", Description: "exit"},
		{Text: "Quit", Description: "exit"},
		{Text: "TraceOn", Description: "enable verbose trace log output"},
		{Text: "TraceOff", Description: "disable verbose trace log output"},
	}
	return prompt.FilterContains(s, d.TextBeforeCursor(), true)
}

func getExecuter(ipoSrv *ipo.IPO) func(string) {
	return func(cmd string) {
		cmd = strings.TrimSpace(cmd)
		cmd = strings.ToLower(cmd)
		switch cmd {
		case "":
			return
		case "quit", "exit", "q":
			fmt.Println("bye!")
			os.Exit(0)
		case "login":
			ipoSrv.Login()
		case "querylines":
			ipoSrv.SubscribeLines()
		case "showlines":
			ipoSrv.GetLinesTable()
		case "queue":
			ipoSrv.SubscribeQueueByName("G190")
		case "traceon":
			ipoSrv.SetTrace(true)
		case "traceoff":
			ipoSrv.SetTrace(false)
		case "context":
			AsyncWrite(fmt.Sprintf("current context:%s", ipoSrv.Context))
		default:
			AsyncWrite(fmt.Sprintf("you selected: %s", cmd))
		}
	}
}

func main() {
	consoleWriter = prompt.NewStdoutWriter()
	ipoSrv := &ipo.IPO{
		AsyncWrite: AsyncWrite,
	}

	fmt.Println("IPO Console use MTCTI3 protocol.")
	p := prompt.New(
		getExecuter(ipoSrv),
		completer,
		prompt.OptionTitle("IPO MTCTI tool"),
		prompt.OptionLivePrefix(func() (string, bool) {
			if ipoSrv.Context == "" {
				return ">>> ", true
			} else {
				return fmt.Sprintf("%s >>> ", ipoSrv.Context), true
			}
		}),
		prompt.OptionWriter(consoleWriter),
		prompt.OptionSuggestionBGColor(prompt.Black),
		prompt.OptionDescriptionBGColor(prompt.Black),
		prompt.OptionSuggestionTextColor(prompt.Blue),
		prompt.OptionDescriptionTextColor(prompt.Blue),
	)
	p.Run()
}
