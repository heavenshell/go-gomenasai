package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/fatih/structs"
	"github.com/flosch/pongo2"
	"github.com/hashicorp/hcl"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
	"gopkg.in/natefinch/lumberjack.v2"
)

type AppContext struct {
	appName string
	config  Config
	logger  *logrus.Logger
}

type Config struct {
	Start    time.Time
	End      time.Time
	Affected string
	Breach   Breach
	Web      Web
}

// ToString()
func (config Config) String() string {
	format := "Config(Start=%v, End=%v, Affected=%v)"
	str := fmt.Sprintf(format, config.Start, config.End, config.Affected)
	return str
}

type Scope struct {
	Start    string `hcl:"start"`
	End      string `hcl:"end"`
	Affected string `hcl:"affected"`
}

type Breach struct {
	DefacedMalware bool `hcl:"defaced_malware"`
	Address        bool `hcl:"address"`
	Name           bool `hcl:"name"`
	Gender         bool `hcl:"gender"`
	Birthday       bool `hcl:"birthday"`
	Tel            bool `hcl:"tel"`
	Card           bool `hcl:"card"`
	Securitycode   bool `hcl:"securitycode"`
	Token          bool `hcl:"token"`
}

// ToString()
func (breach Breach) String() string {
	format := "Breach(DefacedMalware=%v, Address=%v, Name=%v, Gender=%v, Birthday=%v, Tel=%v, Card=%v, Securitycode=%v, Token=%v)"
	str := fmt.Sprintf(format, breach.DefacedMalware, breach.Address, breach.Name, breach.Gender, breach.Birthday, breach.Tel, breach.Card, breach.Securitycode, breach.Token)

	return str
}

type Web struct {
	Endpoint string
}

// Time format for parse string.
const timeformat = "2006-01-02 15:04:05 -0700"

// Parse config file.
func parseConfig(appContex *AppContext, configPath string) (err error) {
	logger := appContex.logger
	logger.WithFields(logrus.Fields{"configPath": configPath}).Debug("Parse config start")

	path, err := filepath.Abs(configPath)
	if err != nil {
		logger.Fatalf("%v", err)
		return err
	}
	_, err = os.Stat(path)
	if err != nil {
		// File not found.
		logger.Fatalf("%v", err)
		return err
	}

	d, err := ioutil.ReadFile(path)
	if err != nil {
		// Fail to load
		logger.Fatalf("%v", err)
		return err
	}

	obj, err := hcl.Parse(string(d))
	if err != nil {
		logger.Fatalf("%v", err)
		return err
	}

	var scope Scope
	if err := hcl.DecodeObject(&scope, obj.Get("scope", false)); err != nil {
		logger.Fatalf("%v", err)
		return err
	}

	var breach Breach
	if err := hcl.DecodeObject(&breach, obj.Get("breach", false)); err != nil {
		logger.Fatalf("%v", err)
		return err
	}

	var web Web
	if err := hcl.DecodeObject(&web, obj.Get("web", false)); err != nil {
		logger.Fatalf("%v", err)
		return err
	}

	config := Config{}
	config.Start, err = time.Parse(timeformat, scope.Start)
	if err != nil {
		logger.Fatalf("%v", err)
		return err
	}
	config.End, err = time.Parse(timeformat, scope.End)
	if err != nil {
		logger.Fatalf("%v", err)
		return err
	}

	config.Affected = scope.Affected
	config.Breach = breach
	config.Web = web
	appContex.config = config

	logger.WithFields(logrus.Fields{"config": config}).Debug("Config")
	logger.WithFields(logrus.Fields{"configPath": configPath}).Debug("Parse config end")

	return nil
}

func (ctx AppContext) showPage(c web.C, w http.ResponseWriter, r *http.Request) {
	logger := ctx.logger
	now := time.Now()
	logger.WithFields(logrus.Fields{"now": now}).Debug("Current time is")

	if now.After(ctx.config.Start) && now.Before(ctx.config.End) {
		logger.Info(now)
		tpl, err := pongo2.DefaultSet.FromFile("sorry.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		m := structs.Map(ctx.config.Breach)
		breach := make([]string, 0)
		for k, v := range m {
			if k == "DefacedMalware" {
				continue
			}
			if v == true {
				breach = append(breach, k)
			}
		}
		logger.Info(len(breach))

		tpl.ExecuteWriter(pongo2.Context{"breach": breach}, w)

	} else {
		// Out of date time.
		logger.WithFields(
			logrus.Fields{
				"Start": ctx.config.Start,
				"End":   ctx.config.End,
			},
		).Info("Current time is out of date.")
		http.Error(w, "404 Not found.", http.StatusNotFound)
	}
}

func setupLogger(logLevel string) *logrus.Logger {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("Log level error %v", err)
	}

	logf := &lumberjack.Logger{
		Filename: "app.log",
		MaxSize:  1,
		MaxAge:   31,
	}

	out := io.MultiWriter(os.Stdout, logf)
	logger := logrus.Logger{
		Formatter: &logrus.TextFormatter{DisableColors: true},
		Level:     level,
		Out:       out,
	}
	logger.Info("Set up log finished.")

	return &logger
}

func run(ctx AppContext, address string) {
	pongo2.DefaultSet.SetBaseDirectory("templates")
	pongo2.Globals["config"] = ctx.config

	pongo2.RegisterFilter("localdate", func(in *pongo2.Value, param *pongo2.Value) (out *pongo2.Value, err *pongo2.Error) {
		date, ok := in.Interface().(time.Time)
		if !ok {
			return nil, &pongo2.Error{
				Sender:   "localdate",
				ErrorMsg: fmt.Sprintf("Date must be of type time.Time not %T ('%v')", in, in),
			}
		}
		return pongo2.AsValue(date.Local()), nil
	})

	goji.Get("/assets/*", http.FileServer(http.Dir(".")))
	goji.Get(ctx.config.Web.Endpoint, ctx.showPage)
	goji.Serve()
}

func runserver(c *cli.Context) {
	logger := setupLogger(c.String("verbose"))
	// HTTP server address(default is 127.0.0.1).
	address := c.GlobalString("bind")

	// Parse config.
	configPath := "setting.hcl"
	if c.String("conf") != "" {
		configPath = c.String("conf")
	}

	ctx := AppContext{c.App.Name, Config{}, logger}
	err := parseConfig(&ctx, configPath)
	if err != nil {
		logger.Fatalf("Parse config error %v", err)
	}

	run(ctx, address)
}

func main() {
	app := cli.NewApp()
	app.Name = "gomenasai"
	app.Usage = "Generate security incident information page."
	app.Author = "Shinya Ohyanagi"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "bind, b",
			Usage: "HTTP server address.",
			Value: "127.0.0.1:8000",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:  "runserver",
			Usage: "Run http server.",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "conf, c",
					Usage: "use configuration file",
					Value: "setting.hcl",
				},
				cli.StringFlag{
					Name:  "verbose, vv",
					Usage: "Logger verbose",
					Value: logrus.InfoLevel.String(),
				},
			},
			Action: runserver,
		},
	}
	app.Run(os.Args)
}
