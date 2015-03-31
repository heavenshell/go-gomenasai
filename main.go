package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"log"

	"github.com/Sirupsen/logrus"
	//log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/hashicorp/hcl"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
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
func parseConfig(appContex AppContext, configPath string) (config Config, err error) {
	logger := appContex.logger
	logger.WithFields(logrus.Fields{"configPath": configPath}).Debug("Parse config start")

	path, err := filepath.Abs(configPath)
	if err != nil {
		logger.Fatalf("%v", err)
		return Config{}, err
	}
	_, err = os.Stat(path)
	if err != nil {
		// File not found.
		logger.Fatalf("%v", err)
		return Config{}, err
	}

	d, err := ioutil.ReadFile(path)
	if err != nil {
		// Fail to load
		logger.Fatalf("%v", err)
		return Config{}, err
	}

	obj, err := hcl.Parse(string(d))
	if err != nil {
		logger.Fatalf("%v", err)
		return Config{}, err
	}

	var scope Scope
	if err := hcl.DecodeObject(&scope, obj.Get("scope", false)); err != nil {
		logger.Fatalf("%v", err)
		return Config{}, err
	}

	var breach Breach
	if err := hcl.DecodeObject(&breach, obj.Get("breach", false)); err != nil {
		logger.Fatalf("%v", err)
		return Config{}, err
	}

	var web Web
	if err := hcl.DecodeObject(&web, obj.Get("web", false)); err != nil {
		logger.Fatalf("%v", err)
		return Config{}, err
	}

	config.Start, err = time.Parse(timeformat, scope.Start)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	config.End, err = time.Parse(timeformat, scope.End)
	if err != nil {
		logger.Fatalf("%v", err)
		return Config{}, err
	}

	config.Affected = scope.Affected
	config.Breach = breach
	config.Web = web
	logger.WithFields(logrus.Fields{"config": config}).Debug("Config")

	logger.WithFields(logrus.Fields{"configPath": configPath}).Debug("Parse config end")

	return config, nil
}

func (ctx AppContext) showPage(c web.C, w http.ResponseWriter, r *http.Request) {
	//fmt.Println(ctx.config.Start)
	ctx.logger.Info(ctx.config.Start)

}

func setupLogger(logLevel string) *logrus.Logger {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("Log level error %v", err)
	}

	logf, _ := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)

	out := io.MultiWriter(os.Stdout, logf)
	logger := logrus.Logger{
		Formatter: &logrus.TextFormatter{DisableColors: true},
		Level: level,
		Out: out,
	}

	return &logger
}

func run(ctx AppContext, address string) {
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
	config, err := parseConfig(ctx, configPath)
	if err != nil {
		logger.Fatalf("Parse config error %v", err)
	}
	ctx.config = config

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