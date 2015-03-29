package main

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/codegangsta/cli"
	"github.com/hashicorp/hcl"
)

type Config struct {
	Start    time.Time
	End      time.Time
	Affected string
	Breach   Breach
	Web      Web
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

type Web struct {
	Endpoint string
}

// Time format for parse string.
const timeformat = "2006-01-02 15:04:05 -0700"

// Parse config file.
func parseConfig(configPath string) (config Config, err error) {
	path, err := filepath.Abs(configPath)
	if err != nil {
		log.Fatalf("%v", err)
		return Config{}, err
	}
	_, err = os.Stat(path)
	if err != nil {
		// File not found.
		log.Fatalf("%v", err)
		return Config{}, err
	}

	d, err := ioutil.ReadFile(path)
	if err != nil {
		// Fail to load
		log.Fatalf("%v", err)
		return Config{}, err
	}

	obj, err := hcl.Parse(string(d))
	if err != nil {
		log.Fatalf("%v", err)
		return Config{}, err
	}

	var scope Scope
	if err := hcl.DecodeObject(&scope, obj.Get("scope", false)); err != nil {
		log.Fatalf("%v", err)
		return Config{}, err
	}

	var breach Breach
	if err := hcl.DecodeObject(&breach, obj.Get("breach", false)); err != nil {
		log.Fatalf("%v", err)
		return Config{}, err
	}

	var web Web
	if err := hcl.DecodeObject(&web, obj.Get("web", false)); err != nil {
		log.Fatalf("%v", err)
		return Config{}, err
	}

	config.Start, err = time.Parse(timeformat, scope.Start)
	if err != nil {
		log.Fatalf("%v", err)
	}
	config.End, err = time.Parse(timeformat, scope.End)
	if err != nil {
		log.Fatalf("%v", err)
		return Config{}, err
	}

	config.Affected = scope.Affected
	config.Breach = breach
	config.Web = web

	return config, nil
}

func run(address string, port int, config Config) {

}

func runserver(c *cli.Context) {
	// HTTP server address(default is 127.0.0.1).
	address := c.String("bind")

	// HTTP Port(default is 8000).
	port := c.Int("port")

	// Parse config.
	configPath := "setting.hlc"
	if c.GlobalString("conf") != "" {
		configPath = c.GlobalString("conf")
	}
	config, err := parseConfig(configPath)
	if err != nil {
	}

	run(address, port, config)
}

func main() {
	app := cli.NewApp()
	app.Name = "gomenasai"
	app.Usage = "Generate security incident information page."
	app.Author = "Shinya Ohyanagi"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name: "conf, c", Usage: "use configuration file",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:  "runserver",
			Usage: "Run http server.",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "bind, b",
					Usage: "HTTP server address.",
					Value: "127.0.0.1",
				},
				cli.IntFlag{
					Name:  "port, p",
					Usage: "HTTP server port.",
					Value: 8000,
				},
			},
			Action: runserver,
		},
	}
	app.Run(os.Args)
}
