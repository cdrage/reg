package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bamachrn/reg/clair"
	"github.com/bamachrn/reg/registry"
	"github.com/bamachrn/reg/utils"
	"github.com/gorilla/mux"
	wordwrap "github.com/mitchellh/go-wordwrap"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	// VERSION is the binary version.
	VERSION          = "v0.2.0"
	dockerConfigPath = ".docker/config.json"
	staticFileDir    = "static"
	dockerfileDir    = "dockerfiles"
)

var (
	updating = false
	r        *registry.Registry
	cl       *clair.Clair
	tmpl     *template.Template
)

// preload initializes any global options and configuration
// before the main or sub commands are run.
func preload(c *cli.Context) (err error) {
	if c.GlobalBool("debug") {
		logrus.SetLevel(logrus.DebugLevel)
	}

	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "reg-server"
	app.Version = VERSION
	app.Author = "@jessfraz"
	app.Email = "no-reply@butts.com"
	app.Usage = "Docker registry v2 static UI server."
	app.Before = preload
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "run in debug mode",
		},
		cli.StringFlag{
			Name:  "username, u",
			Usage: "username for the registry",
		},
		cli.StringFlag{
			Name:  "password, p",
			Usage: "password for the registry",
		},
		cli.StringFlag{
			Name:  "registry, r",
			Usage: "URL to the private registry (ex. r.j3ss.co)",
		},
		cli.BoolFlag{
			Name:  "insecure, k",
			Usage: "do not verify tls certificates of registry",
		},
		cli.BoolFlag{
			Name:  "once, o",
			Usage: "generate an output once and then exit",
		},
		cli.StringFlag{
			Name:  "port",
			Value: "8080",
			Usage: "port for server to run on",
		},
		cli.StringFlag{
			Name:  "cert",
			Usage: "path to ssl cert",
		},
		cli.StringFlag{
			Name:  "key",
			Usage: "path to ssl key",
		},
		cli.StringFlag{
			Name:  "interval",
			Value: "1h",
			Usage: "interval to generate new index.html's at",
		},
		cli.StringFlag{
			Name:  "clair",
			Usage: "url to clair instance",
		},
	}
	app.Action = func(c *cli.Context) error {
		auth, err := utils.GetAuthConfig(c.GlobalString("username"), c.GlobalString("password"), c.GlobalString("registry"))
		if err != nil {
			logrus.Fatal(err)
		}

		// create the registry client
		if c.GlobalBool("insecure") {
			r, err = registry.NewInsecure(auth, c.GlobalBool("debug"))
			if err != nil {
				logrus.Fatal(err)
			}
		} else {
			r, err = registry.New(auth, c.GlobalBool("debug"))
			if err != nil {
				logrus.Fatal(err)
			}
		}

		// create a clair instance if needed
		if c.GlobalString("clair") != "" {
			cl, err = clair.New(c.GlobalString("clair"), c.GlobalBool("debug"))
			if err != nil {
				logrus.Warnf("creation of clair failed: %v", err)
			}
		}

		// get the path to the static and dockerfiles directory
		wd, err := os.Getwd()
		if err != nil {
			logrus.Fatal(err)
		}
		staticDir := filepath.Join(wd, staticFileDir)
		dockerfilesDir := filepath.Join(wd, dockerfileDir)

		// create the template
		templateDir := filepath.Join(staticDir, "../templates")

		// make sure all the templates exist
		vulns := filepath.Join(templateDir, "vulns.html")
		if _, err := os.Stat(vulns); os.IsNotExist(err) {
			logrus.Fatalf("Template %s not found", vulns)
		}
		imageList := filepath.Join(templateDir, "image-list.html")
		if _, err := os.Stat(imageList); os.IsNotExist(err) {
			logrus.Fatalf("Template %s not found", imageList)
		}
		tagList := filepath.Join(templateDir, "tag-list.html")
		if _, err := os.Stat(tagList); os.IsNotExist(err) {
			logrus.Fatalf("Template %s not found", tagList)
		}
		tagDetails := filepath.Join(templateDir, "tag-details.html")
		if _, err := os.Stat(tagDetails); os.IsNotExist(err) {
			logrus.Fatalf("Template %s not found", tagDetails)
		}

		funcMap := template.FuncMap{
			"trim": func(s string) string {
				return wordwrap.WrapString(s, 80)
			},
			"color": func(s string) string {
				switch s = strings.ToLower(s); s {
				case "high":
					return "danger"
				case "critical":
					return "danger"
				case "defcon1":
					return "danger"
				case "medium":
					return "warning"
				case "low":
					return "info"
				case "negligible":
					return "info"
				case "unknown":
					return "default"
				default:
					return "default"
				}
			},
		}

		// Retrieve all the "footers" and "headers" templates
		tmpl = template.Must(template.New("").Funcs(funcMap).ParseGlob(templateDir + "/*.html"))

		rc := registryController{
			reg: r,
			cl:  cl,
		}

		// create the initial index
		logrus.Info("creating initial static index")
		if err := rc.repositories(staticDir); err != nil {
			logrus.Fatalf("Error creating index: %v", err)
		}

		// retrieve all the dockerfiles
		logrus.Info("retrieving dockerfiles")
		if err := rc.dockerfiles(dockerfilesDir); err != nil {
			logrus.Fatalf("Error retrieving initial dockerfiles: %v", err)
		}

		if c.GlobalBool("once") {
			logrus.Info("Output generated")
			return nil
		}

		// parse the duration
		dur, err := time.ParseDuration(c.String("interval"))
		if err != nil {
			logrus.Fatalf("parsing %s as duration failed: %v", c.String("interval"), err)
		}
		ticker := time.NewTicker(dur)

		// TODO! implement README.md updates on site
		go func() {
			// create more indexes every X minutes based off interval
			for range ticker.C {
				if !updating {
					logrus.Info("creating timer based static index")
					if err := rc.repositories(staticDir); err != nil {
						logrus.Warnf("creating static index failed: %v", err)
						updating = false
					}
				} else {
					logrus.Warnf("skipping timer based static index update for %s", c.String("interval"))
				}
			}
		}()

		// create r server
		r := mux.NewRouter()
		r.UseEncodedPath()
		r.StrictSlash(true)

		// static files handler
		staticHandler := http.FileServer(http.Dir(staticDir))

		/*
			r.HandleFunc("/repo/{username}/{container}", rc.tagsHandler)
			r.HandleFunc("/repo/{username}/{container}/", rc.tagsHandler)
			r.HandleFunc("/repo/{username}/{container}/tag/{tag}", rc.vulnerabilitiesHandler)
			r.HandleFunc("/repo/{username}/{container}/tag/{tag}/", rc.vulnerabilitiesHandler)
			r.HandleFunc("/repo/{username}/{container}/tag/{tag}/vulns", rc.vulnerabilitiesHandler)
			r.HandleFunc("/repo/{username}/{container}/tag/{tag}/vulns/", rc.vulnerabilitiesHandler)
			r.HandleFunc("/repo/{username}/{container}/tag/{tag}/vulns.json", rc.vulnerabilitiesHandler)
		*/

		// Make sure we handle css, img and js without the container handler overriding anything
		r.PathPrefix("/css/").Handler(http.StripPrefix("/", staticHandler))
		r.PathPrefix("/img/").Handler(http.StripPrefix("/", staticHandler))
		r.PathPrefix("/js/").Handler(http.StripPrefix("/", staticHandler))
		r.PathPrefix("/about").Handler(http.StripPrefix("/", staticHandler))
		r.PathPrefix("/containers").Handler(http.StripPrefix("/", staticHandler))

		// container handler
		r.HandleFunc("/{username}/{container}", rc.tagListHandler)
		r.HandleFunc("/{username}/{container}/", rc.tagListHandler)

		r.HandleFunc("/{container}", rc.tagListHandler)
		r.HandleFunc("/{container}/", rc.tagListHandler)

		// container handler
		r.HandleFunc("/{username}/{container}/{desired-tag}", rc.tagDetailsHandler)
		r.HandleFunc("/{username}/{container}/{desired-tag}/", rc.tagDetailsHandler)

		// Landing page to containers
		r.HandleFunc("/", rc.landingPageHandler)

		r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			t, err := route.GetPathTemplate()
			if err != nil {
				return err
			}
			fmt.Println(t)
			return nil
		})

		// set up the server
		port := c.String("port")
		server := &http.Server{
			Addr:    ":" + port,
			Handler: r,
		}
		logrus.Infof("Starting server on port %q", port)
		if c.String("cert") != "" && c.String("key") != "" {
			logrus.Fatal(server.ListenAndServeTLS(c.String("cert"), c.String("key")))
		} else {
			logrus.Fatal(server.ListenAndServe())
		}

		return nil
	}

	app.Run(os.Args)
}
