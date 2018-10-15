package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/bamachrn/reg/clair"
	"github.com/bamachrn/reg/registry"
	"github.com/gorilla/mux"
	"github.com/microcosm-cc/bluemonday"
	"github.com/sirupsen/logrus"
	"gopkg.in/russross/blackfriday.v2"
)

type registryController struct {
	reg *registry.Registry
	cl  *clair.Clair
}

type v1Compatibility struct {
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
}

// A Repository holds data after a vulnerability scan of a single repo
type Repository struct {
	Name                string    `json:"name"`
	Tag                 string    `json:"tag"`
	Created             time.Time `json:"created"`
	URI                 string    `json:"uri"`
	Tags                int       `json:"tags"`
	BuildStatus         string
	VulnerabilityReport clair.VulnerabilityReport `json:"vulnerability"`
	AppID               string
	JobID               string
}

// A AnalysisResult holds all vulnerabilities of a scan
type TagList struct {
	Repositories   []Repository `json:"repositories"`
	RegistryDomain string       `json:"registryDomain"`
	Tags           []string     `json:"tags"`
	Latest         string       `json:"latest"` // The "latest" string. If latest doesn't exist, use highest version number
	AppID          string
	JobID          string
}

type ScanLogsGroup struct {
	RPMUpdate    string
	RPMVerify    string
	ContainerCap string
	MiscUpdate   string
}

//All the logs for builds
type BuildLogsGroup struct {
	BuildNumber int
	PreBuildLog string
	LintLog     string
	BuildLog    string
	ScanLog     []ScanLogsGroup
	DeliveryLog string
	NotifyLog   string
}

type TagDetails struct {
	BuildLogs      []BuildLogsGroup
	WScanLogs      []ScanLogsGroup
	RegistryDomain string `json:"registryDomain"`
	Name           string `json:"name"`
	LastUpdated    string `json:"lastUpdated"`
	Tag            string `json:"tags"`
	IsLibrary      bool
	AppID          string
	JobID          string

	// Extra bits
	Dockerfile string
	Readme     template.HTML
	SourceRepo string
}

// Download Dockerfiles to the server
// Puts it into a specific directory.

func (rc *registryController) dockerfiles(dockerfilesDir string) error {

	// Retrieve the catalog
	logrus.Info("fetching catalog for dockerfile retrieval")

	result := AnalysisResult{
		RegistryDomain: rc.reg.Domain,
		LastUpdated:    time.Now().Local().Format(time.RFC1123),
	}

	repoList, err := r.Catalog("")
	if err != nil {
		return fmt.Errorf("getting catalog failed: %v", err)
	}

	for _, repo := range repoList {
		repoURI := fmt.Sprintf("%s/%s", rc.reg.Domain, repo)
		r := Repository{
			Name: repo,
			URI:  repoURI,
		}
		result.Repositories = append(result.Repositories, r)
	}

	// Retrieve all Dockerfiles :)
	logrus.Info("retrieving Dockerfiles (http get)")

	// TODO: Instead of grabbing the *first* id in the cccp.yaml file, possible *show* Dockerfile from each tag instead in the HTML?
	repos, err := retrieveIndex()
	if err != nil {
		return fmt.Errorf("getting dockerfiles from index failed: %v", err)
	}

	for _, repo := range repos {

		// TODO: A bit "hacky" but this will do for now.
		namespace := repo.Projects[0].AppID

		for _, c := range repo.Projects {

			// TODO: A bit "hacky" but this will do for now.
			container := c.JobID
			dockerfileContents := c.Dockerfile
			readme := c.Readme

			dockerfilePath := path.Join(dockerfilesDir, namespace, container)

			// Create the folder if it's not already there
			logrus.Debugf("creating dir %s", dockerfilePath)
			err = os.MkdirAll(dockerfilePath, os.ModePerm)
			if err != nil {
				return err
			}

			// Create / open the file
			logrus.Debugf("creating/opening file %s", path.Join(dockerfilePath, "Dockerfile"))
			f, err := os.Create(path.Join(dockerfilePath, "Dockerfile"))
			defer f.Close()
			if err != nil {
				return err
			}

			// Write Dockerfile contents to file if Dockerfile != ""
			if dockerfileContents != "" {
				_, err = io.Copy(f, strings.NewReader(dockerfileContents))
				if err != nil {
					return errors.Wrap(err, "Unable to write to Dockerfile")
				}
			}

			// Create / open the file
			logrus.Debugf("creating/opening file %s", path.Join(dockerfilePath, "README.md"))
			readmeContents, err := os.Create(path.Join(dockerfilePath, "README.md"))
			defer readmeContents.Close()
			if err != nil {
				return err
			}

			// Write README contents to file if Readme != ""
			if readme != "" {
				// Convert the readme to valid (safe) HTML
				unsafe := blackfriday.Run([]byte(readme))
				html := bluemonday.UGCPolicy().SanitizeBytes(unsafe)

				_, err = io.Copy(readmeContents, strings.NewReader(string(html)))
				if err != nil {
					return errors.Wrap(err, "Unable to write to Readme")
				}
			}

			if err != nil {
				return err
			}

		}
	}

	return nil
}

func (rc *registryController) repositories(staticDir string) error {

	updating = true
	logrus.Info("fetching catalog")

	result := AnalysisResult{
		RegistryDomain: rc.reg.Domain,
		LastUpdated:    time.Now().Local().Format(time.RFC1123),
	}

	repoList, err := r.Catalog("")
	if err != nil {
		return fmt.Errorf("getting catalog failed: %v", err)
	}

	for _, repo := range repoList {
		repoURI := fmt.Sprintf("%s/%s", rc.reg.Domain, repo)

		// Retrieve number of tags
		tags, err := rc.reg.Tags(repo)
		if err != nil {
			logrus.Warningf("Ignoring user %s, unable to retrieve tags: %v.", repo, err)
		}

		// If there are actually tags, we add this to the main site, otherwise, we ignore it.
		if len(tags) != 0 {
			r := Repository{
				Name: repo,
				URI:  repoURI,
				Tags: len(tags),
			}
			result.Repositories = append(result.Repositories, r)
		}

	}

	// parse & execute the template
	logrus.Info("executing the template containers")

	// Use /repo/index.html instead
	path := filepath.Join(staticDir, "/containers/index.html")
	if err := os.MkdirAll(filepath.Dir(path), 0644); err != nil {
		return err
	}
	logrus.Debugf("creating/opening file %s", path)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := tmpl.ExecuteTemplate(f, "containers", result); err != nil {
		f.Close()
		return fmt.Errorf("execute template containers failed: %v", err)
	}

	updating = false
	return nil
}

func (rc *registryController) landingPageHandler(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"func":   "tags",
		"URL":    r.URL,
		"method": r.Method,
	}).Info("Landing Page")
	http.Redirect(w, r, "/containers/", http.StatusSeeOther)
}

func (rc *registryController) tagListHandler(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"func":   "tagList",
		"URL":    r.URL,
		"method": r.Method,
	}).Info("fetching list of tags")

	vars := mux.Vars(r)

	// Change the path to username/container
	if vars["username"] == "" && vars["container"] == "" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Empty repo")
		return
	}

	repo := vars["username"] + "/" + vars["container"]
	if vars["username"] == "" && vars["container"] != "" {
		repo = vars["container"]
	}

	logrus.Debugf("Getting repo %s", repo)

	tags, err := rc.reg.Tags(repo)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "tags",
			"URL":    r.URL,
			"method": r.Method,
		}).Errorf("getting tags for %s failed: %v", repo, err)

		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No tags found")
		return
	}

	// Error out if there are no tags / images (the above err != nil does not error out when nothing has been found)
	if len(tags) == 0 {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No tags found")
		return
	}

	// Let's get the (saved) Dockerfile

	// Get the current executable directory
	wd, err := os.Getwd()
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Info("current working dir: %s", wd)

	//TODO: fix these temporary values after API is working
	gitrepourl := dockerfileDir

	// TODO retrieve the namespace.yaml file

	// Sanitize and convert markdown outputa

	result := AnalysisResult{
		RegistryDomain: rc.reg.Domain,
		LastUpdated:    time.Now().Local().Format(time.RFC1123),
		Name:           repo,
		SourceRepo:     gitrepourl,
	}

	for _, tag := range tags {
		// get the manifest
		m1, err := rc.reg.ManifestV1(repo, tag)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"func":   "tags",
				"URL":    r.URL,
				"method": r.Method,
				"repo":   repo,
				"tag":    tag,
			}).Errorf("getting v1 manifest for %s:%s failed: %v", repo, tag, err)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "Manifest not found")
			return
		}

		var createdDate time.Time
		for _, h := range m1.History {
			var comp v1Compatibility

			if err := json.Unmarshal([]byte(h.V1Compatibility), &comp); err != nil {
				logrus.WithFields(logrus.Fields{
					"func":   "tags",
					"URL":    r.URL,
					"method": r.Method,
				}).Errorf("unmarshal v1 manifest for %s:%s failed: %v", repo, tag, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			createdDate = comp.Created
			break
		}
		//TODO: Get the actual build status from the API
		latestbuildstatus := "success"

		repoURI := fmt.Sprintf("%s/%s", rc.reg.Domain, repo)
		if tag != "latest" {
			repoURI += ":" + tag
		}
		rp := Repository{
			Name:        repo,
			Tag:         tag,
			BuildStatus: latestbuildstatus,
			URI:         repoURI,
			Created:     createdDate,
		}

		result.Tags = append(result.Tags, rp.Tag)
		result.Repositories = append(result.Repositories, rp)
	}

	if err := tmpl.ExecuteTemplate(w, "tagList", result); err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "tags",
			"URL":    r.URL,
			"method": r.Method,
		}).Errorf("template rendering failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	return
}

func (rc *registryController) tagDetailsHandler(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"func":   "tags",
		"URL":    r.URL,
		"method": r.Method,
	}).Info("fetching tags")

	vars := mux.Vars(r)

	// Change the path to username/container
	if vars["username"] == "" && vars["container"] == "" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Empty repo")
		return
	}

	repo := vars["username"] + "/" + vars["container"]
	if vars["username"] == "" && vars["container"] != "" {
		repo = vars["container"]
	}

	logrus.Debugf("Getting repo %s", repo)

	tags, err := rc.reg.Tags(repo)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "tags",
			"URL":    r.URL,
			"method": r.Method,
		}).Errorf("getting tags for %s failed: %v", repo, err)

		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No tags found")
		return
	}

	// Error out if there are no tags / images (the above err != nil does not error out when nothing has been found)
	if len(tags) == 0 {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No tags found")
		return
	}

	// Let's get the (saved) Dockerfile

	// Get the current executable directory
	wd, err := os.Getwd()
	if err != nil {
		logrus.Fatal(err)
	}

	// Retrieve Dockerfile
	dockerfile, err := ioutil.ReadFile(filepath.Join(wd, dockerfileDir, repo, "Dockerfile"))
	if err != nil {
		logrus.Warningf("Unable to retrieve Dockerfile from directory:", err)
	}

	// Retrieve README.md
	readme, err := ioutil.ReadFile(filepath.Join(wd, dockerfileDir, repo, "README.md"))
	if err != nil {
		logrus.Warningf("Unable to retrieve README.md from directory:", err)
	}

	// TODO retrieve the namespace.yaml file

	// Sanitize and convert markdown outputa

	result := AnalysisResult{
		RegistryDomain: rc.reg.Domain,
		LastUpdated:    time.Now().Local().Format(time.RFC1123),
		Name:           repo,
		Dockerfile:     string(dockerfile),
		Readme:         template.HTML(readme),
	}

	for _, tag := range tags {
		// get the manifest
		m1, err := rc.reg.ManifestV1(repo, tag)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"func":   "tags",
				"URL":    r.URL,
				"method": r.Method,
				"repo":   repo,
				"tag":    tag,
			}).Errorf("getting v1 manifest for %s:%s failed: %v", repo, tag, err)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "Manifest not found")
			return
		}

		var createdDate time.Time
		for _, h := range m1.History {
			var comp v1Compatibility

			if err := json.Unmarshal([]byte(h.V1Compatibility), &comp); err != nil {
				logrus.WithFields(logrus.Fields{
					"func":   "tags",
					"URL":    r.URL,
					"method": r.Method,
				}).Errorf("unmarshal v1 manifest for %s:%s failed: %v", repo, tag, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			createdDate = comp.Created
			break
		}

		repoURI := fmt.Sprintf("%s/%s", rc.reg.Domain, repo)
		if tag != "latest" {
			repoURI += ":" + tag
		}
		rp := Repository{
			Name:    repo,
			Tag:     tag,
			URI:     repoURI,
			Created: createdDate,
		}

		result.Tags = append(result.Tags, rp.Tag)
		result.Repositories = append(result.Repositories, rp)
	}

	// Lets find out the "latest" image.
	// if "latest" tag does not exist, use the highest version

	if stringInSlice("latest", result.Tags) == true {
		result.Latest = "latest"
	} else {
		logrus.Debugf("No 'latest' tag found for %s", result.Name)
		sort.Sort(sort.Reverse(sort.StringSlice(result.Tags)))
		result.Latest = result.Tags[0]
	}

	if err := tmpl.ExecuteTemplate(w, "tagList", result); err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "tags",
			"URL":    r.URL,
			"method": r.Method,
		}).Errorf("template rendering failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	return
}

func (rc *registryController) vulnerabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"func":   "vulnerabilities",
		"URL":    r.URL,
		"method": r.Method,
	}).Info("fetching vulnerabilities")

	vars := mux.Vars(r)

	// Change the path to username/container
	if vars["username"] == "" || vars["container"] == "" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Empty repo")
		return
	}
	repo := vars["username"] + "/" + vars["container"]

	// Retrieve tag
	tag := vars["tag"]

	if tag == "" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Empty tag")
		return
	}

	m1, err := rc.reg.ManifestV1(repo, tag)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "vulnerabilities",
			"URL":    r.URL,
			"method": r.Method,
			"repo":   repo,
			"tag":    tag,
		}).Errorf("getting v1 manifest for %s:%s failed: %v", repo, tag, err)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Manifest not found")
		return
	}

	result := clair.VulnerabilityReport{}

	if rc.cl != nil {
		result, err = rc.cl.Vulnerabilities(rc.reg, repo, tag, m1)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"func":   "vulnerabilities",
				"URL":    r.URL,
				"method": r.Method,
			}).Errorf("vulnerability scanning for %s:%s failed: %v", repo, tag, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	if strings.HasSuffix(r.URL.String(), ".json") {
		js, err := json.Marshal(result)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"func":   "vulnerabilities",
				"URL":    r.URL,
				"method": r.Method,
			}).Errorf("json marshal failed: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "vulns", result); err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "vulnerabilities",
			"URL":    r.URL,
			"method": r.Method,
		}).Errorf("template rendering failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	return
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
