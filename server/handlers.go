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
	BuildLogs         []BuildLogsGroup
	WScanLogs         []ScanLogsGroup
	RegistryDomain    string `json:"registryDomain"`
	Name              string `json:"name"`
	LastUpdated       string `json:"lastUpdated"`
	Tag               string `json:"tags"`
	IsLibrary         bool
	AppID             string
	JobID             string
	PreBuildRequested bool

	// Extra bits
	TargetFile string
	Readme     template.HTML
	SourceRepo string
}

var (
	//Namespace for the openshift projects
	APIURL    = "registryApi.serverAddress"
	NAMESPACE = "pipeline"
)

func getDetailsFromAPI(uri string) {
	var data map[string]string
	resp, err := http.Get(APIURL + "/v1/" + NAMESPACE + "/" + uri)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "tags",
			"URL":    r.URL,
			"method": r.Method,
		}).Errorf("getting details for %s failed: %v", url, err)

		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No tags found")
		return
	}
	defer resp.Body.Close()
	err := json.NewDecoder(resp.Body).Decode(&data)

	return data, err
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
	if vars["appid"] == "" && vars["jobid"] == "" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Empty repo")
		return
	}

	//If it is a library image we will have the appid blank
	if vars["appid"] == "" && vars["jobid"] != "" {
		vars["appid"] = "library"
	}
	repo := vars["appid"] + "/" + vars["jobid"]

	logrus.Debugf("Getting repo tag list %s", repo)

	data, err := getDetailsFromAPI(repo + "/desired-tags")
	if err != nil || len(data.tags) == 0 {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No tags found")
		return
	}

	// Sanitize and convert markdown output

	result := TagList{
		RegistryDomain: rc.reg.Domain,
		LastUpdated:    time.Now().Local().Format(time.RFC1123),
		Name:           repo,
	}

	for _, tag := range data.tags {

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
		"func":   "tagDetails",
		"URL":    r.URL,
		"method": r.Method,
	}).Info("fetching tags")

	vars := mux.Vars(r)

	// Change the path to username/container
	if vars["appid"] == "" && vars["jobid"] == "" && vars["desiredtag"] {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Empty repo")
		return
	}
	//For library images appid would be blank
	if vars["appid"] == "" && vars["jobid"] != "" && vars["desiredtag"] != "" {
		vars["appid"] = "library"
	}

	repo := vars["appid"] + "/" + vars["jobid"] + "/" + vars["desiredtag"]

	logrus.Debugf("Getting repo %s", repo)

	targetfileDetails, err := getDetailsFromAPI(repo + "/target-file")
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Target file details not found")
		return
	}
	prebuildRequested := targetfileDetails.prebuild
	targetfileLink := targetfileDetails.target - file - link

	metadata, err := getDetailsFromAPI(repo + "/metadata")
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Target file details not found")
		return
	}

	//Fix the git url without .git
	gitURL := metadata.git - url
	if strings.HasSuffix(gitURL, ".git") {
		gitURL := strings.TrimRight(gitURL, ".git")
	}

	sourceRepo := gitURL + "/tree/" + metadata.git - branch
	readmeLink := gitURL + "/" + metadata.git - branch + "/README.md"

	//TODO: retrieve Readme and targetfile content
	targetfile := retrieveContent(targetfileLink)
	readme := retrieveContent(readmeLink)

	result := TagDetails{
		RegistryDomain: rc.reg.Domain,
		LastUpdated:    time.Now().Local().Format(time.RFC1123),
		Name:           repo,
		TargetFile:     string(targetfile),
		Readme:         template.HTML(readme),
	}

	buildList, err := getDetailsFromAPI(repo + "/builds")
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No builds found for %s", repo)
		return
	}
	latestBuildNum := len(buildList.builds) + 1

	latestBuildLogs, err := getDetailsFromAPI(repo + "/" + LatestBuildNum + "/build-logs")
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Target file details not found")
		return
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
