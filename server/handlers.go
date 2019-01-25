package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"reg/clair"
	"reg/registry"
)

type registryController struct {
	reg *registry.Registry
	cl  *clair.Clair
}

type v1Compatibility struct {
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
}

type Meta struct {
	APIVersion string `json:"apiVersion"`
	TimeStamp  string `json:"timestamp"`
}

type NameSpaces struct {
	Meta       Meta     `json:"meta"`
	Namespaces []string `json:"namespaces"`
}

// A Project holds data for a single image in registry
type Project struct {
	Name              string `json:"name"`
	Tag               string `json:"desired_tag" mapstructure:"desired_tag"`
	LastUpdated       string `json:"last_updated"`
	URI               string `json:"uri"`
	LatestBuildStatus string `json:"latest_build_status"`
	AppID             string `json:"app_id" mapstructure:"app_id"`
	JobID             string `json:"job_id" mapstructure:"job_id"`
}

//An ImageList holds list of images avaialable
type ImageList struct {
	RegistryDomain string
	LastUpdated    string
	Meta           Meta      `json:"meta"`
	Projects       []Project `json:"projects" mapstructure:"projects"`
}

type Tag struct {
	Image       string `json:"image" mapstructure:"image"`
	Tag         string `json:"desired_tag" mapstructure:"desired_tag"`
	BuildStatus string `json:"build_status" mapstructure:"build_status"`
	PullCount   string `json:"pull_count"`
	CreatedAt   string `json:"created_at"`
}

// A TagList holds all the tags for specific appid and jobid
type TagList struct {
	Meta           Meta   `json:"meta" mapstructure:"meta"`
	AppID          string `json:"app_id" mapstructure:"app_id"`
	JobID          string `json:"job_id" mapstructure:"job_id"`
	Tags           []Tag  `json:"tags" mapstructure:"tags"`
	RegistryDomain string `json:"registryDomain"`
	Latest         string `json:"latest"` // The "latest" string. If latest doesn't exist, use highest version number
	Name           string
	LastUpdated    string
}

type TargetFile struct {
	Meta              Meta   `json:"meta"`
	PreBuildRequested bool   `json:"prebuild"`
	TargetFileLink    string `json:"target_file_link"`
	SourceRepo        string `json:"source_repo"`
}

type ScanLog struct {
	Description string        `json:"description" mapstructure:"description"`
	Logs        template.HTML `json:"logs" mapstructure:"logs"`
}

type ScanLogsGroup struct {
	ScannerName []ScanLog `json:"scanner_name"`
}

//All the logs for builds
type BuildLogsGroup struct {
	BuildNumber string
	PreBuildLog template.HTML `json:"prebuild"`
	LintLog     template.HTMl `json:"lint"`
	BuildLog    template.HTML `json:"build"`
	ScanLog     ScanLogsGroup `json:"scan"`
	DeliveryLog string
	NotifyLog   string
}

type BuildDetails struct {
	Meta              Meta           `json:"meta"`
	BuildLogs         BuildLogsGroup `json:"logs"`
	WScanLogs         ScanLogsGroup
	RegistryDomain    string `json:"registryDomain"`
	Image             string `json:"image"`
	LastUpdated       string `json:"lastUpdated"`
	Tag               string `json:"desired_tag"`
	IsLibrary         bool
	AppID             string `json:"app_id"`
	JobID             string `json:"job_id"`
	PreBuildRequested bool

	// Extra bits
	TargetFile template.HTML
	Readme     template.HTML
	SourceRepo string
}

func getImageCreatedDate(rc *registryController, image string, tag string) string {
	m1, err := rc.reg.ManifestV1(image, tag)
	if err != nil {
		logrus.Warningf("Manifest not found in registry")
		return ""
	}
	var createdDate time.Time
	for _, h := range m1.History {
		var comp v1Compatibility

		if err := json.Unmarshal([]byte(h.V1Compatibility), &comp); err != nil {
			logrus.Errorf("unmarshal v1 manifest for %s:%s failed: %v", image, tag, err)
			return ""
		}
		createdDate = comp.Created
		break
	}
	return createdDate.Local().Format(time.RFC822)
}

func getAPIData(uri string, datatype string) (interface{}, error) {
	url := APIURL + "/v1/namespaces/" + NAMESPACE + "/" + uri

	var DataType map[string]interface{}
	DataType = make(map[string]interface{})
	DataType["Namespace"] = make([]Namespace, 1)
	DataType["ImageList"] = make([]ImageList, 1)
	DataType["TagList"] = make([]TagList, 1)
	DataType["TargetFile"] = make([]TargetFile, 1)
	DataType["BuildDetails"] = make([]BuildDetails, 1)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		logrus.Errorf("Could not fetch details from API %v\n", uri)
		return nil, err
	}
	defer resp.Body.Close()

	data := DataType[datatype]
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		logrus.Errorf("Could not Decode API data to struct %v\n", uri)
		return nil, err
	}

	return data, err
}

func getImagePullCount(app_id string, job_id string, desired_tag string) string {
	return "pull_count"
}

func retrieveContent(contentLink string) string {
	resp, err := http.Get(contentLink)
	if err != nil {
		fmt.Printf("Error retirving content")
		return ""
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Unable to read content")
		return ""
	}
	return string(content)
}

func retrieveHTMLContent(contentLink string) template.HTML {

	resp, err := http.Get(contentLink)
	if err != nil {
		fmt.Printf("Error retirving content")
		return ""
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Unable to read content")
		return ""
	}

	var html template.HTML
	unsafe := blackfriday.Run([]byte(content))
	html = bluemonday.UGCPolicy().SanitizeBytes(unsafe)

	return html
}

func (rc *registryController) landingPageHandler(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"func":   "tags",
		"URL":    r.URL,
		"method": r.Method,
	}).Info("Landing Page")
	http.Redirect(w, r, "/containers/", http.StatusSeeOther)
}

//This function renders the landing page of registry
//i.e. listing of images available in the registry
func (rc *registryController) imageListHandler(w http.ResponseWriter, r *http.Request) {
	var apiProjects ImageList

	api_data, err := getAPIData("projects", "ImageList")
	if err != nil {
		logrus.Errorf("Could not retrieve image list %v", err)
		return
	}

	err = mapstructure.Decode(api_data, &apiProjects)
	if err != nil || len(apiProjects.Projects) == 0 {
		logrus.Errorf("Could not decode image list %v", err)
		return
	}

	imageList := ImageList{
		RegistryDomain: rc.reg.Domain,
		LastUpdated:    time.Now().Local().Format(time.RFC822),
	}

	for _, project := range apiProjects.Projects {
		var project_detail Project
		project_detail.Name = project.AppID + "/" + project.JobID
		project_detail.URI = imageList.RegistryDomain + "/" + project_detail.Name
		imageList.Projects = append(imageList.Projects, project_detail)
	}

	if err := tmpl.ExecuteTemplate(w, "imageList", imageList); err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "images",
			"URL":    r.URL,
			"method": r.Method,
		}).Errorf("template rendering failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	return
}

//This function renders all the tags with build status for specific app_id and job_id
func (rc *registryController) tagListHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	app_id := vars["appid"]
	job_id := vars["jobid"]

	// Change the path to username/container
	if app_id == "" && job_id == "" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Empty repo")
		return
	}

	imageName := app_id + "/" + job_id

	//If it is a library image we will have the appid blank
	if app_id == "" && job_id != "" {
		app_id = "library"
		imageName = job_id
	}

	repo := app_id + "/" + job_id
	repoPath := "app-ids/" + app_id + "/job-ids/" + job_id

	logrus.Debugf("Getting repo tag list %s", repo)

	var apiTags TagList

	api_data, err := getAPIData(repoPath+"/desired-tags", "TagList")
	if err != nil {
		logrus.Errorf("Could not retrieve tag list %v", err)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No tags found")
		return
	}

	err = mapstructure.Decode(api_data, &apiTags)
	if err != nil || len(apiTags.Tags) == 0 {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No tags found")
		logrus.Errorf("Could not decode tag list %v", err)
		return
	}

	tagList := TagList{
		RegistryDomain: rc.reg.Domain,
		LastUpdated:    time.Now().Local().Format(time.RFC822),
		Name:           imageName,
		Latest:         "latest",
	}

	for _, tag := range apiTags.Tags {
		var tag_detail Tag
		tag_detail.Image = imageName
		tag_detail.BuildStatus = tag.BuildStatus
		tag_detail.Tag = tag.Tag
		tag_detail.PullCount = getImagePullCount(app_id, job_id, tag.Tag)
		tag_detail.CreatedAt = getImageCreatedDate(rc, imageName, tag.Tag)

		tagList.Tags = append(tagList.Tags, tag_detail)
	}

	if err := tmpl.ExecuteTemplate(w, "tagList", tagList); err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "images",
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

	var tagDetails TagDetails

	vars := mux.Vars(r)

	app_id := vars["appid"]
	job_id := vars["jobid"]
	desired_tag := vars["desiredtag"]

	// Check if it is a blank request
	if app_id == "" && job_id == "" && desired_tag == "" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Empty repo")
		return
	}

	imageName := app_id + "/" + job_id
	//For library images appid would be blank
	if app_id == "" && job_id != "" && desired_tag != "" {
		app_id = "library"
		imageName = job_id
	}

	repo := app_id + "/" + job_id + "/" + desired_tag
	repoPath := "app-ids/" + app_id + "/job-ids/" + job_id + "/desired-tags/" + desired_tag

	logrus.Debugf("Getting repo %s", repo)

	var apiTargetFile TargetFile

	api_data, err := getAPIData(repoPath+"/target-file", "TargetFile")
	if err != nil {
		logrus.Errorf("Could not retrieve target file details %v", err)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No Target File found")
		return
	}

	err = mapstructure.Decode(api_data, &apiTargetFile)
	if err != nil || apiTargetFile.SourceRepo == nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No Source Repo found")
		logrus.Errorf("Could not decode Target File %v", err)
		return
	}

	var apiBuildDetails BuildDetails

	api_data, err = getAPIData(repoPath+"/builds/lastBuild/logs", "BuildDetails")
	if err != nil {
		logrus.Errorf("Could not retrieve build details %v", err)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No Build Logs found")
		return
	}

	err = mapstructure.Decode(api_data, &apiBuildDetails)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No Logs found")
		logrus.Errorf("Could not decode Build Details %v", err)
		return
	}

	buildDetails := BuildDetails{
		RegistryDomain: rc.reg.Domain,
		LastUpdated:    time.Now().Local().Format(time.RFC822),
		Image:          imageName,
		Tag:            desired_tag,
	}

	buildDetails.TargetFile = retrieveContent(apiTargetFile.TargetFileLink)
	buildDetails.SourceRepo = apiTargetFile.SourceRepo
	buildDetails.Readme = retrieveContent(apiTargetFile.SourceRepo + "README.md")
	buildDetails.BuildLogs = apiBuildDetails.BuildLogs
	buildDetails.PreBuildRequested = apiTargetFile.PreBuildRequested

	if err := tmpl.ExecuteTemplate(w, "tagList", buildDetails); err != nil {
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
	/*
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
	*/
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
