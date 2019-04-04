package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/gorilla/mux"
	//	"github.com/microcosm-cc/bluemonday"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	//	"gopkg.in/russross/blackfriday.v2"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"

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
	Meta              Meta   `json:"meta" mapstructure:"meta"`
	PreBuildRequested bool   `json:"prebuild" mapstructure:"prebuild"`
	TargetFilePath    string `json:"target_file_path" mapstructure:"target_file_path"`
	SourceRepo        string `json:"source_repo" mapstructure:"source_repo"`
	SourceBranch      string `json:"source_branch" mapstructure:"source_branch"`
	LatestBuildNumber string `json:"latest_build_number" mapstructure:"latest_build_number"`
}

type ScanLog struct {
	Description string `json:"description" mapstructure:"description"`
	Logs        string `json:"logs" mapstructure:"logs"`
}

type ScanLogsGroup struct {
	ScannerName []ScanLog `json:"scanner_name" mapstructure:"scanner_name"`
}

//All the logs for builds
type BuildLogsGroup struct {
	BuildNumber    string
	PreBuildLog    string        `json:"prebuild" mapstructure:"prebuild"`
	LintLog        string        `json:"lint" mapstructure:"lint"`
	BuildLog       string        `json:"build" mapstructure:"build"`
	ScanLog        ScanLogsGroup `json:"scan" mapstructure:"scan"`
	DeliveryLog    string
	NotifyLog      string
	ScanLogContent string
}

type BuildDetails struct {
	Meta              Meta           `json:"meta" mapstructure:"meta"`
	BuildLogs         BuildLogsGroup `json:"logs" mapstructure:"logs"`
	WScanLogs         ScanLogsGroup
	RegistryDomain    string `json:"registryDomain"`
	Image             string `json:"image"`
	LastUpdated       string `json:"lastUpdated"`
	Tag               string `json:"desired_tag"`
	IsLibrary         string
	AppID             string
	JobID             string
	PreBuildRequested bool   `json:"pre-build" mapstructure:"pre-build"`
	BuildNumber       string `json:"build" mapstructure:"build"`
	FailedStage       string `json:"failed-stage" mapstructure:"failed-stage"`
	BuildStatus       string `json:"status" mapstructure:"status"`

	// Extra bits
	TargetFile string
	Readme     string
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

func readTagFileContent(app_id string, job_id string, desired_tag string, content_type string) string {
	content_path := path.Join(IMAGE_PULL_MOUNT, app_id, job_id, desired_tag, content_type)
	if app_id == "library" {
		content_path = path.Join(IMAGE_PULL_MOUNT, job_id, desired_tag, content_type)
	}
	data, err := ioutil.ReadFile(content_path)
	if err != nil {
		logrus.Errorf("Could not retrieve file content: %v\n", err)
	}
	return string(data)
}

//This function checks if the dockerfile and readme is in sync or not
//If there is new build triggered this returns false: means they are not in sync
//Else it returns true and we do not have to fetch new dockerfile and readme
func checkRepoUpdate(app_id string, job_id string, desired_tag string, latestBuildNumber string) bool {
	repoUpdated := false
	content_path := path.Join(IMAGE_PULL_MOUNT, app_id, job_id, desired_tag)
	if app_id == "library" {
		content_path = path.Join(IMAGE_PULL_MOUNT, job_id, desired_tag)
	}
	buildNumberFile := path.Join(content_path, "BuildNumber")
	processedBuildNumber := readTagFileContent(app_id, job_id, desired_tag, "BuildNumber")
	if processedBuildNumber != "" {
		if latestBuildNumber != processedBuildNumber {
			repoUpdated = false
		}
	} else {
		logrus.Info("Build is procesed for first time")
	}
	//If the directory is not already existing create it
	_, err := os.Stat(content_path)
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(content_path, 0777)
		if errDir != nil {
			logrus.Errorf("Could not create the content dir")
		}
	} else {
		logrus.Info("Content Dir is already existing")
	}

	//Write the latest build number to the file
	latestBuildNumberByte := []byte(latestBuildNumber)
	ioutil.WriteFile(buildNumberFile, latestBuildNumberByte, 0777)
	return repoUpdated
}

func copyFileContent(src string, dst string) (err error) {
	sfi, err := os.Stat(src)
	if err != nil {
		return
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("CopyFile: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			logrus.Info("File " + dst + " Already exists")
			return
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("CopyFile: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return
		}
	}
	if err = os.Link(src, dst); err == nil {
		return
	}

	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

func getDockerFileReadme(gitUrl string, gitBranch string, targetFiePath string, targetFileName string, app_id string, job_id string, desired_tag string, PreBuildRequested bool) {
	//Git clone the source repo to fetch dockerfile and readme
	branchref := "refs/heads/" + gitBranch
	clonePath := "/tmp/git_clone/" + app_id + "_" + job_id + "_" + desired_tag
	_, err := git.PlainClone(clonePath, false, &git.CloneOptions{
		URL:           gitUrl,
		ReferenceName: plumbing.ReferenceName(branchref),
		SingleBranch:  true,
	})
	if err != nil {
		logrus.Info("Could not clone the repo %v \t %v \n", err, gitBranch)
	}
	content_path := path.Join(IMAGE_PULL_MOUNT, app_id, job_id, desired_tag)

	dockerfile_path := path.Join(content_path, targetFileName)
	readme_path := path.Join(content_path, "README.md")
	err = copyFileContent(path.Join(clonePath, targetFiePath), dockerfile_path)
	if err != nil {
		logrus.Errorf("Could not copy the TargetFile %v", err)
		if PreBuildRequested == true {
			_ = copyFileContent(path.Join(IMAGE_PULL_MOUNT, "PreBuildRequestedNoTargetFile"), dockerfile_path)
		} else {
			_ = copyFileContent(path.Join(IMAGE_PULL_MOUNT, "TargetFileNotExists"), dockerfile_path)
		}
	}
	err = copyFileContent(path.Join(clonePath, "README.md"), readme_path)
	if err != nil {
		logrus.Info("Could not retrive the readme file %v", err)
	}
	clonePathExists, err := os.Stat(clonePath)
	if err != nil {
		logrus.Info("Could not get the clone location %v", err)
	} else {
		err = os.RemoveAll(clonePath)
		if err != nil {
			logrus.Info("Could not remove cloned repo %v", err)
		}
	}
	logrus.Info("Clone data is %v", clonePathExists)
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
		if project.AppID == "library" {
			project_detail.Name = project.JobID
		}
		project_detail.URI = imageList.RegistryDomain + "/" + project_detail.Name
		dataExists := false
		for _, data := range imageList.Projects {
			if data.Name == project_detail.Name {
				dataExists = true
				break
			}
		}
		if !dataExists {
			imageList.Projects = append(imageList.Projects, project_detail)
		}
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
		tag_detail.PullCount = readTagFileContent(app_id, job_id, tag.Tag, "count")
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
	if err != nil || apiTargetFile.SourceRepo == "" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "No Source Repo found")
		logrus.Errorf("Could not decode Target File %v", err)
		return
	}
	tfl := strings.Split(apiTargetFile.TargetFilePath, "/")
	targetFileName := tfl[len(tfl)-1]

	repoUpdated := checkRepoUpdate(app_id, job_id, desired_tag, apiTargetFile.LatestBuildNumber)

	if !repoUpdated {
		getDockerFileReadme(
			apiTargetFile.SourceRepo, apiTargetFile.SourceBranch,
			apiTargetFile.TargetFilePath, targetFileName, app_id, job_id, desired_tag,
			apiTargetFile.PreBuildRequested,
		)
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

	buildDetails.TargetFile = readTagFileContent(app_id, job_id, desired_tag, targetFileName)
	buildDetails.SourceRepo = apiTargetFile.SourceRepo
	buildDetails.Readme = readTagFileContent(app_id, job_id, desired_tag, "README.md")
	buildDetails.BuildLogs = apiBuildDetails.BuildLogs
	buildDetails.BuildLogs.ScanLogContent = apiBuildDetails.BuildLogs.ScanLog.ScannerName[0].Logs
	buildDetails.PreBuildRequested = apiTargetFile.PreBuildRequested
	buildDetails.BuildStatus = apiBuildDetails.BuildStatus

	if err := tmpl.ExecuteTemplate(w, "tagDetails", buildDetails); err != nil {
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
