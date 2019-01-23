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
	Image       string `json:"image"`
	Tag         string `json:"desired_tag"`
	BuildStatus string `json:"build_status"`
	CreatedAt   string `json:"created_at"`
}

// A AnalysisResult holds all vulnerabilities of a scan
type TagList struct {
	Meta           Meta   `json:"meta"`
	AppID          string `json:"app_id"`
	JobID          string `json:"job_id"`
	Tags           []Tag  `json:"tags"`
	RegistryDomain string `json:"registryDomain"`
	Latest         string `json:"latest"` // The "latest" string. If latest doesn't exist, use highest version number
	Name           string
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
	Image             string `json:"name"`
	LastUpdated       string `json:"lastUpdated"`
	Tag               string `json:"desired_tag"`
	IsLibrary         bool
	AppID             string `json:"app_id"`
	JobID             string `json:"job_id"`
	PreBuildRequested bool
	TargetFileLink    string `json:"target_file_link"`

	// Extra bits
	TargetFile string
	Readme     template.HTML
	SourceRepo string
}

func getAPIData(uri string, datatype string) (interface{}, error) {
	url := APIURL + "/v1/namespaces/pipeline/" + uri

	var DataType map[string]interface{}
	DataType = make(map[string]interface{})
	DataType["Namespace"] = make([]Namespace, 1)
	DataType["ImageList"] = make([]ImageList, 1)

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

func (rc *registryController) landingPageHandler(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"func":   "tags",
		"URL":    r.URL,
		"method": r.Method,
	}).Info("Landing Page")
	http.Redirect(w, r, "/containers/", http.StatusSeeOther)
}

// Download Dockerfiles to the server
// Puts it into a specific directory.

func (rc *registryController) dockerfiles(dockerfilesDir string) error {
	/*
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
	*/
	return nil
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

/*
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
*/
//}

func (rc *registryController) tagListHandler(w http.ResponseWriter, r *http.Request) {
	/*	logrus.WithFields(logrus.Fields{
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
		repoPath := "app-ids/" + vars["appid"] + "/job-ids/" + vars["jobid"]

		logrus.Debugf("Getting repo tag list %s", repo)

		data := TagList{
			RegistryDomain: rc.reg.Domain,
		}

		//Get the full API path for the repo
		repoAPIURL := generateAPIURL(repoPath + "/desired-tags")
		//Get details from api server
		resp, err := http.Get(repoAPIURL)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"func":   "tags",
				"URL":    r.URL,
				"method": r.Method,
			}).Errorf("getting details for %s failed: %v", repo, err)
			w.WriteHeader(http.StatusNoContent)
			fmt.Fprint(w, "Error while retriving tags")
			return
		}

		//process json object for taglist
		defer resp.Body.Close()
		err = json.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"func":   "tags",
				"URL":    r.URL,
				"method": r.Method,
			}).Errorf("decoding details for %s failed: %v", repo, err)
			w.WriteHeader(http.StatusNoContent)
			fmt.Fprint(w, "Error while decoding API output")
			return
		}

		if len(data.Tags) == 0 {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "No tags found")
			return
		}

		// Sanitize and convert markdown output

		result := TagList{
			RegistryDomain: rc.reg.Domain,
			Name:           repo,
		}

		for _, tag := range data.Tags {

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
	*/
	return
}

func (rc *registryController) tagDetailsHandler(w http.ResponseWriter, r *http.Request) {
	/*
		logrus.WithFields(logrus.Fields{
			"func":   "tagDetails",
			"URL":    r.URL,
			"method": r.Method,
		}).Info("fetching tags")

		var tagDetails TagDetails

		vars := mux.Vars(r)

		// Change the path to username/container
		if vars["appid"] == "" && vars["jobid"] == "" && vars["desiredtag"] == "" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "Empty repo")
			return
		}
		//For library images appid would be blank
		if vars["appid"] == "" && vars["jobid"] != "" && vars["desiredtag"] != "" {
			vars["appid"] = "library"
		}

		repo := vars["appid"] + "/" + vars["jobid"] + "/" + vars["desiredtag"]
		repoPath := "app-ids/" + vars["appid"] + "/job-ids/" + vars["jobid"] + "/desired-tags/" + vars["desiredtag"]

		logrus.Debugf("Getting repo %s", repo)

		targetfileAPIURL := generateAPIURL(repoPath + "/target-file")

		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "Target file details not found")
			return
		}
		prebuildRequested := true
		targetfileLink := "targetfile link"

		metadataAPIURL := generateAPIURL(repoPath + "/metadata")
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
	*/
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
