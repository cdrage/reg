package main

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

	"gopkg.in/src-d/go-git.v4"
	yaml "gopkg.in/yaml.v2"
)

//  Both of these structs are from the "index.d/namespace" file format..
type Repos struct {
	Projects []Namespace `yaml:"Projects"`
}
type Namespace struct {
	AppID           string      `yaml:"app-id"`
	BuildContext    string      `yaml:"build-context"`
	DependsOn       StringArray `yaml:"depends-on"`
	DesiredTag      string      `yaml:"desired-tag"`
	GitBranch       string      `yaml:"git-branch"`
	GitPath         string      `yaml:"git-path"`
	GitURL          string      `yaml:"git-url"`
	ID              int         `yaml:"id"`
	JobID           string      `yaml:"job-id"`
	NotifyEmail     string      `yaml:"notify-email"`
	PrebuildContext string      `yaml:"prebuild-context"`
	PrebuildScript  string      `yaml:"prebuild-script"`
	TargetFile      string      `yaml:"target-file"`
	// Extras (not included in index.d/namespace file format)
	Dockerfile string
	Readme     string
}

const (
	repo          = "https://github.com/CentOS/container-index"
	indexFolder   = "index.d"
	indexTemplate = "index_template"
)

/*
func main() {

	Repos, err := retrieveIndex()
	if err != nil {
		log.Fatal(err)
	}

	log.Print(Repos[0].Projects[0].Dockerfile)
}
*/

// Retrieve the entire index and return []Repos

func retrieveIndex() ([]Repos, error) {

	// Initially set the variables
	var Repositories []Repos

	// Create a temporary directory in order to retrieve conainer-index
	dir, err := ioutil.TempDir("", "")
	defer os.RemoveAll(dir)

	if err != nil {
		return []Repos{}, err
	}

	// Clone
	_, err = git.PlainClone(dir, false, &git.CloneOptions{
		URL:      repo,
		Progress: os.Stdout,
	})
	if err != nil {
		return []Repos{}, err
	}

	// Iterate through the files
	files, err := ioutil.ReadDir(path.Join(dir, indexFolder))
	if err != nil {
		return []Repos{}, err
	}

	// Retrieve all the YAML information
	for _, f := range files {

		var b Repos

		// If it's the index template, skip it!
		if strings.Contains(f.Name(), indexTemplate) {
			continue
		}

		// Read in the file to memory
		content, err := ioutil.ReadFile(path.Join(dir, indexFolder, f.Name()))
		if err != nil {
			return []Repos{}, err
		}

		// Unmarshal
		err = yaml.Unmarshal(content, &b)
		if err != nil {
			return []Repos{}, err
		}

		// RETRIEVE DOCKERFILES

		// "Hacky" way to put everything into a go routine so we can http GET & retrieve at the same time!
		var wg sync.WaitGroup
		wg.Add(len(b.Projects))

		// Let's retrieve the Dockerfile!
		for i, c := range b.Projects {

			// We're going to run this in a Go routine to retrieve the Dockerfile as well as README.md files
			go func(i int, c Namespace) {
				defer wg.Done()

				// Retrieve the Dockerfile
				dockerFile, err := retrieveGitFile(c.GitURL, c.GitBranch, c.GitPath, c.TargetFile)
				if err != nil {
					log.Warningf("WARNING: Unable to retrieve '%s' '%s'. Error: %s", c.GitURL, c.GitBranch, err)
				} else {
					// Add the Dockerfile to the Namespace struct
					b.Projects[i].Dockerfile = dockerFile
				}

				// Retrieve the README
				readme, err := retrieveGitFile(c.GitURL, c.GitBranch, c.GitPath, "README.md")
				if err == nil {
					b.Projects[i].Readme = readme
				} else {
					log.Warningf("WARNING: README Dockerfile dir: Unable to retrieve '%s' '%s'. Error: %s. Trying the root directory.", c.GitURL, c.GitBranch, err)
					readme, err := retrieveGitFile(c.GitURL, c.GitBranch, "/", "README.md")
					if err == nil {
						b.Projects[i].Readme = readme
					} else {
						log.Warningf("WARNING: README root dir: Unable to retrieve '%s' '%s'. Error: %s.", c.GitURL, c.GitBranch, err)
					}
				}

			}(i, c)
		}

		// Wait for all Go Routines to complete.
		wg.Wait()

		// END RETRIEVE DOCKERFILES

		Repositories = append(Repositories, b)

	}

	return Repositories, nil
}

// Retrieves the Dockerfile and returns it as a string
func retrieveGitFile(gitURL string, gitBranch string, filePath string, gitFile string) (string, error) {

	// Format the URL, get rid of the "cruft"
	gitURL = strings.Replace(gitURL, "git://", "https://", -1)
	gitURL = strings.Replace(gitURL, "http://", "https://", -1)
	gitURL = strings.Replace(gitURL, ".git", "", -1)

	// Remove slash from other strings (since some users included and some not)
	gitURL = strings.TrimRight(gitURL, "/")
	gitBranch = strings.TrimRight(gitBranch, "/")
	filePath = strings.TrimRight(filePath, "/")
	gitFile = strings.TrimLeft(gitFile, "/")

	var url string
	if strings.Contains(gitURL, "github") {

		// Replace it with RAW directory URL
		gitURL = strings.Replace(gitURL, "github.com", "raw.githubusercontent.com", -1)

		url = fmt.Sprintf("%s/%s/%s/%s",
			gitURL,
			gitBranch,
			filePath,
			gitFile,
		)

	} else if strings.Contains(gitURL, "gitlab") {

		url = fmt.Sprintf("%s/raw/%s/%s/%s",
			gitURL,
			gitBranch,
			filePath,
			gitFile,
		)

	} else {
		return "", errors.New("Must be a github or gitlab link")
	}

	log.Debugf("fetching file: '%s'", url)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", errors.New("WARNING: Unable to retrieve " + url)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil
	}

	return string(body), nil
}

type StringArray []string

func (a *StringArray) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var multi []string
	err := unmarshal(&multi)
	if err != nil {
		var single string
		err := unmarshal(&single)
		if err != nil {
			return err
		}
		*a = []string{single}
	} else {
		*a = multi
	}
	return nil
}

type Data struct {
	Field StringArray
}
