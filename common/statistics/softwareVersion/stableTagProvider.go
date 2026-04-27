package softwareVersion

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type stableTagProvider struct {
	stableTagLocation string
	httpClient        *http.Client
}

// NewStableTagProvider returns a new instance of stableTagProvider
func NewStableTagProvider(stableTagLocation string) *stableTagProvider {
	transport := &http.Transport{
		DisableKeepAlives: true,
	}

	return &stableTagProvider{
		stableTagLocation: stableTagLocation,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// FetchTagVersion will call the provided URL and will fetch the software version
func (stp *stableTagProvider) FetchTagVersion() (string, error) {
	resp, err := stp.httpClient.Get(stp.stableTagLocation)
	if err != nil {
		return "", err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Debug(err.Error())
		}
	}()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var tag tagVersion
	if err = json.Unmarshal(respBytes, &tag); err != nil {
		return "", err
	}

	return tag.TagVersion, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (stp *stableTagProvider) IsInterfaceNil() bool {
	return stp == nil
}
