package dockerctl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// BuildImage builds tag from a tar build context.
//
// The Engine reports progress as a stream of JSON objects and signals failure
// inside that stream rather than with an HTTP status, so the body has to be
// read to the end to know whether the build worked.
func (c *Client) BuildImage(ctx context.Context, tag string, tarContext []byte, onProgress func(string)) error {
	q := url.Values{
		"t":          {tag},
		"dockerfile": {"Dockerfile"},
		"rm":         {"1"},
		"forcerm":    {"1"},
		"pull":       {"0"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.url("/build", q), bytes.NewReader(tarContext))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("build %s: %w", tag, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("build %s: %s: %s", tag, resp.Status, strings.TrimSpace(string(msg)))
	}

	dec := json.NewDecoder(resp.Body)
	for {
		var line struct {
			Stream      string `json:"stream"`
			Error       string `json:"error"`
			ErrorDetail *struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}

		if err := dec.Decode(&line); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("build %s: reading progress: %w", tag, err)
		}

		if line.Error != "" {
			detail := line.Error
			if line.ErrorDetail != nil && line.ErrorDetail.Message != "" {
				detail = line.ErrorDetail.Message
			}
			return fmt.Errorf("build %s failed: %s", tag, strings.TrimSpace(detail))
		}
		if s := strings.TrimSpace(line.Stream); s != "" && onProgress != nil {
			onProgress(s)
		}
	}
}

// ImageExists reports whether the daemon already has the tag, so an unchanged
// build context does not cost a rebuild.
//
// The tag goes into the path unescaped on purpose. An image name's slash is a
// path separator to the Engine API, and percent-encoding it produces a name
// the daemon rejects outright.
func (c *Client) ImageExists(ctx context.Context, tag string) (bool, error) {
	resp, err := c.do(ctx, http.MethodGet, "/images/"+tag+"/json", nil, nil)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "No such image") {
			return false, nil
		}
		return false, err
	}
	resp.Body.Close()
	return true, nil
}

// DeviceMapping passes a host device through to the container. The VPN needs
// /dev/net/tun to create its tunnel.
type DeviceMapping struct {
	PathOnHost        string `json:"PathOnHost"`
	PathInContainer   string `json:"PathInContainer"`
	CgroupPermissions string `json:"CgroupPermissions"`
}

type PortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type RestartPolicy struct {
	Name string `json:"Name"`
}

type HostConfig struct {
	Binds         []string                 `json:"Binds,omitempty"`
	CapAdd        []string                 `json:"CapAdd,omitempty"`
	Devices       []DeviceMapping          `json:"Devices,omitempty"`
	PortBindings  map[string][]PortBinding `json:"PortBindings,omitempty"`
	RestartPolicy RestartPolicy            `json:"RestartPolicy"`
}

type ContainerSpec struct {
	Image        string              `json:"Image"`
	Env          []string            `json:"Env,omitempty"`
	Labels       map[string]string   `json:"Labels,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	HostConfig   HostConfig          `json:"HostConfig"`
}

// CreateContainer creates a container and returns its id.
func (c *Client) CreateContainer(ctx context.Context, name string, spec ContainerSpec) (string, error) {
	resp, err := c.do(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, spec)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var created struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", err
	}
	return created.ID, nil
}

// RemoveContainer deletes a container, stopping it first if needed.
func (c *Client) RemoveContainer(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/containers/"+id,
		url.Values{"force": {"1"}}, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ListByLabel returns every container carrying the given label.
func (c *Client) ListByLabel(ctx context.Context, label string) ([]Container, error) {
	filters, err := json.Marshal(map[string][]string{"label": {label}})
	if err != nil {
		return nil, err
	}

	var list []Container
	if err := c.getJSON(ctx, "/containers/json",
		url.Values{"all": {"1"}, "filters": {string(filters)}}, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// Rename moves a container to a different name, used to free a name that a
// container from an earlier setup is holding.
func (c *Client) Rename(ctx context.Context, id, name string) error {
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/rename",
		url.Values{"name": {name}}, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// RemoveImage deletes an image by tag.
func (c *Client) RemoveImage(ctx context.Context, tag string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/images/"+tag, url.Values{"force": {"1"}}, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
