package service

import "runtime"

type Status struct {
	Installed bool   `json:"installed"`
	Active    string `json:"active"`
	Platform  string `json:"platform"`
}

func GetStatus(serviceName string) *Status {
	s := &Status{Platform: runtime.GOOS, Active: "unknown"}
	if runtime.GOOS == "linux" {
		out, err := SystemdStatus(serviceName)
		if err != nil {
			s.Active = "unknown"
		} else {
			s.Active = out
			s.Installed = out != "unknown" && out != ""
		}
	}
	return s
}

func currentPlatform() string {
	return runtime.GOOS
}
