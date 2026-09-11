package config

import "github.com/fregie/tokenhush/pkg/platform"

func defaultConfigFile() (string, error) {
	path, err := platform.ConfigFile()
	if err != nil {
		return "", &Error{Reason: "cannot resolve config file path", Err: ErrRead, Cause: err}
	}
	return path, nil
}
