package packages

import (
	"context"
	"github.com/GoogleCloudPlatform/osconfig/osinfo"
)

type scalibrInstalledPackagesProvider struct {
	extractors      []string
	osinfoProvider  osinfo.Provider
}

func (p scalibrInstalledPackagesProvider) GetInstalledPackages(ctx context.Context) (Packages, error) {
	return Packages{}, nil
}
