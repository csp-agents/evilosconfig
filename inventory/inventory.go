package inventory

import (
	"context"
	"github.com/GoogleCloudPlatform/osconfig/packages"
)

type InstanceInventory struct {
	Hostname             string
	LongName             string
	ShortName            string
	Version              string
	Architecture         string
	KernelVersion        string
	KernelRelease        string
	OSConfigAgentVersion string
	InstalledPackages    *packages.Packages
	PackageUpdates       *packages.Packages
	LastUpdated          string
}

type Provider interface {
	Get(context.Context) *InstanceInventory
}

type defaultProvider struct{}

func NewProvider() Provider { return &defaultProvider{} }

func (p *defaultProvider) Get(ctx context.Context) *InstanceInventory {
	return &InstanceInventory{}
}
