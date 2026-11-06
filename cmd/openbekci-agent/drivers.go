package main

import (
	"github.com/openbekci/openbekci-agent/internal/driver"
	"github.com/openbekci/openbekci-agent/internal/driver/platecam"
	"github.com/openbekci/openbekci-agent/internal/driver/relay"
)

// Drivers is the explicit driver registry: no init() side effects. Adding a
// driver means adding one line here.
var Drivers = []driver.Registration{
	relay.Registration,
	platecam.Registration,
}

func driverTypes() []string {
	out := make([]string, len(Drivers))
	for i, r := range Drivers {
		out[i] = r.Type
	}
	return out
}
