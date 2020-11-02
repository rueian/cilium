// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxylib

import (
	"github.com/cilium/cilium/pkg/lock"
	cilium "github.com/cilium/proxy/go/cilium/api"

	log "github.com/sirupsen/logrus"
)

type AccessLogger interface {
	Log(pblog *cilium.LogEntry)
	Close()
	Path() string
}

type Instance struct {
	id           uint64
	accessLogger AccessLogger
}

var (
	// mutex protects instances
	mutex lock.RWMutex
	// Key uint64 is a monotonically increasing instance ID
	instances map[uint64]*Instance = make(map[uint64]*Instance)
	// Last instance ID used
	instanceId uint64 = 0
)

func NewInstance(accessLogger AccessLogger) *Instance {

	instanceId++

	// TODO: Sidecar instance id needs to be different.
	ins := &Instance{
		id:           instanceId,
		accessLogger: accessLogger,
	}

	return ins
}

// OpenInstance creates a new instance or finds an existing one with equivalent parameters.
// returns the instance id.
func OpenInstance(accessLogPath string, newAccessLogger func(accessLogPath string) AccessLogger) uint64 {
	mutex.Lock()
	defer mutex.Unlock()

	ins := NewInstance(newAccessLogger(accessLogPath))

	instances[instanceId] = ins

	log.Debugf("Opened new library instance %d", instanceId)

	return instanceId
}

func FindInstance(id uint64) *Instance {
	mutex.RLock()
	defer mutex.RUnlock()
	return instances[id]
}

// Close returns the new open count
func CloseInstance(id uint64) uint64 {
	mutex.Lock()
	defer mutex.Unlock()

	if ins, ok := instances[id]; ok {
		ins.accessLogger.Close()
		delete(instances, id)
	}

	return 0
}

func (ins *Instance) Log(pblog *cilium.LogEntry) {
	ins.accessLogger.Log(pblog)
}
