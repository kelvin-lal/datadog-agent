// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && linux_bpf

package file

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	configmock "github.com/DataDog/datadog-agent/pkg/config/mock"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	// System probe imports for fd-transfer
	"github.com/DataDog/datadog-agent/cmd/system-probe/modules"
	"github.com/DataDog/datadog-agent/pkg/system-probe/api/module"
	"github.com/DataDog/datadog-agent/pkg/system-probe/api/server"
	sysconfigtypes "github.com/DataDog/datadog-agent/pkg/system-probe/config/types"
)

type testPrivilegedHandler struct {
	handler http.Handler
	called  bool
}

func newTestPrivilegedHandler(handler http.Handler) *testPrivilegedHandler {
	return &testPrivilegedHandler{
		handler: handler,
	}
}

func (h *testPrivilegedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Lock due to the setreuid(2) call below.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get current EUID to restore later
	originalEUID := syscall.Geteuid()

	// Temporarily escalate to root for file access (this thread only).  Need to
	// use the raw system call since the wrapper sets it on all threads.
	if _, _, err := syscall.Syscall(syscall.SYS_SETREUID, ^uintptr(0), 0, 0); err != 0 {
		http.Error(w, fmt.Sprintf("Privilege escalation failed: %v", err),
			http.StatusInternalServerError)
		return
	}

	// Ensure we restore EUID even if panic occurs
	defer func() {
		if _, _, err := syscall.Syscall(syscall.SYS_SETREUID, ^uintptr(0), uintptr(originalEUID), 0); err != 0 {
			// Log error but can't do much else in test context
			log.Errorf("Failed to restore EUID: %v", err)
		}
	}()

	// Call the wrapped handler
	h.handler.ServeHTTP(w, r)
	h.called = true
}

type FDTransferTestSetupStrategy struct {
	socketPath    string
	serverCleanup func()
	tempDirs      [2]string
}

func (s *FDTransferTestSetupStrategy) Setup(t *testing.T) TestSetupResult {
	unprivilegedUid := 0
	sudoUid := os.Getenv("SUDO_UID")
	if sudoUid != "" {
		var err error
		unprivilegedUid, err = strconv.Atoi(sudoUid)
		require.NoError(t, err)
	}

	if unprivilegedUid == 0 {
		user, err := user.Lookup("nobody")
		require.NoError(t, err)
		unprivilegedUid, err = strconv.Atoi(user.Uid)
		require.NoError(t, err)
	}

	err := syscall.Seteuid(unprivilegedUid)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := syscall.Seteuid(0)
		require.NoError(t, err)
	})

	// Set up fd-transfer server
	setupTestServerForLauncher(t)

	// Create temp directories before setting umask
	s.tempDirs = [2]string{}
	for i := 0; i < 2; i++ {
		testDir := t.TempDir()
		s.tempDirs[i] = testDir
	}

	// Set umask so all created files have 000 permissions and are not readable
	// by the unprivileged user
	oldUmask := syscall.Umask(0777)
	t.Cleanup(func() {
		syscall.Umask(oldUmask)
	})

	return TestSetupResult{TestDirs: s.tempDirs[:]}
}

type FDTransferLauncherTestSuite struct {
	BaseLauncherTestSuite
}

// setupTestServer creates a test server with the FD transfer module
func setupTestServerForLauncher(t *testing.T) {
	// Create the fd transfer module
	cfg := &sysconfigtypes.Config{}
	deps := module.FactoryDependencies{}

	fdModule, err := modules.FDTransfer.Fn(cfg, deps)
	if err != nil {
		t.Fatalf("Failed to create fd transfer module: %v", err)
	}

	// Use /tmp for shorter socket paths to avoid Unix socket limits
	tempDir, err := os.MkdirTemp("/tmp", "fdtest")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	socketPath := filepath.Join(tempDir, "fd.sock")
	listener, err := server.NewListener(socketPath)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create listener: %v", err)
	}

	// Set up HTTP router and register the module
	httpMux := mux.NewRouter()
	router := module.NewRouter("fd_transfer", httpMux)
	err = fdModule.Register(router)
	if err != nil {
		listener.Close()
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to register module: %v", err)
	}

	testHandler := &testPrivilegedHandler{
		handler: httpMux,
	}
	httpServer := &http.Server{
		Handler: testHandler,
	}

	t.Cleanup(func() {
		require.True(t, testHandler.called, "fd-transfer was not used")
	})

	// Start the server in a goroutine
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		conn, err := net.Dial("unix", socketPath)
		require.NoError(collect, err)
		conn.Close()
	}, 1*time.Second, 10*time.Millisecond)

	t.Cleanup(func() {
		if httpServer != nil {
			httpServer.Close()
		}
		// Wait for server to finish
		select {
		case <-serverDone:
		case <-time.After(1 * time.Second):
			t.Log("Server shutdown timed out")
		}
		if listener != nil {
			listener.Close()
		}
		os.RemoveAll(tempDir)
	})

	systemProbeConfig := configmock.NewSystemProbe(t)
	systemProbeConfig.SetWithoutSource("system_probe_config.sysprobe_socket", socketPath)
}

func (suite *FDTransferLauncherTestSuite) SetupSuite() {
	suite.setupStrategy = &FDTransferTestSetupStrategy{}
}

func TestFDTransferLauncherTestSuite(t *testing.T) {
	suite.Run(t, new(FDTransferLauncherTestSuite))
}

func TestFDTransferLauncherTestSuiteWithConfigID(t *testing.T) {
	s := new(FDTransferLauncherTestSuite)
	s.configID = "123456789"
	suite.Run(t, s)
}

func TestFDTransferLauncherScanStartNewTailer(t *testing.T) {
	setup := setupFDTransferTest(t)
	runLauncherScanStartNewTailerTest(t, setup.tempDirs[:])
}

func TestFDTransferLauncherWithConcurrentContainerTailer(t *testing.T) {
	setup := setupFDTransferTest(t)
	runLauncherWithConcurrentContainerTailerTest(t, setup.tempDirs[:])
}

func TestFDTransferLauncherTailFromTheBeginning(t *testing.T) {
	setup := setupFDTransferTest(t)
	runLauncherTailFromTheBeginningTest(t, setup.tempDirs[:], true)
}

func TestFDTransferLauncherSetTail(t *testing.T) {
	setup := setupFDTransferTest(t)
	runLauncherSetTailTest(t, setup.tempDirs[:])
}

func TestFDTransferLauncherConfigIdentifier(t *testing.T) {
	setup := setupFDTransferTest(t)
	runLauncherConfigIdentifierTest(t, setup.tempDirs[:])
}

func TestFDTransferLauncherScanWithTooManyFiles(t *testing.T) {
	setup := setupFDTransferTest(t)
	runLauncherScanWithTooManyFilesTest(t, setup.tempDirs[:])
}

func TestFDTransferLauncherUpdatesSourceForExistingTailer(t *testing.T) {
	setup := setupFDTransferTest(t)
	runLauncherUpdatesSourceForExistingTailerTest(t, setup.tempDirs[:])
}

func TestFDTransferLauncherScanRecentFilesWithRemoval(t *testing.T) {
	setup := setupFDTransferTest(t)
	runLauncherScanRecentFilesWithRemovalTest(t, setup.tempDirs[:])
}

func TestFDTransferLauncherScanRecentFilesWithNewFiles(t *testing.T) {
	setup := setupFDTransferTest(t)
	runLauncherScanRecentFilesWithNewFilesTest(t, setup.tempDirs[:])
}

func TestFDTransferLauncherFileRotation(t *testing.T) {
	setup := setupFDTransferTest(t)
	runLauncherFileRotationTest(t, setup.tempDirs[:])
}

func TestFDTransferLauncherFileDetectionSingleScan(t *testing.T) {
	setup := setupFDTransferTest(t)
	runLauncherFileDetectionSingleScanTest(t, setup.tempDirs[:])
}

// setupFDTransferTest is a helper type for FD transfer test setup
type fdTransferTestSetup struct {
	tempDirs [2]string
}

// setupFDTransferTest sets up the FD transfer test environment
func setupFDTransferTest(t *testing.T) *fdTransferTestSetup {
	strategy := &FDTransferTestSetupStrategy{}
	result := strategy.Setup(t)

	return &fdTransferTestSetup{
		tempDirs: [2]string{result.TestDirs[0], result.TestDirs[1]},
	}
}
