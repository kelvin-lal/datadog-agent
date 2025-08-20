// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"

	configModel "github.com/DataDog/datadog-agent/pkg/config/model"
	configutils "github.com/DataDog/datadog-agent/pkg/config/utils"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
)

// clusterCAData holds the cluster CA configuration and certificate data
type clusterCAData struct {
	enableTLSVerification bool
	caCert                *x509.Certificate
	caPrivKey             any
}

// readClusterCAConfig reads cluster CA configuration and files from disk once
// Returns nil if no cluster CA is configured
func readClusterCAConfig(config configModel.Reader) (*clusterCAData, error) {
	enableTLSVerification := config.GetBool("cluster_trust_chain.enable_tls_verification")
	clusterCAPath := config.GetString("cluster_trust_chain.ca_cert_file_path")
	clusterCAKeyPath := config.GetString("cluster_trust_chain.ca_key_file_path")

	// If no cluster CA path is configured, return nil (not an error)
	if clusterCAPath == "" {
		return &clusterCAData{
			enableTLSVerification: enableTLSVerification,
		}, nil
	}

	// Read cluster CA certificate and private key from disk
	caCert, caPrivKey, err := ReadClusterCA(clusterCAPath, clusterCAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read cluster CA cert and key: %w", err)
	}

	return &clusterCAData{
		enableTLSVerification: enableTLSVerification,
		caCert:                caCert,
		caPrivKey:             caPrivKey,
	}, nil
}

// buildClusterClientTLSConfig creates the TLS configuration for cluster client communication
// using pre-read cluster CA data
func buildClusterClientTLSConfig(caData *clusterCAData) (*tls.Config, error) {
	// Default to insecure configuration
	clusterClientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Validate that TLS verification requirements are met
	if caData.enableTLSVerification && (caData.caCert == nil || caData.caPrivKey == nil) {
		return nil, fmt.Errorf("cluster_trust_chain.enable_tls_verification cannot be true if cluster_trust_chain.ca_cert_file_path or cluster_trust_chain.ca_key_file_path is not set")
	}

	// If TLS verification is enabled and we have a CA certificate, configure proper certificate validation
	if caData != nil && caData.enableTLSVerification && caData.caCert != nil {
		clusterClientCertPool := x509.NewCertPool()
		clusterClientCertPool.AddCert(caData.caCert)
		clusterClientConfig = &tls.Config{
			RootCAs: clusterClientCertPool,
		}
	}

	return clusterClientConfig, nil
}

// setupCertificateFactoryWithClusterCA configures the certificate factory with cluster CA
// and determines additional SANs based on the agent flavor and configuration
func setupCertificateFactoryWithClusterCA(config configModel.Reader, factory *certificateFactory, caData *clusterCAData) error {
	// Only proceed if cluster CA data is available
	if caData == nil || caData.caCert == nil {
		return nil
	}

	factory.caCert = caData.caCert
	factory.caPrivKey = caData.caPrivKey

	var serverHost string

	// If the process is a Cluster Agent, add the external IP and DNS name to the SANs
	if flavor.GetFlavor() == flavor.ClusterAgent {
		clusterAgentEndpoint, err := configutils.GetClusterAgentEndpoint()
		if err != nil {
			return fmt.Errorf("unable to get cluster agent endpoint: %w", err)
		}
		parsedURL, err := url.Parse(clusterAgentEndpoint)
		if err != nil {
			return fmt.Errorf("unable to parse cluster agent endpoint URL: %w", err)
		}

		serverHost, _, err = net.SplitHostPort(parsedURL.Host)
		if err != nil {
			return fmt.Errorf("unable to get pod IP from cluster agent endpoint: %w", err)
		}
	}

	// If the process is a CLC Runner, add the CLC Runner host to the SANs
	if clcRunnerHost := config.GetString("clc_runner_host"); clcRunnerHost != "" {
		serverHost = clcRunnerHost
	}

	// Determine if the server host is an IP address or DNS name and add to appropriate SANs
	ip := net.ParseIP(serverHost)
	if ip != nil {
		factory.additionalIPs = []net.IP{ip}
	} else if serverHost != "" {
		factory.additionalDNSNames = []string{serverHost}
	}

	return nil
}
