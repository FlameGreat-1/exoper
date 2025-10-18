package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

type TLSConfig struct {
	MinVersion               uint16
	MaxVersion               uint16
	CipherSuites             []uint16
	PreferServerCipherSuites bool
	ClientAuth               tls.ClientAuthType
	ClientCAs                *x509.CertPool
	InsecureSkipVerify       bool
}

func (m *MTLSManager) GetTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                m.rootCAs,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	if m.config.Security.MTLSClientAuth == "optional" {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	} else if m.config.Security.MTLSClientAuth == "none" {
		tlsConfig.ClientAuth = tls.NoClientCert
	}

	if m.config.Environment == "development" {
		tlsConfig.InsecureSkipVerify = true
		m.logger.Warn("TLS certificate verification disabled for development")
	}

	return tlsConfig, nil
}

func (m *MTLSManager) ValidateTLSConfig() error {
	if m.rootCAs == nil {
		return fmt.Errorf("no root CAs configured")
	}

	if m.config.Security.MTLSRequired && m.config.Security.MTLSClientAuth == "none" {
		return fmt.Errorf("mTLS required but client auth is disabled")
	}

	return nil
}
