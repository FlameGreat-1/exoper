package mtls

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

func (m *MTLSManager) ParseCertificateChain(chainPEM string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	
	rest := []byte(chainPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in chain: %v", err)
		}

		certificates = append(certificates, cert)
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("no valid certificates found in chain")
	}

	return certificates, nil
}

func (m *MTLSManager) ValidateCertificateChain(certificates []*x509.Certificate) error {
	if len(certificates) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	for i := 0; i < len(certificates)-1; i++ {
		cert := certificates[i]
		issuer := certificates[i+1]

		if err := cert.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("certificate chain validation failed at position %d: %v", i, err)
		}
	}

	return nil
}

func (m *MTLSManager) GetCertificateDetails(cert *x509.Certificate) map[string]interface{} {
	details := map[string]interface{}{
		"serial_number":        cert.SerialNumber.String(),
		"subject":              cert.Subject.String(),
		"issuer":               cert.Issuer.String(),
		"not_before":           cert.NotBefore,
		"not_after":            cert.NotAfter,
		"signature_algorithm":  cert.SignatureAlgorithm.String(),
		"public_key_algorithm": cert.PublicKeyAlgorithm.String(),
		"version":              cert.Version,
		"is_ca":                cert.IsCA,
		"dns_names":            cert.DNSNames,
		"email_addresses":      cert.EmailAddresses,
		"ip_addresses":         cert.IPAddresses,
		"key_usage":            m.extractKeyUsage(cert),
		"ext_key_usage":        m.extractExtendedKeyUsage(cert),
	}

	if cert.PublicKeyAlgorithm == x509.RSA {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			details["rsa_key_size"] = rsaKey.N.BitLen()
		}
	}

	return details
}

func (m *MTLSManager) FormatCertificateInfo(cert *x509.Certificate) string {
	var info strings.Builder
	
	info.WriteString(fmt.Sprintf("Subject: %s\n", cert.Subject.String()))
	info.WriteString(fmt.Sprintf("Issuer: %s\n", cert.Issuer.String()))
	info.WriteString(fmt.Sprintf("Serial Number: %s\n", cert.SerialNumber.String()))
	info.WriteString(fmt.Sprintf("Valid From: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC")))
	info.WriteString(fmt.Sprintf("Valid Until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC")))
	info.WriteString(fmt.Sprintf("Signature Algorithm: %s\n", cert.SignatureAlgorithm.String()))
	info.WriteString(fmt.Sprintf("Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String()))

	if len(cert.DNSNames) > 0 {
		info.WriteString(fmt.Sprintf("DNS Names: %s\n", strings.Join(cert.DNSNames, ", ")))
	}

	if len(cert.EmailAddresses) > 0 {
		info.WriteString(fmt.Sprintf("Email Addresses: %s\n", strings.Join(cert.EmailAddresses, ", ")))
	}

	keyUsage := m.extractKeyUsage(cert)
	if len(keyUsage) > 0 {
		info.WriteString(fmt.Sprintf("Key Usage: %s\n", strings.Join(keyUsage, ", ")))
	}

	extKeyUsage := m.extractExtendedKeyUsage(cert)
	if len(extKeyUsage) > 0 {
		info.WriteString(fmt.Sprintf("Extended Key Usage: %s\n", strings.Join(extKeyUsage, ", ")))
	}

	return info.String()
}

func (m *MTLSManager) IsCertificateExpiringSoon(cert *x509.Certificate, days int) bool {
	threshold := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	return cert.NotAfter.Before(threshold)
}

func (m *MTLSManager) GetCertificateRemainingDays(cert *x509.Certificate) int {
	duration := cert.NotAfter.Sub(time.Now())
	return int(duration.Hours() / 24)
}
