package mtls

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"

)

type TrustChainResult struct {
	Valid  bool              `json:"valid"`
	Status string            `json:"status"`
	Errors []ValidationError `json:"errors"`
	Chain  []string          `json:"chain"`
}

type RevocationResult struct {
	Revoked   bool       `json:"revoked"`
	Status    string     `json:"status"`
	Reason    string     `json:"reason,omitempty"`
	Method    string     `json:"method"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func (m *MTLSManager) getCRLInfo(ctx context.Context, crlURL string) (*CRLInfo, error) {
	if crlInfo, exists := m.crlCache[crlURL]; exists {
		if time.Now().Before(crlInfo.CacheExpiry) {
			return crlInfo, nil
		}
	}

	crlData, err := m.downloadCRL(ctx, crlURL)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseCRL(crlData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %v", err)
	}

	revokedCerts := make(map[string]*RevokedCert)
	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		serialNumber := revokedCert.SerialNumber.String()
		
		reason := ReasonUnspecified
		for _, ext := range revokedCert.Extensions {
			if ext.Id.Equal([]int{2, 5, 29, 21}) {
				if len(ext.Value) > 0 {
					reason = RevocationReason(fmt.Sprintf("reason_%d", ext.Value[0]))
				}
			}
		}

		revokedCerts[serialNumber] = &RevokedCert{
			SerialNumber:     serialNumber,
			RevocationTime:   revokedCert.RevocationTime,
			RevocationReason: reason,
		}
	}

	crlInfo := &CRLInfo{
		URL:          crlURL,
		LastUpdate:   crl.TBSCertList.ThisUpdate,
		NextUpdate:   crl.TBSCertList.NextUpdate,
		RevokedCerts: revokedCerts,
		CacheExpiry:  time.Now().Add(time.Hour),
	}

	m.crlCache[crlURL] = crlInfo

	m.logger.Debug("CRL updated",
		zap.String("url", crlURL),
		zap.Int("revoked_count", len(revokedCerts)),
		zap.Time("next_update", crl.TBSCertList.NextUpdate))

	return crlInfo, nil
}

func (m *MTLSManager) downloadCRL(ctx context.Context, crlURL string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", crlURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download CRL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL download failed with status: %d", resp.StatusCode)
	}

	crlData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL data: %v", err)
	}

	return crlData, nil
}

func (m *MTLSManager) getOCSPResponse(ctx context.Context, cert *x509.Certificate, ocspURL string) (*OCSPResponse, error) {
	cacheKey := fmt.Sprintf("%s:%s", ocspURL, cert.SerialNumber.String())
	
	if ocspResp, exists := m.ocspCache[cacheKey]; exists {
		if time.Now().Before(ocspResp.CacheExpiry) {
			return ocspResp, nil
		}
	}

	issuer, err := m.findIssuerCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to find issuer certificate: %v", err)
	}

	ocspRequest, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %v", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", ocspURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP HTTP request: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Body = io.NopCloser(strings.NewReader(string(ocspRequest)))

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send OCSP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP request failed with status: %d", resp.StatusCode)
	}

	ocspRespData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP response: %v", err)
	}

	ocspResponse, err := ocsp.ParseResponse(ocspRespData, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %v", err)
	}

	status := "unknown"
	switch ocspResponse.Status {
	case ocsp.Good:
		status = "good"
	case ocsp.Revoked:
		status = "revoked"
	case ocsp.Unknown:
		status = "unknown"
	}

	ocspResp := &OCSPResponse{
		Status:      status,
		ProducedAt:  ocspResponse.ProducedAt,
		ThisUpdate:  ocspResponse.ThisUpdate,
		NextUpdate:  ocspResponse.NextUpdate,
		CacheExpiry: time.Now().Add(time.Hour),
	}

	m.ocspCache[cacheKey] = ocspResp

	return ocspResp, nil
}

func (m *MTLSManager) findIssuerCertificate(cert *x509.Certificate) (*x509.Certificate, error) {
	if m.intermediateCAs != nil {
		for _, caCert := range m.intermediateCAs.Subjects() {
			issuerCert := &x509.Certificate{Raw: caCert}
			if cert.CheckSignatureFrom(issuerCert) == nil {
				return issuerCert, nil
			}
		}
	}

	if m.rootCAs != nil {
		for _, caCert := range m.rootCAs.Subjects() {
			issuerCert := &x509.Certificate{Raw: caCert}
			if cert.CheckSignatureFrom(issuerCert) == nil {
				return issuerCert, nil
			}
		}
	}

	return nil, fmt.Errorf("issuer certificate not found")
}

func (m *MTLSManager) startCRLUpdateWorker() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.updateCRLCache()
		}
	}
}

func (m *MTLSManager) startOCSPCacheWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanupOCSPCache()
		}
	}
}

func (m *MTLSManager) updateCRLCache() {
	ctx := context.Background()
	
	for crlURL := range m.crlCache {
		_, err := m.getCRLInfo(ctx, crlURL)
		if err != nil {
			m.logger.Warn("Failed to update CRL cache", 
				zap.String("url", crlURL), 
				zap.Error(err))
		}
	}
}

func (m *MTLSManager) cleanupOCSPCache() {
	now := time.Now()
	
	for key, response := range m.ocspCache {
		if now.After(response.CacheExpiry) {
			delete(m.ocspCache, key)
		}
	}

	m.logger.Debug("OCSP cache cleaned up", 
		zap.Int("remaining_entries", len(m.ocspCache)))
}
