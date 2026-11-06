// kubeclient.go — the apiserver credential loading + rv LIST probe:
// admin.conf (kubeconfig with embedded client creds) or the
// admin.crt/admin.key + ca.crt triple → a cached mTLS http.Client
// rebuilt on credential rotation, then the ?resourceVersion= LIST
// probe (api_list_rv parity).
package controllerhygiene

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/tools/clientcmd"
)

// ensureClient lazily builds the mTLS HTTP client the first time the
// credential source exists — the per-run `[ -f admin.crt ]` gate of
// the shell maps to "no client → hub checks skipped this cycle".
// The shell re-read the cert files EVERY probe; the client is rebuilt
// whenever the credential files' mtime/size fingerprint changes —
// caching a rotated cert forever would make post-rotation probes fail
// permanently and the dead-fallback could restart a healthy apiserver.
func (d *deps) ensureClient() *http.Client {
	if d.cfg.HTTPClient != nil {
		return d.client // injected test seam — never rebuilt
	}
	fp := d.credFingerprint()
	if d.client != nil && fp == d.credFP {
		return d.client
	}
	c, err := d.buildClient()
	if err != nil {
		d.state.AppendLogWarn(fmt.Sprintf(
			"controllerhygiene: apiserver credential load failed: %v — wedge checks blind this cycle",
			err))
		return nil
	}
	if c == nil {
		return nil
	}
	if d.client != nil {
		d.client.CloseIdleConnections() // drop the rotated client's pool
	}
	d.client = c
	d.credFP = fp
	return c
}

// credFingerprint stamps mtime+size of every credential source file —
// a k0s admin.conf/cert rotation changes it and triggers a rebuild.
func (d *deps) credFingerprint() string {
	var b strings.Builder
	for _, f := range []string{
		d.cfg.AdminKubeconfig, d.cfg.AdminCert, d.cfg.AdminKey, d.cfg.AdminCA,
	} {
		if fi, err := os.Stat(f); err == nil {
			fmt.Fprintf(&b, "%s:%x:%x;", f, fi.ModTime().UnixNano(), fi.Size())
		}
	}
	return b.String()
}

// buildClient loads client credentials from admin.conf (kubeconfig
// with embedded cert/key) or the admin.crt/admin.key + ca.crt triple,
// mirroring `curl -sk --cacert ca --cert crt --key key`.
func (d *deps) buildClient() (*http.Client, error) {
	certPEM, keyPEM, caPEM, err := d.loadCreds()
	if err != nil || len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("admin client cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{pair},
		InsecureSkipVerify: d.cfg.InsecureTLS, // mirrors curl -sk
	}
	if !d.cfg.InsecureTLS && len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("no certificates in CA data")
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	tr.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: tr}, nil
}

// loadCreds resolves the admin client cert/key (+optional CA) PEM
// blocks: admin.conf kubeconfig first (embedded *-data fields, file
// refs resolved relative to the kubeconfig dir), then the flat
// cert/key/ca files.
func (d *deps) loadCreds() (cert, key, ca []byte, err error) {
	if _, statErr := os.Stat(d.cfg.AdminKubeconfig); statErr == nil {
		kc, kerr := clientcmd.LoadFromFile(d.cfg.AdminKubeconfig)
		if kerr != nil {
			return nil, nil, nil, fmt.Errorf("load %s: %w", d.cfg.AdminKubeconfig, kerr)
		}
		for _, a := range kc.AuthInfos {
			if len(a.ClientCertificateData) > 0 {
				cert = a.ClientCertificateData
			} else if a.ClientCertificate != "" {
				// A kubeconfig that REFERENCES cert/key files and
				// cannot read them is not "no creds" — warn so the
				// blind-cycle no_creds result stays attributable.
				ref := resolveRel(d.cfg.AdminKubeconfig, a.ClientCertificate)
				if b, rerr := os.ReadFile(ref); rerr != nil {
					d.state.AppendLogWarn(fmt.Sprintf(
						"controllerhygiene: kubeconfig client-cert %s unreadable: %v",
						ref, rerr))
				} else {
					cert = b
				}
			}
			if len(a.ClientKeyData) > 0 {
				key = a.ClientKeyData
			} else if a.ClientKey != "" {
				ref := resolveRel(d.cfg.AdminKubeconfig, a.ClientKey)
				if b, rerr := os.ReadFile(ref); rerr != nil {
					d.state.AppendLogWarn(fmt.Sprintf(
						"controllerhygiene: kubeconfig client-key %s unreadable: %v",
						ref, rerr))
				} else {
					key = b
				}
			}
			if len(cert) > 0 && len(key) > 0 {
				break
			}
		}
		for _, cl := range kc.Clusters {
			if len(cl.CertificateAuthorityData) > 0 {
				ca = cl.CertificateAuthorityData
				break
			}
			if cl.CertificateAuthority != "" {
				if b, rerr := os.ReadFile(resolveRel(d.cfg.AdminKubeconfig, cl.CertificateAuthority)); rerr == nil {
					ca = b
					break
				}
			}
		}
		return cert, key, ca, nil
	}
	if _, statErr := os.Stat(d.cfg.AdminCert); statErr != nil {
		// not a controller / k0s not initialised
		logger().Debug("controllerhygiene: admin cert absent — apiserver checks idle",
			"path", d.cfg.AdminCert, "error", statErr)
		return nil, nil, nil, nil
	}
	cert, err = os.ReadFile(d.cfg.AdminCert)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err = os.ReadFile(d.cfg.AdminKey)
	if err != nil {
		return nil, nil, nil, err
	}
	if b, rerr := os.ReadFile(d.cfg.AdminCA); rerr == nil {
		ca = b
	}
	return cert, key, ca, nil
}

// resolveRel resolves a kubeconfig file reference relative to the
// kubeconfig's directory (clientcmd semantics for non-absolute paths).
func resolveRel(kubeconfig, ref string) string {
	if filepath.IsAbs(ref) {
		return ref
	}
	return filepath.Join(filepath.Dir(kubeconfig), ref)
}

// listRV returns the LIST-level resourceVersion of one apiserver
// endpoint — api_list_rv parity. cached=true → ?resourceVersion=0
// (watch-cache), cached=false → ?resourceVersion= (consistent read →
// storage backend). ok=false on any transport/HTTP/parse failure.
func (d *deps) listRV(ctx context.Context, endpoint string, cached bool) (int64, bool) {
	if d.cfg.listRVFn != nil {
		return d.cfg.listRVFn(ctx, endpoint, cached)
	}
	client := d.ensureClient()
	if client == nil {
		return 0, false
	}
	q := "resourceVersion="
	if cached {
		q = "resourceVersion=0"
	}
	qctx, cancel := context.WithTimeout(ctx, d.cfg.QueryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet,
		"https://"+endpoint+d.cfg.APIPath+"?"+q+"&limit=1", nil)
	if err != nil {
		return 0, false
	}
	resp, err := client.Do(req)
	if err != nil {
		logger().Warn("controllerhygiene: rv probe failed",
			"endpoint", endpoint, "cached", cached, "error", err,
		)
		return 0, false
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		logger().Warn("controllerhygiene: rv probe non-200",
			"endpoint", endpoint, "cached", cached,
			"status", resp.StatusCode)
		return 0, false
	}
	var list struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return 0, false
	}
	rv, err := strconv.ParseInt(list.Metadata.ResourceVersion, 10, 64)
	if err != nil {
		return 0, false
	}
	return rv, true
}
