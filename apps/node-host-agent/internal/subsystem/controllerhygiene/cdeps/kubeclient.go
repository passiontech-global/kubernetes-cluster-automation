// kubeclient.go — the apiserver credential loading + rv LIST probe:
// admin.conf (kubeconfig with embedded client creds) or the
// admin.crt/admin.key + ca.crt triple → a cached mTLS http.Client
// rebuilt on credential rotation, then the ?resourceVersion= LIST
// probe (api_list_rv parity).
package cdeps

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
	"strings"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
)

// maxListRVBody caps one RV-probe response read. With the
// PartialObjectMetadataList negotiation above the payload is a few
// KiB even on big-object endpoints; the cap is a runaway guard, not
// the hard 1 MiB truncation that used to fail the probe.
const maxListRVBody = 4 << 20

// EnsureClient lazily builds the mTLS HTTP client the first time the
// credential source exists — the per-run `[ -f admin.crt ]` gate of
// the shell maps to "no client → hub checks skipped this cycle".
// The shell re-read the cert files EVERY probe; the client is rebuilt
// whenever the credential files' mtime/size fingerprint changes —
// caching a rotated cert forever would make post-rotation probes fail
// permanently and the dead-fallback could restart a healthy apiserver.
func (d *Deps) EnsureClient() *http.Client {
	if d.Cfg.HTTPClient != nil {
		return d.Client // injected test seam — never rebuilt
	}
	fp := d.credFingerprint()
	if d.Client != nil && fp == d.CredFP {
		return d.Client
	}
	c, err := d.buildClient()
	if err != nil {
		d.State.AppendLogWarn(fmt.Sprintf(
			"controllerhygiene: apiserver credential load failed: %v — wedge checks blind this cycle",
			err))
		return nil
	}
	if c == nil {
		return nil
	}
	if d.Client != nil {
		d.Client.CloseIdleConnections() // drop the rotated client's pool
	}
	d.Client = c
	d.CredFP = fp
	return c
}

// credFingerprint stamps mtime+size of every credential source file —
// a k0s admin.conf/cert rotation changes it and triggers a rebuild.
func (d *Deps) credFingerprint() string {
	var b strings.Builder
	for _, f := range []string{
		d.Cfg.AdminKubeconfig, d.Cfg.AdminCert, d.Cfg.AdminKey, d.Cfg.AdminCA,
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
func (d *Deps) buildClient() (*http.Client, error) {
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
		InsecureSkipVerify: d.Cfg.InsecureTLS, // mirrors curl -sk
	}
	if !d.Cfg.InsecureTLS && len(caPEM) > 0 {
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
func (d *Deps) loadCreds() (cert, key, ca []byte, err error) {
	if _, statErr := os.Stat(d.Cfg.AdminKubeconfig); statErr == nil {
		kc, kerr := clientcmd.LoadFromFile(d.Cfg.AdminKubeconfig)
		if kerr != nil {
			return nil, nil, nil, fmt.Errorf("load %s: %w", d.Cfg.AdminKubeconfig, kerr)
		}
		for _, a := range kc.AuthInfos {
			if len(a.ClientCertificateData) > 0 {
				cert = a.ClientCertificateData
			} else if a.ClientCertificate != "" {
				// A kubeconfig that REFERENCES cert/key files and
				// cannot read them is not "no creds" — warn so the
				// blind-cycle no_creds result stays attributable.
				ref := ResolveRel(d.Cfg.AdminKubeconfig, a.ClientCertificate)
				if b, rerr := os.ReadFile(ref); rerr != nil {
					d.State.AppendLogWarn(fmt.Sprintf(
						"controllerhygiene: kubeconfig client-cert %s unreadable: %v",
						ref, rerr))
				} else {
					cert = b
				}
			}
			if len(a.ClientKeyData) > 0 {
				key = a.ClientKeyData
			} else if a.ClientKey != "" {
				ref := ResolveRel(d.Cfg.AdminKubeconfig, a.ClientKey)
				if b, rerr := os.ReadFile(ref); rerr != nil {
					d.State.AppendLogWarn(fmt.Sprintf(
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
				if b, rerr := os.ReadFile(ResolveRel(d.Cfg.AdminKubeconfig, cl.CertificateAuthority)); rerr == nil {
					ca = b
					break
				}
			}
		}
		return cert, key, ca, nil
	}
	if _, statErr := os.Stat(d.Cfg.AdminCert); statErr != nil {
		// not a controller / k0s not initialised
		logger().Debug("controllerhygiene: admin cert absent — apiserver checks idle",
			"path", d.Cfg.AdminCert, "error", statErr)
		return nil, nil, nil, nil
	}
	cert, err = os.ReadFile(d.Cfg.AdminCert)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err = os.ReadFile(d.Cfg.AdminKey)
	if err != nil {
		return nil, nil, nil, err
	}
	if b, rerr := os.ReadFile(d.Cfg.AdminCA); rerr == nil {
		ca = b
	}
	return cert, key, ca, nil
}

// ResolveRel resolves a kubeconfig file reference relative to the
// kubeconfig's directory (clientcmd semantics for non-absolute paths).
func ResolveRel(kubeconfig, ref string) string {
	if filepath.IsAbs(ref) {
		return ref
	}
	return filepath.Join(filepath.Dir(kubeconfig), ref)
}

// ListRV returns the LIST-level resourceVersion of one apiserver
// endpoint — api_list_rv parity. cached=true → ?resourceVersion=0
// (watch-cache), cached=false → ?resourceVersion= (consistent read →
// storage backend). ok=false on any transport/HTTP/parse failure.
// The test seam is the injected Config.HTTPClient underneath —
// there is no ListRVFn: stubbing the client covers the probe and
// exercises this parse for real.
func (d *Deps) ListRV(ctx context.Context, endpoint string, cached bool) (int64, bool) {
	client := d.EnsureClient()
	if client == nil {
		return 0, false
	}
	q := "resourceVersion="
	if cached {
		q = "resourceVersion=0"
	}
	qctx, cancel := context.WithTimeout(ctx, d.Cfg.QueryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet,
		"https://"+endpoint+d.Cfg.APIPath+"?"+q+"&limit=1", nil)
	if err != nil {
		return 0, false
	}
	// Metadata-only negotiation: a limit=1 response no longer carries
	// spec/status, so one huge object can never truncate the probe —
	// the old hard 1 MiB cut made exactly that a permanent
	// "rv probe failed" on big-object endpoints. Servers without the
	// feature fall back to the plain List envelope, which
	// probee.ListResourceVersion decodes identically.
	req.Header.Set("Accept", "application/json;as=PartialObjectMetadataList;"+
		"v=v1alpha1;g=meta.k8s.io,application/json")
	resp, err := client.Do(req)
	if err != nil {
		logger().Warn("controllerhygiene: rv probe failed",
			"endpoint", endpoint, "cached", cached, "error", err,
		)
		return 0, false
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListRVBody))
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
	rv, ok := probee.ListResourceVersion(body)
	if !ok {
		return 0, false
	}
	return rv, true
}

// APIServerReadyEndpoints counts the distinct ready apiserver
// addresses the `kubernetes` service's Endpoints object reports —
// the peer-quorum evidence a k0scontroller restart needs before it
// can bounce a LIVE controller: with >=2 ready endpoints the peer
// keeps serving the API through the restart; with <2 the restart
// would take the last serving apiserver down with it. subsets[].
// addresses[] ARE the ready set (notReadyAddresses is a separate
// field), deduped by IP because one apiserver can appear under
// several port groups. ok=false on transport/HTTP/parse failure —
// an unreadable endpoints object is inconclusive, never "zero".
// The peer endpoint is queried first (the healthy witness); the
// self endpoint is the fallback when no peer is configured.
func (d *Deps) APIServerReadyEndpoints(ctx context.Context) (ready int, ok bool) {
	ep := d.Cfg.Hub.PeerAPI
	if ep == "" {
		ep = d.Cfg.Hub.SelfAPI
	}
	if ep == "" {
		return 0, false
	}
	client := d.EnsureClient()
	if client == nil {
		return 0, false
	}
	qctx, cancel := context.WithTimeout(ctx, d.Cfg.QueryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet,
		"https://"+ep+"/api/v1/namespaces/default/endpoints/kubernetes", nil)
	if err != nil {
		return 0, false
	}
	resp, err := client.Do(req)
	if err != nil {
		logger().Warn("controllerhygiene: endpoints probe failed",
			"endpoint", ep, "error", err)
		return 0, false
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		logger().Warn("controllerhygiene: endpoints probe non-200",
			"endpoint", ep, "status", resp.StatusCode)
		return 0, false
	}
	var eps struct {
		Subsets []struct {
			Addresses []struct {
				IP string `json:"ip"`
			} `json:"addresses"`
		} `json:"subsets"`
	}
	if err := json.Unmarshal(body, &eps); err != nil {
		return 0, false
	}
	seen := map[string]struct{}{}
	for _, sub := range eps.Subsets {
		for _, a := range sub.Addresses {
			if a.IP != "" {
				seen[a.IP] = struct{}{}
			}
		}
	}
	return len(seen), true
}

// ControllerQuorumReady is the shared peer-quorum gate every
// RestartUnit restart must pass: single-controller topologies
// (no Hub.PeerAPI) have nothing to protect and always pass; an
// UNREADABLE endpoints object fails open — the peer-fresh/streak
// gates already proved liveness where they apply, and blocking a
// needed restart on an inconclusive read would wedge the healer.
// Only a successfully-read count below 2 holds the restart.
func (d *Deps) ControllerQuorumReady(ctx context.Context) bool {
	if d.Cfg.Hub.PeerAPI == "" {
		return true
	}
	ready, ok := d.APIServerReadyEndpoints(ctx)
	if !ok {
		return true
	}
	return ready >= 2
}
