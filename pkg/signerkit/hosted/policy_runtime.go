package hosted

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policyarchive"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
)

// PolicyAPIConfig is deliberately post-construction: nil leaves every
// existing route byte-for-byte untouched.
type PolicyAPIConfig struct {
	Engine       *PolicyEngine
	Handler      http.Handler
	Archive      *policyarchive.Archive
	Lease        *policyarchive.MaintenanceLease
	DurableAudit signerkit.DurableAuditSink
}

// AttachPolicy registers both policy subtrees while readiness is false. The
// stable outer wrapper is mounted before any scan so a real policy target can
// never transiently appear as an unmounted 404.
func (server *Server) AttachPolicy(config *PolicyAPIConfig) error {
	if config == nil || config.Engine == nil || config.Handler == nil || config.Archive == nil || config.Lease == nil || config.DurableAudit == nil {
		return errors.New("hosted: AttachPolicy: complete engine, handler, archive, lease, and durable audit are required")
	}
	if server.Human == nil {
		return errors.New("hosted: AttachPolicy: human plane must be attached")
	}
	if server.MachineClientID == "" {
		return errors.New("hosted: AttachPolicy: MachineClientID is required")
	}
	if config.Engine.audit != config.DurableAudit {
		return errors.New("hosted: AttachPolicy: engine and route durable audits differ")
	}
	if err := config.Lease.Revalidate(); err != nil {
		return fmt.Errorf("hosted: AttachPolicy: maintenance lease: %w", err)
	}
	if err := config.DurableAudit.PolicyAuditReady(context.Background()); err != nil {
		return fmt.Errorf("hosted: AttachPolicy: durable audit: %w", err)
	}
	server.policyMu.Lock()
	defer server.policyMu.Unlock()
	if server.policy != nil {
		return errors.New("hosted: AttachPolicy: policy plane already attached")
	}
	machine := server.policyReady(config.Engine.Readiness(), server.withAuth(config.Handler))
	human := server.policyReady(config.Engine.Readiness(), config.Handler)
	server.mux.Handle("POST /v2/policy/base-manifests", machine)
	server.mux.Handle("GET /v2/policy/base-manifests/{request_id}", machine)
	server.mux.Handle("GET /ui/policy/pending", human)
	server.mux.Handle("GET /ui/policy/requests/{review_id}", human)
	server.mux.Handle("POST /ui/policy/requests/{review_id}/approve", human)
	server.mux.Handle("POST /ui/policy/requests/{review_id}/deny", human)
	server.mux.Handle("GET /ui/policy/requests/{review_id}/audit", human)
	server.policy = config
	return nil
}

func (server *Server) policyReady(readiness *PolicyReadiness, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		if err := readiness.Check(request.Context()); err != nil {
			writeJSONError(writer, http.StatusServiceUnavailable, "policy authority unavailable")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// StartPolicyWorkers starts exactly the independently owned ROSTER and
// RECOVERY goroutines after startup has made policy ready.
func (server *Server) StartPolicyWorkers(parent context.Context) error {
	server.policyMu.Lock()
	defer server.policyMu.Unlock()
	if server.policy == nil || server.policy.Engine == nil {
		return errors.New("hosted: policy plane is not attached")
	}
	if server.policyClosed {
		return errors.New("hosted: policy server is closed")
	}
	if server.policyWorkersRun {
		return errors.New("hosted: policy workers already started")
	}
	if !server.policy.Engine.Readiness().Ready() {
		return ErrPolicyUnavailable
	}
	workerContext, cancel := context.WithCancel(parent)
	server.policyCancel = cancel
	server.policyWorkersRun = true
	server.policyWorkers.Add(2)
	go server.runRosterWorker(workerContext, server.policy.Engine)
	go server.runRecoveryWorker(workerContext, server.policy.Engine)
	return nil
}

func (server *Server) runRosterWorker(ctx context.Context, engine *PolicyEngine) {
	defer server.policyWorkers.Done()
	interval := server.policyRosterWait
	if interval <= 0 {
		interval = policyRosterSweepInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := engine.RosterSweep(ctx); err != nil && !errors.Is(err, context.Canceled) {
				server.Logger.Printf("policy roster sweep failed: %v", err)
			}
		}
	}
}

func (server *Server) runRecoveryWorker(ctx context.Context, engine *PolicyEngine) {
	defer server.policyWorkers.Done()
	for {
		if err := engine.RecoverOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			server.Logger.Printf("policy recovery pass failed: %v", err)
		}
		if err := engine.sleep(ctx, engine.jitter(policyRecoveryBackoffBase)); err != nil {
			return
		}
	}
}

// MarkPolicyUnready closes only the policy plane so a runtime can stop HTTP
// intake before it cancels either worker.
func (server *Server) MarkPolicyUnready() {
	server.policyMu.Lock()
	if server.policy != nil {
		server.policy.Engine.Readiness().MarkUnready()
	}
	server.policyMu.Unlock()
}

// Close makes policy unavailable, cancels, and joins both owned workers. It
// intentionally performs no row-lease clear.
func (server *Server) Close() error {
	server.MarkPolicyUnready()
	server.policyMu.Lock()
	if server.policyClosed {
		server.policyMu.Unlock()
		return nil
	}
	server.policyClosed = true
	cancel := server.policyCancel
	server.policyMu.Unlock()
	if cancel != nil {
		cancel()
	}
	server.policyWorkers.Wait()
	return nil
}

type PolicyDatabase interface {
	PolicyStore() policystore.Store
	Close() error
}

type PolicyStartupConfig struct {
	DatabasePath string
	ArchiveRoot  string
	Binding      policystore.AuthorityBinding
	WorkerID     string
	Core         PolicyCustody

	OpenDatabase func() (PolicyDatabase, error)
	OpenAudit    func() (signerkit.DurableAuditSink, error)
	BuildServer  func(PolicyDatabase) (*Server, error)
	BuildHandler func(*PolicyEngine, *policyarchive.Archive) (http.Handler, error)
	// StopIntake synchronously stops the owning HTTP server from accepting work.
	StopIntake func() error

	Now    func() time.Time
	Fault  func(PolicyFaultPoint) error
	Sleep  func(context.Context, time.Duration) error
	Jitter func(time.Duration) time.Duration
}

// PolicyRuntime owns the resource tail whose close order is security
// significant. The maintenance lease is always released last.
type PolicyRuntime struct {
	Server   *Server
	Engine   *PolicyEngine
	Database PolicyDatabase
	Archive  *policyarchive.Archive
	Audit    signerkit.DurableAuditSink
	Lease    *policyarchive.MaintenanceLease
	stopHTTP func() error
	closed   bool
}

// StartPolicy performs the frozen serving order. In particular, lease
// acquisition happens inside this function before OpenDatabase is invoked.
func StartPolicy(ctx context.Context, config PolicyStartupConfig) (_ *PolicyRuntime, returnedErr error) {
	if config.DatabasePath == "" || config.ArchiveRoot == "" || config.OpenDatabase == nil || config.OpenAudit == nil || config.BuildServer == nil || config.BuildHandler == nil || config.StopIntake == nil || config.Core == nil {
		return nil, errors.New("hosted policy startup: incomplete configuration")
	}
	runtime := &PolicyRuntime{}
	defer func() {
		if returnedErr != nil {
			returnedErr = errors.Join(returnedErr, runtime.Close())
		}
	}()

	lease, err := policyarchive.AcquireMaintenanceLease(config.DatabasePath, policyarchive.LeaseShared)
	if err != nil {
		return nil, fmt.Errorf("hosted policy startup: acquire maintenance lease: %w", err)
	}
	runtime.Lease = lease
	if err := lease.Revalidate(); err != nil {
		return nil, fmt.Errorf("hosted policy startup: revalidate maintenance lease: %w", err)
	}

	database, err := config.OpenDatabase()
	if err != nil {
		return nil, fmt.Errorf("hosted policy startup: open database: %w", err)
	}
	runtime.Database = database
	store := database.PolicyStore()
	if store == nil {
		return nil, errors.New("hosted policy startup: database has no policy store")
	}

	archive, err := policyarchive.OpenServing(config.ArchiveRoot, lease)
	if err != nil {
		return nil, fmt.Errorf("hosted policy startup: validate archive root: %w", err)
	}
	runtime.Archive = archive

	audit, err := config.OpenAudit()
	if err != nil {
		return nil, fmt.Errorf("hosted policy startup: open durable audit: %w", err)
	}
	runtime.Audit = audit
	if audit == nil {
		return nil, errors.New("hosted policy startup: durable audit is nil")
	}
	if err := audit.PolicyAuditReady(ctx); err != nil {
		return nil, fmt.Errorf("hosted policy startup: durable audit is not ready: %w", err)
	}

	publicKey, keyID, err := config.Core.SnapshotBaseManifestSigner()
	if err != nil {
		return nil, fmt.Errorf("hosted policy startup: snapshot custody: %w", err)
	}
	binding := config.Binding
	binding.SignerKeyID = keyID
	binding.SignerPublicKey = append([]byte(nil), publicKey...)
	if err := store.BindAuthority(ctx, binding); err != nil {
		return nil, fmt.Errorf("hosted policy startup: bind authority: %w", err)
	}
	if err := archive.PublishBinding(lease, binding.ArchiveID, binding.AuthorityID); err != nil {
		return nil, fmt.Errorf("hosted policy startup: publish archive binding: %w", err)
	}
	if err := archive.PrepareServingShards(lease); err != nil {
		return nil, fmt.Errorf("hosted policy startup: prepare archive shards: %w", err)
	}
	if err := archive.VerifyShards(); err != nil {
		return nil, fmt.Errorf("hosted policy startup: verify archive shards: %w", err)
	}

	server, err := config.BuildServer(database)
	if err != nil {
		return nil, fmt.Errorf("hosted policy startup: build server: %w", err)
	}
	runtime.Server = server
	runtime.stopHTTP = config.StopIntake
	engine, err := NewPolicyEngine(PolicyEngineConfig{
		AuthorityID: binding.AuthorityID, WorkerID: config.WorkerID,
		Store: store, Core: config.Core, Audit: audit, Now: config.Now,
		Fault: config.Fault, Sleep: config.Sleep, Jitter: config.Jitter,
	})
	if err != nil {
		return nil, err
	}
	runtime.Engine = engine
	handler, err := config.BuildHandler(engine, archive)
	if err != nil {
		return nil, fmt.Errorf("hosted policy startup: build handler: %w", err)
	}
	if err := server.AttachPolicy(&PolicyAPIConfig{Engine: engine, Handler: handler, Archive: archive, Lease: lease, DurableAudit: audit}); err != nil {
		return nil, err
	}

	scanner, ok := store.(policystore.SafetyScanner)
	if !ok {
		return nil, errors.New("hosted policy startup: policy store has no one-transaction safety scanner")
	}
	if err := scanner.SafetyScan(ctx, func(tombstone *policystore.Request) error {
		if tombstone == nil {
			if err := archive.VerifyBinding(binding.ArchiveID, binding.AuthorityID); err != nil {
				return err
			}
			return archive.VerifyShards()
		}
		reference := tombstone.ArchiveRef()
		if reference == nil {
			return fmt.Errorf("%w: tombstone has incomplete archive reference", policystore.ErrCorrupt)
		}
		encoded, err := archive.ReadObject(policyarchive.ObjectRef{SHA256: reference.ObjectSHA256, Bytes: reference.RecordBytes})
		if err != nil {
			return err
		}
		_, err = sqlitestore.ResolveTerminalArchive(tombstone, encoded)
		return err
	}); err != nil {
		return nil, fmt.Errorf("hosted policy startup: safety scan: %w", err)
	}
	if err := engine.RosterSweep(ctx); err != nil {
		return nil, fmt.Errorf("hosted policy startup: roster sweep: %w", err)
	}
	if err := engine.Readiness().SetReady(ctx); err != nil {
		return nil, fmt.Errorf("hosted policy startup: set readiness: %w", err)
	}
	if err := server.StartPolicyWorkers(ctx); err != nil {
		return nil, err
	}
	return runtime, nil
}

func (runtime *PolicyRuntime) Close() error {
	if runtime == nil || runtime.closed {
		return nil
	}
	runtime.closed = true
	var err error
	if runtime.Server != nil {
		runtime.Server.MarkPolicyUnready()
	}
	if runtime.stopHTTP != nil {
		err = errors.Join(err, runtime.stopHTTP())
	}
	if runtime.Server != nil {
		err = errors.Join(err, runtime.Server.Close())
	}
	if closer, ok := runtime.Audit.(io.Closer); ok {
		err = errors.Join(err, closer.Close())
	}
	if runtime.Database != nil {
		err = errors.Join(err, runtime.Database.Close())
	}
	if runtime.Archive != nil {
		err = errors.Join(err, runtime.Archive.Close())
	}
	if runtime.Lease != nil {
		err = errors.Join(err, runtime.Lease.Close())
	}
	return err
}
