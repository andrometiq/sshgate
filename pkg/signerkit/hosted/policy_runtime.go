package hosted

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policyarchive"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/src/policyreview"
	"github.com/karthikeyan5/sshgate/src/redact"
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
	if err := policystore.ValidateIdentity(server.MachineClientID); err != nil {
		return fmt.Errorf("hosted: AttachPolicy: MachineClientID: %w", err)
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
	machine := server.policyMachineDispatch(server.policyReady(config.Engine.Readiness(), server.withAuth(server.policyMachineLimit(config.Handler))))
	humanHandler, err := newPolicyHumanHandler(config.Engine, config.Archive, server.Human)
	if err != nil {
		return fmt.Errorf("hosted: AttachPolicy: human handler: %w", err)
	}
	human := server.policyReady(config.Engine.Readiness(), server.Human.withSession(humanHandler.ServeAuthenticated))
	server.mux.Handle("GET /ui/policy/pending", human)
	server.mux.Handle("GET /ui/policy/requests/{review_id}", human)
	server.mux.Handle("POST /ui/policy/requests/{review_id}/approve", human)
	server.mux.Handle("POST /ui/policy/requests/{review_id}/deny", human)
	server.mux.Handle("GET /ui/policy/requests/{review_id}/audit", human)
	server.policyMachine = machine
	server.policyHuman = human
	server.policy = config
	return nil
}

func (server *Server) policyMachineDispatch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		if request.URL.RawQuery != "" {
			writeJSONError(writer, http.StatusNotFound, "not found")
			return
		}
		target := request.URL.EscapedPath()
		collection := target == "/v2/policy/base-manifests"
		resource := validPolicyResourcePath(target)
		switch {
		case collection && request.Method != http.MethodPost, resource && request.Method != http.MethodGet:
			writeJSONError(writer, http.StatusMethodNotAllowed, "method not allowed")
			return
		case !collection && !resource:
			writeJSONError(writer, http.StatusNotFound, "not found")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) policyMachineLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		limiter, maximum := server.policyPostLimit, 120
		if request.Method == http.MethodGet {
			limiter, maximum = server.policyGetLimit, 600
		}
		if !limiter.allow(maximum) {
			writer.Header().Set("Retry-After", "60")
			writeJSONError(writer, http.StatusTooManyRequests, "too many requests")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func validPolicyResourcePath(target string) bool {
	const prefix = "/v2/policy/base-manifests/pm_"
	if len(target) != len(prefix)+32 || !strings.HasPrefix(target, prefix) {
		return false
	}
	for index := len(prefix); index < len(target); index++ {
		if (target[index] < '0' || target[index] > '9') && (target[index] < 'a' || target[index] > 'f') {
			return false
		}
	}
	return true
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
	ticks := server.policyRosterTick
	var ticker *time.Ticker
	if ticks == nil {
		interval := server.policyRosterWait
		if interval <= 0 {
			interval = policyRosterSweepInterval
		}
		ticker = time.NewTicker(interval)
		ticks = ticker.C
		defer ticker.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
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
	Random io.Reader

	ReviewRules           []redact.Rule
	RedactString          policyreview.RedactString
	ReviewRendererVersion string
	ReviewRulesDigest     string
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
	store    policystore.Store
	binding  policystore.AuthorityBinding

	completionOnce    sync.Once
	completionMu      sync.Mutex
	completionCancel  context.CancelFunc
	completionDone    chan struct{}
	completionStarted bool
	completionErr     error
	closed            atomic.Bool
}

// StartPolicy performs the frozen serving order through route mounting. It
// returns with policy readiness false so the caller can begin ordinary HTTP
// service before CompleteStartup runs the initial safety gates.
func StartPolicy(ctx context.Context, config PolicyStartupConfig) (_ *PolicyRuntime, returnedErr error) {
	if config.DatabasePath == "" || config.ArchiveRoot == "" || config.OpenDatabase == nil || config.OpenAudit == nil || config.BuildServer == nil || config.BuildHandler == nil || config.StopIntake == nil || config.Core == nil {
		return nil, errors.New("hosted policy startup: incomplete configuration")
	}
	runtime := &PolicyRuntime{completionDone: make(chan struct{})}
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
	runtime.store = store

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
	runtime.binding = binding
	if err := binding.Config.Validate(); err != nil {
		return nil, fmt.Errorf("hosted policy startup: validate binding config: %w", err)
	}
	if binding.Config.VoterEligibilityVersion != policystore.VoterEligibilityVersion {
		return nil, errors.New("hosted policy startup: binding voter eligibility version mismatch")
	}
	if binding.Config.ReviewRendererVersion != policyreview.RendererVersion || config.ReviewRendererVersion != policyreview.RendererVersion {
		return nil, errors.New("hosted policy startup: review renderer version mismatch")
	}
	if binding.Config.ReviewRulesDigest != policyreview.RulesDigest() || config.ReviewRulesDigest != policyreview.RulesDigest() {
		return nil, errors.New("hosted policy startup: review rules digest mismatch")
	}
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
		Random: config.Random, ReviewRules: config.ReviewRules, RedactString: config.RedactString,
		ReviewRendererVersion: config.ReviewRendererVersion, ReviewRulesDigest: config.ReviewRulesDigest,
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
	return runtime, nil
}

// CompleteStartup runs exactly once after the owning HTTP listener is live.
// A failure is sticky for this runtime: policy remains unready, workers do not
// start, and the already-listening ordinary plane remains available.
func (runtime *PolicyRuntime) CompleteStartup(ctx context.Context) error {
	if runtime == nil {
		return errors.New("hosted policy startup: nil runtime")
	}
	runtime.completionOnce.Do(func() {
		runtime.completionMu.Lock()
		if runtime.closed.Load() {
			runtime.completionErr = errors.New("hosted policy startup: runtime is closed")
			runtime.completionMu.Unlock()
			return
		}
		completionContext, cancel := context.WithCancel(ctx)
		runtime.completionCancel = cancel
		runtime.completionStarted = true
		runtime.completionMu.Unlock()
		defer func() {
			cancel()
			close(runtime.completionDone)
		}()

		runtime.completionErr = runtime.completeStartup(completionContext)
		if runtime.completionErr != nil && runtime.Engine != nil {
			runtime.Engine.Readiness().MarkUnready()
		}
	})
	return runtime.completionErr
}

func (runtime *PolicyRuntime) completeStartup(ctx context.Context) error {
	scanner, ok := runtime.store.(policystore.SafetyScanner)
	if !ok {
		return errors.New("hosted policy startup: policy store has no one-transaction safety scanner")
	}
	if err := scanner.SafetyScan(ctx, func(tombstone *policystore.Request) error {
		if tombstone == nil {
			if err := runtime.Archive.VerifyBinding(runtime.binding.ArchiveID, runtime.binding.AuthorityID); err != nil {
				return err
			}
			return runtime.Archive.VerifyShards()
		}
		reference := tombstone.ArchiveRef()
		if reference == nil {
			return fmt.Errorf("%w: tombstone has incomplete archive reference", policystore.ErrCorrupt)
		}
		encoded, err := runtime.Archive.ReadObject(policyarchive.ObjectRef{SHA256: reference.ObjectSHA256, Bytes: reference.RecordBytes})
		if err != nil {
			return err
		}
		_, err = sqlitestore.ResolveTerminalArchive(tombstone, encoded)
		return err
	}); err != nil {
		return fmt.Errorf("hosted policy startup: safety scan: %w", err)
	}
	if err := runtime.Engine.RosterSweep(ctx); err != nil {
		return fmt.Errorf("hosted policy startup: roster sweep: %w", err)
	}
	if err := runtime.Engine.Readiness().SetReady(ctx); err != nil {
		return fmt.Errorf("hosted policy startup: set readiness: %w", err)
	}
	if err := runtime.Server.StartPolicyWorkers(ctx); err != nil {
		return err
	}
	return nil
}

func (runtime *PolicyRuntime) Close() error {
	if runtime == nil || !runtime.closed.CompareAndSwap(false, true) {
		return nil
	}
	runtime.completionMu.Lock()
	completionCancel := runtime.completionCancel
	var completionDone <-chan struct{}
	if runtime.completionStarted {
		completionDone = runtime.completionDone
	}
	runtime.completionMu.Unlock()
	if completionCancel != nil {
		completionCancel()
	}
	var err error
	if runtime.Server != nil {
		runtime.Server.MarkPolicyUnready()
	}
	if runtime.stopHTTP != nil {
		err = errors.Join(err, runtime.stopHTTP())
	}
	if completionDone != nil {
		<-completionDone
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
