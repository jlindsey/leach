package main

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	packr "github.com/gobuffalo/packr/v2"
	consul "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/segmentio/ksuid"
)

type serverShutdownError struct {
	st  hclog.CapturedStacktrace
	err error
}

type key int

const (
	requestIDKey key = iota
)

type certData struct {
	FQDN       string
	ExtraNames []string
	NotAfter   time.Time
}
type indexData struct {
	Version, GitSHA string
	Certs           []certData
}

var (
	templatesBox, assetsBox *packr.Box
	templates               map[string]*template.Template
	healthy                 int32
)

func init() {
	healthy = 1
	templatesBox = packr.New("Templates", "./web/templates")
	assetsBox = packr.New("Assets", "./web/assets")
	templates = make(map[string]*template.Template)
}

func runWeb(ctx context.Context, bind, prefix string, kv *consul.KV) error {
	done := make(chan serverShutdownError, 1)

	logger := baseLogger.Named("Web")
	logger.Info("Web listener starting", "bind", bind)

	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(assetsBox)))
	mux.Handle("/healthz", handleHealthz(prefix, kv))
	mux.Handle("/", handleIndex(prefix, kv))

	nextRequestID := func() string { return ksuid.New().String() }

	server := &http.Server{
		Addr:         bind,
		Handler:      tracing(nextRequestID)(logging(logger)(mux)),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	go func() {
		<-ctx.Done()
		logger.Debug("Shutting down webserver")
		atomic.StoreInt32(&healthy, 0)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)

		if err := server.Shutdown(shutdownCtx); err != nil {
			st := hclog.Stacktrace()
			done <- serverShutdownError{st, err}
		}
		close(done)
	}()

	server.ListenAndServe()

	shutdownErr, ok := <-done
	if ok {
		logger.Error("Unable to gracefully shutdown server", "err", shutdownErr.err, shutdownErr.st)
		return shutdownErr.err
	}
	return nil
}

func handleIndex(prefix string, kv *consul.KV) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}

		certs, err := getAllCerts(req.Context(), kv, prefix)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		data := &indexData{
			Version: Version,
			GitSHA:  GitSHA,
		}
		data.Certs = make([]certData, len(certs))
		for i, cert := range certs {
			names := make([]string, 0)
			for _, name := range cert.DNSNames {
				if name == cert.Subject.CommonName {
					continue
				}
				names = append(names, name)
			}
			data.Certs[i] = certData{
				FQDN:       cert.Subject.CommonName,
				ExtraNames: names,
				NotAfter:   cert.NotAfter,
			}
		}

		err = renderTemplate("index.gohtml", data, w)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
	})
}

func handleHealthz(prefix string, kv *consul.KV) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if atomic.LoadInt32(&healthy) != 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		status := map[string]interface{}{
			"watchers": watchers,
		}

		err := renderJSON(status, w)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
}

func renderTemplate(name string, data interface{}, w http.ResponseWriter) error {
	var (
		tmpl *template.Template
		ok   bool
	)

	tmpl, ok = templates[name]
	if !ok {
		var file string
		file, err := templatesBox.FindString(name)
		if err != nil {
			return err
		}

		tmpl, err = template.New(name).Funcs(template.FuncMap{"StringsJoin": strings.Join}).Parse(file)
		if err != nil {
			return err
		}
		templates[name] = tmpl
	}

	return tmpl.Execute(w, data)
}

func renderJSON(data interface{}, w http.ResponseWriter) error {
	out, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(out)
	return err
}

// Compose function for a ServerMux (or other http.Handler) to add request logging
func logging(logger hclog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				requestID, ok := r.Context().Value(requestIDKey).(string)
				if !ok {
					requestID = "unknown"
				}
				logger.Info(requestID, "method", r.Method, "path", r.URL.Path, "remoteAddr", r.RemoteAddr, "userAgent", r.UserAgent())
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Compose function for a ServerMux (or other http.Handler) to add request ID tagging
func tracing(nextRequestID func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-Id")
			if requestID == "" {
				requestID = nextRequestID()
			}
			ctx := context.WithValue(r.Context(), requestIDKey, requestID)
			w.Header().Set("X-Request-Id", requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
