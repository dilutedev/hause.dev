package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	sessionCookieName       = "__Host-hause-admin"
	sessionLifetime         = 12 * time.Hour
	freshVerificationWindow = 10 * time.Minute
	ceremonyLifetime        = 5 * time.Minute
	enrollmentLifetime      = 10 * time.Minute
	maxPendingEnrollments   = 5
	attemptsPerMinute       = 30
	enrollmentCodeAlphabet  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

type session struct {
	deviceID   string
	expiresAt  time.Time
	verifiedAt time.Time
}

type ceremonyKind int

const (
	signInCeremony ceremonyKind = iota
	registrationCeremony
)

type ceremony struct {
	kind         ceremonyKind
	data         webauthn.SessionData
	deviceName   string
	setupToken   string
	enrollmentID string
	expiresAt    time.Time
}

type enrollment struct {
	secret     string
	code       string
	deviceName string
	approved   bool
	expiresAt  time.Time
}

type rateWindow struct {
	count   int
	resetAt time.Time
}

type App struct {
	store         *Store
	relyingParty  *webauthn.WebAuthn
	monitor       *ProcessMonitor
	dataDirectory string
	origin        string

	mutex       sync.Mutex
	sessions    map[string]*session
	ceremonies  map[string]*ceremony
	enrollments map[string]*enrollment
	rateWindows map[string]*rateWindow
}

type sessionHandler func(http.ResponseWriter, *http.Request, string, session)

func newApp(store *Store, relyingParty *webauthn.WebAuthn, monitor *ProcessMonitor, dataDirectory, origin string) *App {
	return &App{
		store:         store,
		relyingParty:  relyingParty,
		monitor:       monitor,
		dataDirectory: dataDirectory,
		origin:        origin,
		sessions:      map[string]*session{},
		ceremonies:    map[string]*ceremony{},
		enrollments:   map[string]*enrollment{},
		rateWindows:   map[string]*rateWindow{},
	}
}

func (app *App) routes(staticFiles fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(staticFiles))
	mux.HandleFunc("GET /api/state", app.handleState)
	mux.HandleFunc("POST /api/login/begin", app.limited(app.handleLoginBegin))
	mux.HandleFunc("POST /api/login/finish", app.limited(app.handleLoginFinish))
	mux.HandleFunc("POST /api/logout", app.handleLogout)
	mux.HandleFunc("POST /api/register/begin", app.limited(app.handleRegisterBegin))
	mux.HandleFunc("POST /api/register/finish", app.limited(app.handleRegisterFinish))
	mux.HandleFunc("POST /api/enrollments", app.limited(app.handleEnrollmentCreate))
	mux.HandleFunc("POST /api/enrollments/status", app.handleEnrollmentStatus)
	mux.HandleFunc("POST /api/enrollments/approve", app.requireSession(true, app.handleEnrollmentApprove))
	mux.HandleFunc("GET /api/devices", app.requireSession(false, app.handleDeviceList))
	mux.HandleFunc("DELETE /api/devices/{id}", app.requireSession(true, app.handleDeviceRemove))
	mux.HandleFunc("GET /api/processes", app.requireSession(false, app.handleProcessList))
	mux.HandleFunc("GET /api/processes/{pid}/details", app.requireSession(false, app.handleProcessDetails))
	mux.HandleFunc("POST /api/processes/signal", app.requireSession(true, app.handleProcessSignal))
	return app.securityHeaders(app.sameOriginWrites(mux))
}

func (app *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		header := writer.Header()
		header.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		header.Set("X-Robots-Tag", "noindex, nofollow")
		if strings.HasPrefix(request.URL.Path, "/api/") {
			header.Set("Cache-Control", "no-store")
		} else {
			header.Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(writer, request)
	})
}

func (app *App) sameOriginWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			if request.Header.Get("Origin") != app.origin {
				writeError(writer, http.StatusForbidden, "", "Cross-origin request blocked.")
				return
			}
			request.Body = http.MaxBytesReader(writer, request.Body, 64<<10)
		}
		next.ServeHTTP(writer, request)
	})
}

func (app *App) limited(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		address := clientAddress(request)
		now := time.Now()
		app.mutex.Lock()
		window := app.rateWindows[address]
		if window == nil || now.After(window.resetAt) {
			window = &rateWindow{resetAt: now.Add(time.Minute)}
			app.rateWindows[address] = window
		}
		window.count++
		overLimit := window.count > attemptsPerMinute
		app.mutex.Unlock()
		if overLimit {
			writer.Header().Set("Retry-After", "60")
			writeError(writer, http.StatusTooManyRequests, "", "Too many attempts. Wait a minute and try again.")
			return
		}
		next(writer, request)
	}
}

func (app *App) requireSession(needsFreshVerification bool, next sessionHandler) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		token, current, ok := app.currentSession(request)
		if !ok {
			writeError(writer, http.StatusUnauthorized, "signin", "Sign in to continue.")
			return
		}
		if needsFreshVerification && time.Since(current.verifiedAt) > freshVerificationWindow {
			writeError(writer, http.StatusUnauthorized, "reauth", "Confirm with your passkey to continue.")
			return
		}
		next(writer, request, token, current)
	}
}

func (app *App) currentSession(request *http.Request) (string, session, bool) {
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return "", session{}, false
	}
	app.mutex.Lock()
	defer app.mutex.Unlock()
	current, ok := app.sessions[cookie.Value]
	if !ok {
		return "", session{}, false
	}
	if time.Now().After(current.expiresAt) || !app.store.hasDevice(current.deviceID) {
		delete(app.sessions, cookie.Value)
		return "", session{}, false
	}
	return cookie.Value, *current, true
}

func (app *App) startSession(writer http.ResponseWriter, request *http.Request, deviceID string) session {
	now := time.Now()
	token := randomToken(32)
	created := session{deviceID: deviceID, expiresAt: now.Add(sessionLifetime), verifiedAt: now}
	app.mutex.Lock()
	if previous, err := request.Cookie(sessionCookieName); err == nil {
		delete(app.sessions, previous.Value)
	}
	app.sessions[token] = &created
	app.mutex.Unlock()
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionLifetime.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	return created
}

func clearSessionCookie(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func sessionState(current session) map[string]any {
	return map[string]any{
		"signedIn":   true,
		"deviceId":   current.deviceID,
		"freshUntil": current.verifiedAt.Add(freshVerificationWindow).UnixMilli(),
	}
}

func (app *App) saveCeremony(pending *ceremony) string {
	identifier := randomToken(16)
	pending.expiresAt = time.Now().Add(ceremonyLifetime)
	app.mutex.Lock()
	app.ceremonies[identifier] = pending
	app.mutex.Unlock()
	return identifier
}

func (app *App) takeCeremony(identifier string, kind ceremonyKind) *ceremony {
	app.mutex.Lock()
	defer app.mutex.Unlock()
	pending, ok := app.ceremonies[identifier]
	if !ok {
		return nil
	}
	delete(app.ceremonies, identifier)
	if pending.kind != kind || time.Now().After(pending.expiresAt) {
		return nil
	}
	return pending
}

func (app *App) handleState(writer http.ResponseWriter, request *http.Request) {
	_, current, ok := app.currentSession(request)
	if !ok {
		writeJSON(writer, http.StatusOK, map[string]any{"signedIn": false})
		return
	}
	writeJSON(writer, http.StatusOK, sessionState(current))
}

func (app *App) handleLoginBegin(writer http.ResponseWriter, request *http.Request) {
	if app.store.deviceCount() == 0 {
		writeError(writer, http.StatusConflict, "", "No passkeys are registered yet. Use the setup link from the server log.")
		return
	}
	options, data, err := app.relyingParty.BeginLogin(app.store.owner(), webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		log.Printf("begin sign-in: %v", err)
		writeError(writer, http.StatusInternalServerError, "", "Couldn't start sign-in.")
		return
	}
	identifier := app.saveCeremony(&ceremony{kind: signInCeremony, data: *data})
	writeJSON(writer, http.StatusOK, map[string]any{"ceremony": identifier, "options": options})
}

func (app *App) handleLoginFinish(writer http.ResponseWriter, request *http.Request) {
	pending := app.takeCeremony(request.URL.Query().Get("ceremony"), signInCeremony)
	if pending == nil {
		writeError(writer, http.StatusBadRequest, "expired", "That sign-in attempt expired. Try again.")
		return
	}
	credential, err := app.relyingParty.FinishLogin(app.store.owner(), pending.data, request)
	if err != nil {
		log.Printf("sign-in rejected from %s: %v", clientAddress(request), err)
		writeError(writer, http.StatusUnauthorized, "", "That passkey wasn't accepted.")
		return
	}
	if credential.Authenticator.CloneWarning {
		log.Printf("sign-in rejected from %s: signature counter went backwards", clientAddress(request))
		writeError(writer, http.StatusUnauthorized, "", "This passkey looks cloned, so it was rejected. Remove the device and add it again.")
		return
	}
	device, err := app.store.recordSignIn(credential)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "", "That passkey wasn't accepted.")
		return
	}
	log.Printf("signed in: %s from %s", device.Name, clientAddress(request))
	writeJSON(writer, http.StatusOK, sessionState(app.startSession(writer, request, device.ID)))
}

func (app *App) handleLogout(writer http.ResponseWriter, request *http.Request) {
	if cookie, err := request.Cookie(sessionCookieName); err == nil {
		app.mutex.Lock()
		delete(app.sessions, cookie.Value)
		app.mutex.Unlock()
	}
	clearSessionCookie(writer)
	writeJSON(writer, http.StatusOK, map[string]any{"signedIn": false})
}

func (app *App) handleRegisterBegin(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		SetupToken       string `json:"setupToken"`
		EnrollmentID     string `json:"enrollmentId"`
		EnrollmentSecret string `json:"enrollmentSecret"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	pending := &ceremony{kind: registrationCeremony}
	switch {
	case body.SetupToken != "":
		if !setupTokenValid(app.dataDirectory, body.SetupToken) {
			writeError(writer, http.StatusForbidden, "", "This setup link is invalid or expired. Run hause-admin setup-link on the server for a new one.")
			return
		}
		pending.setupToken = body.SetupToken
	case body.EnrollmentID != "":
		deviceName, ok := app.approvedEnrollment(body.EnrollmentID, body.EnrollmentSecret)
		if !ok {
			writeError(writer, http.StatusForbidden, "", "This device hasn't been approved, or the approval expired.")
			return
		}
		pending.enrollmentID = body.EnrollmentID
		pending.deviceName = deviceName
	default:
		writeError(writer, http.StatusForbidden, "", "Adding a device needs approval from a device that's already signed in.")
		return
	}
	options, data, err := app.relyingParty.BeginRegistration(
		app.store.owner(),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(app.store.credentialDescriptors()),
	)
	if err != nil {
		log.Printf("begin registration: %v", err)
		writeError(writer, http.StatusInternalServerError, "", "Couldn't start passkey creation.")
		return
	}
	pending.data = *data
	writeJSON(writer, http.StatusOK, map[string]any{"ceremony": app.saveCeremony(pending), "options": options})
}

func (app *App) handleRegisterFinish(writer http.ResponseWriter, request *http.Request) {
	pending := app.takeCeremony(request.URL.Query().Get("ceremony"), registrationCeremony)
	if pending == nil {
		writeError(writer, http.StatusBadRequest, "expired", "That attempt expired. Try again.")
		return
	}
	credential, err := app.relyingParty.FinishRegistration(app.store.owner(), pending.data, request)
	if err != nil {
		log.Printf("registration rejected from %s: %v", clientAddress(request), err)
		writeError(writer, http.StatusBadRequest, "", "The passkey couldn't be verified.")
		return
	}
	deviceName := pending.deviceName
	if pending.setupToken != "" {
		if !setupTokenValid(app.dataDirectory, pending.setupToken) {
			writeError(writer, http.StatusForbidden, "", "This setup link was already used or has expired.")
			return
		}
		discardSetupToken(app.dataDirectory)
		deviceName = cleanDeviceName(request.URL.Query().Get("name"))
	} else if !app.consumeEnrollment(pending.enrollmentID) {
		writeError(writer, http.StatusForbidden, "", "The approval for this device expired. Request access again.")
		return
	}
	device, err := app.store.addDevice(deviceName, credential)
	if err != nil {
		log.Printf("saving device: %v", err)
		writeError(writer, http.StatusInternalServerError, "", "The passkey was created but couldn't be saved.")
		return
	}
	log.Printf("device added: %s from %s", device.Name, clientAddress(request))
	writeJSON(writer, http.StatusOK, sessionState(app.startSession(writer, request, device.ID)))
}

func (app *App) handleEnrollmentCreate(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	now := time.Now()
	app.mutex.Lock()
	pendingCount := 0
	for _, existing := range app.enrollments {
		if now.Before(existing.expiresAt) {
			pendingCount++
		}
	}
	if pendingCount >= maxPendingEnrollments {
		app.mutex.Unlock()
		writeError(writer, http.StatusTooManyRequests, "", "Too many devices are waiting for approval. Try again in a few minutes.")
		return
	}
	identifier := randomToken(12)
	created := &enrollment{
		secret:     randomToken(32),
		code:       randomEnrollmentCode(),
		deviceName: cleanDeviceName(body.Name),
		expiresAt:  now.Add(enrollmentLifetime),
	}
	app.enrollments[identifier] = created
	app.mutex.Unlock()
	log.Printf("access requested: %s from %s", created.deviceName, clientAddress(request))
	writeJSON(writer, http.StatusOK, map[string]any{
		"id":        identifier,
		"secret":    created.secret,
		"code":      created.code[:4] + "-" + created.code[4:],
		"expiresAt": created.expiresAt.UnixMilli(),
	})
}

func (app *App) handleEnrollmentStatus(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	app.mutex.Lock()
	existing, ok := app.enrollments[body.ID]
	status := "expired"
	if ok && subtle.ConstantTimeCompare([]byte(existing.secret), []byte(body.Secret)) == 1 && time.Now().Before(existing.expiresAt) {
		status = "pending"
		if existing.approved {
			status = "approved"
		}
	}
	app.mutex.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{"status": status})
}

func (app *App) handleEnrollmentApprove(writer http.ResponseWriter, request *http.Request, _ string, current session) {
	var body struct {
		Code string `json:"code"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	code := normalizeEnrollmentCode(body.Code)
	now := time.Now()
	app.mutex.Lock()
	var approved *enrollment
	for _, existing := range app.enrollments {
		if !existing.approved && now.Before(existing.expiresAt) && subtle.ConstantTimeCompare([]byte(existing.code), []byte(code)) == 1 {
			approved = existing
		}
	}
	if approved != nil {
		approved.approved = true
		approved.expiresAt = now.Add(enrollmentLifetime)
	}
	app.mutex.Unlock()
	if approved == nil {
		writeError(writer, http.StatusNotFound, "", "No device is waiting with that code. Check it, or request access again if it expired.")
		return
	}
	log.Printf("access approved: %s by device %s", approved.deviceName, current.deviceID)
	writeJSON(writer, http.StatusOK, map[string]any{"name": approved.deviceName})
}

func (app *App) approvedEnrollment(identifier, secret string) (string, bool) {
	app.mutex.Lock()
	defer app.mutex.Unlock()
	existing, ok := app.enrollments[identifier]
	if !ok || !existing.approved || time.Now().After(existing.expiresAt) {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(existing.secret), []byte(secret)) != 1 {
		return "", false
	}
	return existing.deviceName, true
}

func (app *App) consumeEnrollment(identifier string) bool {
	app.mutex.Lock()
	defer app.mutex.Unlock()
	existing, ok := app.enrollments[identifier]
	if !ok {
		return false
	}
	delete(app.enrollments, identifier)
	return existing.approved && time.Now().Before(existing.expiresAt)
}

func (app *App) handleDeviceList(writer http.ResponseWriter, request *http.Request, _ string, current session) {
	type deviceSummary struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		CreatedAt  int64  `json:"createdAt"`
		LastUsedAt int64  `json:"lastUsedAt"`
		Current    bool   `json:"current"`
	}
	devices := app.store.listDevices()
	summaries := make([]deviceSummary, len(devices))
	for index, device := range devices {
		summaries[index] = deviceSummary{
			ID:         device.ID,
			Name:       device.Name,
			CreatedAt:  device.CreatedAt.UnixMilli(),
			LastUsedAt: device.LastUsedAt.UnixMilli(),
			Current:    device.ID == current.deviceID,
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"devices": summaries})
}

func (app *App) handleDeviceRemove(writer http.ResponseWriter, request *http.Request, _ string, current session) {
	deviceID := request.PathValue("id")
	if err := app.store.removeDevice(deviceID); err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, errLastDevice):
			status = http.StatusConflict
		case errors.Is(err, errDeviceNotFound):
			status = http.StatusNotFound
		default:
			log.Printf("removing device: %v", err)
		}
		writeError(writer, status, "", err.Error())
		return
	}
	app.mutex.Lock()
	for token, existing := range app.sessions {
		if existing.deviceID == deviceID {
			delete(app.sessions, token)
		}
	}
	app.mutex.Unlock()
	log.Printf("device removed: %s by device %s", deviceID, current.deviceID)
	if deviceID == current.deviceID {
		clearSessionCookie(writer)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"removed": deviceID, "signedOut": deviceID == current.deviceID})
}

func (app *App) handleProcessList(writer http.ResponseWriter, request *http.Request, _ string, _ session) {
	writeJSON(writer, http.StatusOK, app.monitor.snapshot())
}

func (app *App) handleProcessDetails(writer http.ResponseWriter, request *http.Request, _ string, _ session) {
	processID, err := strconv.Atoi(request.PathValue("pid"))
	if err != nil || processID <= 0 {
		writeError(writer, http.StatusBadRequest, "", "Invalid process ID.")
		return
	}
	startTicks, err := strconv.ParseUint(request.URL.Query().Get("startTicks"), 10, 64)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "", "Invalid start time.")
		return
	}
	details, err := app.monitor.details(processID, startTicks)
	if err != nil {
		writeError(writer, http.StatusGone, "", err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, details)
}

type signalTarget struct {
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"startTicks"`
}

type signalResult struct {
	PID   int    `json:"pid"`
	Name  string `json:"name,omitempty"`
	Error string `json:"error,omitempty"`
}

func (app *App) handleProcessSignal(writer http.ResponseWriter, request *http.Request, _ string, current session) {
	var body struct {
		Signal  string         `json:"signal"`
		Targets []signalTarget `json:"targets"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	if body.Signal != "TERM" && body.Signal != "KILL" {
		writeError(writer, http.StatusBadRequest, "", "Signal must be TERM or KILL.")
		return
	}
	if len(body.Targets) == 0 || len(body.Targets) > 200 {
		writeError(writer, http.StatusBadRequest, "", "Signal needs between 1 and 200 processes.")
		return
	}
	results := make([]signalResult, 0, len(body.Targets))
	for _, target := range body.Targets {
		result := signalResult{PID: target.PID}
		if target.PID <= 1 {
			result.Error = "Invalid process ID."
			results = append(results, result)
			continue
		}
		process, err := app.monitor.sendSignal(target.PID, target.StartTicks, body.Signal)
		if process.Name != "" {
			result.Name = process.Name
		}
		var protectedErr protectedProcessError
		switch {
		case errors.Is(err, errProcessGone):
			result.Error = errProcessGone.Error()
		case errors.As(err, &protectedErr):
			result.Error = err.Error()
		case err != nil:
			log.Printf("signal %s to %d failed: %v", body.Signal, target.PID, err)
			result.Error = err.Error()
		default:
			log.Printf("SIG%s sent to %d (%s) by device %s", body.Signal, target.PID, process.Name, current.deviceID)
		}
		results = append(results, result)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"signal": body.Signal, "results": results})
}

func (app *App) purgeExpiredLoop() {
	ticker := time.NewTicker(time.Minute)
	for now := range ticker.C {
		app.mutex.Lock()
		for key, value := range app.sessions {
			if now.After(value.expiresAt) {
				delete(app.sessions, key)
			}
		}
		for key, value := range app.ceremonies {
			if now.After(value.expiresAt) {
				delete(app.ceremonies, key)
			}
		}
		for key, value := range app.enrollments {
			if now.After(value.expiresAt) {
				delete(app.enrollments, key)
			}
		}
		for key, value := range app.rateWindows {
			if now.After(value.resetAt) {
				delete(app.rateWindows, key)
			}
		}
		app.mutex.Unlock()
	}
}

func randomEnrollmentCode() string {
	randomIndexes := randomBytes(8)
	code := make([]byte, len(randomIndexes))
	for position, value := range randomIndexes {
		code[position] = enrollmentCodeAlphabet[int(value)%len(enrollmentCodeAlphabet)]
	}
	return string(code)
}

func normalizeEnrollmentCode(input string) string {
	var builder strings.Builder
	for _, character := range strings.ToUpper(input) {
		if strings.ContainsRune(enrollmentCodeAlphabet, character) {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

func cleanDeviceName(input string) string {
	cleaned := strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, strings.TrimSpace(input))
	if runes := []rune(cleaned); len(runes) > 40 {
		cleaned = string(runes[:40])
	}
	if cleaned == "" {
		return "Unnamed device"
	}
	return cleaned
}

func clientAddress(request *http.Request) string {
	if realAddress := request.Header.Get("X-Real-IP"); realAddress != "" {
		return realAddress
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, target any) bool {
	if err := json.NewDecoder(request.Body).Decode(target); err != nil {
		writeError(writer, http.StatusBadRequest, "", "Invalid request body.")
		return false
	}
	return true
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]string{"error": message, "code": code})
}
