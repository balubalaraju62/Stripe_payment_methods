package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/paymentintent"
	"github.com/stripe/stripe-go/v76/refund"
)

// --- Type Declarations ---

type StripeClient interface {
	CreatePaymentIntent(ctx context.Context, req CreateIntentRequest) (*stripe.PaymentIntent, error)
	CapturePaymentIntent(ctx context.Context, id string, amount int64) (*stripe.PaymentIntent, error)
	CreateRefund(ctx context.Context, paymentIntentID string, req CreateRefundRequest) (*stripe.Refund, error)
	ListPaymentIntents(ctx context.Context, limit int64) ([]*stripe.PaymentIntent, error)
}

type stripeService struct{ log *logrus.Logger }

type mockStripe struct {
	CreateFn  func(ctx context.Context, req CreateIntentRequest) (*stripe.PaymentIntent, error)
	CaptureFn func(ctx context.Context, id string, amount int64) (*stripe.PaymentIntent, error)
	RefundFn  func(ctx context.Context, id string, req CreateRefundRequest) (*stripe.Refund, error)
	ListFn    func(ctx context.Context, limit int64) ([]*stripe.PaymentIntent, error)
}

type PaymentHandler struct {
	svc StripeClient
	log *logrus.Logger
}

type CreateIntentRequest struct {
	Amount                  int64             `json:"amount"`
	Currency                string            `json:"currency"`
	PaymentMethod           string            `json:"payment_method,omitempty"`
	Confirm                 bool              `json:"confirm,omitempty"`
	CaptureMethod           string            `json:"capture_method,omitempty"`
	Description             string            `json:"description,omitempty"`
	AutomaticPaymentMethods *bool             `json:"automatic_payment_methods,omitempty"`
	Metadata                map[string]string `json:"metadata,omitempty"`
}

type CreateRefundRequest struct {
	Amount int64  `json:"amount,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type responseWriter struct {
	status int
	http.ResponseWriter
}

// --- Static Variable Declarations ---

var stripeKey = "sk_test_"

// --- Main Method ---

func main() {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})

	if stripeKey == "" {
		log.Fatal("STRIPE_API_KEY env var is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	stripeSvc := NewStripeService(stripeKey, log)
	r := New(stripeSvc, log)

	// Add middlewares
	r.Use(RequestID())
	r.Use(Logging(log))

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	go func() {
		log.WithField("port", port).Info("server starting")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("server crashed")
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("shutdown signal received")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.WithError(err).Error("server forced to shutdown")
	}
	log.Info("server exiting")
}

// --- Other Functions ---

// RequestID adds a X-Request-ID header if absent.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Request-ID") == "" {
				w.Header().Set("X-Request-ID", uuid.New().String())
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Logging logs each request in structured form.
func Logging(log *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(rw, r)
			log.WithFields(logrus.Fields{
				"method": r.Method,
				"path":   r.URL.Path,
				"status": rw.status,
				"dur_ms": time.Since(start).Milliseconds(),
			}).Info("request")
		})
	}
}

// New initializes the router with payment handler routes.
func New(svc StripeClient, log *logrus.Logger) *mux.Router {
	r := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
	h := NewPaymentHandler(svc, log)

	r.HandleFunc("/create_intent", h.CreateIntent).Methods("POST")
	r.HandleFunc("/capture_intent/{id}", h.CaptureIntent).Methods("POST")
	r.HandleFunc("/create_refund/{id}", h.CreateRefund).Methods("POST")
	r.HandleFunc("/get_intents", h.ListIntents).Methods("GET")
	return r
}

// NewStripeService creates a new instance of StripeClient.
func NewStripeService(apiKey string, log *logrus.Logger) StripeClient {
	stripe.Key = apiKey
	return &stripeService{log: log}
}

// NewPaymentHandler creates a new instance of PaymentHandler.
func NewPaymentHandler(svc StripeClient, log *logrus.Logger) *PaymentHandler {
	return &PaymentHandler{svc: svc, log: log}
}

// writeJSON writes a JSON response to the client.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// CreateIntent handles the creation of a new payment intent.
func (h *PaymentHandler) CreateIntent(w http.ResponseWriter, r *http.Request) {
	var req CreateIntentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}
	pi, err := h.svc.CreatePaymentIntent(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, pi)
}

// CaptureIntent captures a payment intent.
func (h *PaymentHandler) CaptureIntent(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	amount := int64(0)
	if v := r.URL.Query().Get("amount"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			amount = parsed
		}
	}
	pi, err := h.svc.CapturePaymentIntent(r.Context(), id, amount)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, pi)
}

// CreateRefund creates a refund for a payment intent.
func (h *PaymentHandler) CreateRefund(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req CreateRefundRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	re, err := h.svc.CreateRefund(r.Context(), id, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, re)
}

// ListIntents lists the payment intents with a limit.
func (h *PaymentHandler) ListIntents(w http.ResponseWriter, r *http.Request) {
	limit := int64(10)
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			limit = parsed
		}
	}
	ints, err := h.svc.ListPaymentIntents(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ints)
}

// --- Stripe Service Methods ---

// CreatePaymentIntent creates a new payment intent.
func (s *stripeService) CreatePaymentIntent(ctx context.Context, req CreateIntentRequest) (*stripe.PaymentIntent, error) {
	if req.Amount <= 0 {
		return nil, errors.New("amount must be > 0")
	}
	if req.Currency == "" {
		return nil, errors.New("currency is required")
	}

	params := &stripe.PaymentIntentParams{
		Amount:   stripe.Int64(req.Amount),
		Currency: stripe.String(req.Currency),
	}

	// Default manual capture
	capture := req.CaptureMethod
	if capture == "" {
		capture = "manual"
	}
	params.CaptureMethod = stripe.String(capture)

	// Enable automatic payment methods by default
	apm := true
	if req.AutomaticPaymentMethods != nil {
		apm = *req.AutomaticPaymentMethods
	}
	params.AutomaticPaymentMethods = &stripe.PaymentIntentAutomaticPaymentMethodsParams{
		Enabled: stripe.Bool(apm),
	}

	if req.Description != "" {
		params.Description = stripe.String(req.Description)
	}
	if len(req.Metadata) > 0 {
		params.AddMetadata("source", "portone-assignment")
		for k, v := range req.Metadata {
			params.AddMetadata(k, v)
		}
	}
	if req.PaymentMethod != "" {
		params.PaymentMethod = stripe.String(req.PaymentMethod)
	}
	if req.Confirm {
		params.Confirm = stripe.Bool(true)
	}

	pi, err := paymentintent.New(params)
	if err != nil {
		return nil, fmt.Errorf("stripe create intent: %w", err)
	}
	return pi, nil
}

// CapturePaymentIntent captures a payment intent.
func (s *stripeService) CapturePaymentIntent(ctx context.Context, id string, amount int64) (*stripe.PaymentIntent, error) {
	if id == "" {
		return nil, errors.New("id is required")
	}
	params := &stripe.PaymentIntentCaptureParams{}
	if amount > 0 {
		params.AmountToCapture = stripe.Int64(amount)
	}
	pi, err := paymentintent.Capture(id, params)
	if err != nil {
		return nil, fmt.Errorf("stripe capture: %w", err)
	}
	return pi, nil
}

// CreateRefund creates a refund for a payment intent.
func (s *stripeService) CreateRefund(ctx context.Context, paymentIntentID string, req CreateRefundRequest) (*stripe.Refund, error) {
	if paymentIntentID == "" {
		return nil, errors.New("payment_intent id is required")
	}
	params := &stripe.RefundParams{PaymentIntent: stripe.String(paymentIntentID)}
	if req.Amount > 0 {
		params.Amount = stripe.Int64(req.Amount)
	}
	if req.Reason != "" {
		params.Reason = stripe.String(req.Reason)
	}
	r, err := refund.New(params)
	if err != nil {
		return nil, fmt.Errorf("stripe refund: %w", err)
	}
	return r, nil
}

// ListPaymentIntents lists payment intents with a limit.
func (s *stripeService) ListPaymentIntents(ctx context.Context, limit int64) ([]*stripe.PaymentIntent, error) {
	if limit <= 0 {
		limit = 10
	}
	params := &stripe.PaymentIntentListParams{}
	params.Limit = stripe.Int64(limit)
	it := paymentintent.List(params)
	var out []*stripe.PaymentIntent
	for it.Next() {
		out = append(out, it.PaymentIntent())
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("stripe list intents: %w", err)
	}
	return out, nil
}
