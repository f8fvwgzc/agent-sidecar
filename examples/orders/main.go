// orders: a plain Go HTTP service with zero agentsc SDK. It talks to its sidecar on localhost.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type order struct {
	ID       string `json:"id"`
	SKU      string `json:"sku"`
	Qty      int    `json:"qty"`
	Status   string `json:"status"`
	Customer string `json:"customer"`
}

var orders = map[string]order{
	"1001": {ID: "1001", SKU: "WIDGET-1", Qty: 3, Status: "paid", Customer: "cust-77"},
	"1002": {ID: "1002", SKU: "GADGET-2", Qty: 1, Status: "shipped", Customer: "cust-12"},
}

func main() {
	sidecar := os.Getenv("AGENTSC_URL")
	if sidecar == "" {
		sidecar = "http://127.0.0.1:3500"
	}
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	client := &http.Client{Timeout: 5 * time.Minute}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	mux.HandleFunc("GET /orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		o, ok := orders[r.PathValue("id")]
		w.Header().Set("content-type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "no such order"})
			return
		}
		json.NewEncoder(w).Encode(o)
	})
	// POST /ask {"question": "..."} → the ops-assistant agent in our sidecar. No SDK: one HTTP call to localhost.
	mux.HandleFunc("POST /ask", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Question string `json:"question"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Question == "" {
			http.Error(w, `{"error":"body must be {\"question\": string}"}`, http.StatusBadRequest)
			return
		}
		body, _ := json.Marshal(map[string]any{
			"input":   in.Question,
			"context": map[string]any{"source": "orders /ask"},
		})
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, sidecar+"/v1/agents/ops-assistant/invoke", bytes.NewReader(body))
		req.Header.Set("content-type", "application/json")
		if tp := r.Header.Get("traceparent"); tp != "" {
			req.Header.Set("traceparent", tp)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("sidecar unreachable: %v", err)
			http.Error(w, `{"error":"sidecar unreachable"}`, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for _, h := range []string{"content-type", "traceparent", "x-agentsc-request-id"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
	log.Printf("orders listening on %s, sidecar at %s", addr, sidecar)
	log.Fatal(http.ListenAndServe(addr, mux))
}
