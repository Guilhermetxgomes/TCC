// cliente é a ferramenta do investigador autorizado.
//
// Uso:
//
//	cliente -modo open    -camera CAM-001 -inicio 2026-06-01T00:00:00Z -fim 2026-06-30T23:59:59Z
//	cliente -modo closed  -placa  ABC1234
//	cliente -modo total   -camera CAM-001 -inicio 2026-06-01T00:00:00Z -fim 2026-06-30T23:59:59Z -sk-hex <hex>
//
// Variáveis de ambiente obrigatórias:
//
//	SERVIDOR_URL          ex: http://localhost:8080
//	GOVERNANCA_URL        ex: http://localhost:8090
//	INVESTIGATOR_API_KEY  chave de acesso à governança
//	DECODED_BY            identificador do investigador (para o log de auditoria)
//	KGOV_PATH             caminho para kgov.bin (necessário para -modo closed)
package main

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/crypto/crumpling"
	"github.com/Guilhermetxgomes/TCC/internal/token"
)

func main() {
	modo := flag.String("modo", "", "open | closed | total")
	cameraID := flag.String("camera", "", "camera_id (open, total)")
	placa := flag.String("placa", "", "placa em texto claro (closed)")
	inicio := flag.String("inicio", "", "RFC3339 início do período (open, total)")
	fim := flag.String("fim", "", "RFC3339 fim do período (open, total)")
	skHex := flag.String("sk-hex", "", "SK mensal reconstruída em hex (total)")
	ttl := flag.Int("ttl", 60, "validade do token em minutos")
	flag.Parse()

	servidorURL := mustEnv("SERVIDOR_URL")
	govURL := mustEnv("GOVERNANCA_URL")
	invKey := mustEnv("INVESTIGATOR_API_KEY")
	decodedBy := mustEnv("DECODED_BY")

	switch *modo {
	case "open":
		if *cameraID == "" || *inicio == "" || *fim == "" {
			log.Fatal("modo open requer -camera, -inicio e -fim")
		}
		runOpen(servidorURL, govURL, invKey, decodedBy, *cameraID, *inicio, *fim, *ttl)
	case "closed":
		if *placa == "" {
			log.Fatal("modo closed requer -placa")
		}
		kgov := loadKgov(env("KGOV_PATH", "secrets/kgov.bin"))
		runClosed(servidorURL, govURL, invKey, decodedBy, *placa, kgov, *ttl)
	case "total":
		if *cameraID == "" || *inicio == "" || *fim == "" || *skHex == "" {
			log.Fatal("modo total requer -camera, -inicio, -fim e -sk-hex")
		}
		skBytes, err := hex.DecodeString(*skHex)
		if err != nil {
			log.Fatalf("sk-hex inválido: %v", err)
		}
		monthlySK, err := ecdh.X25519().NewPrivateKey(skBytes)
		if err != nil {
			log.Fatalf("sk-hex não é uma chave X25519 válida: %v", err)
		}
		runTotal(servidorURL, govURL, invKey, decodedBy, *cameraID, *inicio, *fim, monthlySK, *ttl)
	default:
		log.Fatal("uso: cliente -modo <open|closed|total> [flags]\n\n  -h para ver todas as opções")
	}
}

// ----- modos de busca -----

func runOpen(servidorURL, govURL, invKey, decodedBy, cameraID, inicio, fim string, ttl int) {
	tok := requestToken(govURL, invKey, token.SearchOpen, map[string]any{
		"camera_id":   cameraID,
		"start":       inicio,
		"end":         fim,
		"decoded_by":  decodedBy,
		"ttl_minutes": ttl,
	})

	records := fetchRecords(servidorURL+"/records", tok,
		"camera_id="+cameraID+"&start="+inicio+"&end="+fim)

	fmt.Printf("Busca Aberta — câmera %s (%s → %s)\n", cameraID, inicio, fim)
	fmt.Printf("%d registro(s) encontrado(s)\n\n", len(records))

	for i, rec := range records {
		ad := []byte(rec.CameraID + "|" + rec.CapturedAt)
		plain, err := crumpling.Open(
			rec.OpenPayload.Ciphertext,
			rec.OpenPayload.Nonce,
			rec.OpenPayload.PuzzlePrefix,
			ad,
			rec.OpenPayload.EntropyBits,
		)
		if err != nil {
			fmt.Printf("[%d] record_id=%s — ERRO: %v\n\n", i+1, rec.RecordID, err)
			continue
		}
		printPlaintext(i+1, rec.RecordID, plain)
	}
}

func runClosed(servidorURL, govURL, invKey, decodedBy, placa string, kgov []byte, ttl int) {
	mac := hmac.New(sha256.New, kgov)
	mac.Write([]byte(placa))
	plateHMAC := mac.Sum(nil)
	plateHex := hex.EncodeToString(plateHMAC)

	tok := requestToken(govURL, invKey, token.SearchClosed, map[string]any{
		"plate_hmac":  plateHex,
		"decoded_by":  decodedBy,
		"ttl_minutes": ttl,
	})

	records := fetchRecords(servidorURL+"/records/closed", tok, "plate_hmac="+plateHex)

	fmt.Printf("Busca Fechada — placa %s\n", placa)
	fmt.Printf("%d registro(s) encontrado(s)\n\n", len(records))

	for i, rec := range records {
		ad := []byte(placa)
		plain, err := crumpling.Open(
			rec.ClosedPayload.Ciphertext,
			rec.ClosedPayload.Nonce,
			rec.ClosedPayload.PuzzlePrefix,
			ad,
			rec.ClosedPayload.EntropyBits,
		)
		if err != nil {
			fmt.Printf("[%d] record_id=%s — ERRO: %v\n\n", i+1, rec.RecordID, err)
			continue
		}
		printPlaintext(i+1, rec.RecordID, plain)
	}
}

func runTotal(servidorURL, govURL, invKey, decodedBy, cameraID, inicio, fim string, monthlySK *ecdh.PrivateKey, ttl int) {
	tok := requestToken(govURL, invKey, token.SearchOpen, map[string]any{
		"camera_id":   cameraID,
		"start":       inicio,
		"end":         fim,
		"decoded_by":  decodedBy,
		"ttl_minutes": ttl,
	})

	records := fetchRecords(servidorURL+"/records", tok,
		"camera_id="+cameraID+"&start="+inicio+"&end="+fim)

	fmt.Printf("Busca Total (acesso excepcional) — câmera %s (%s → %s)\n", cameraID, inicio, fim)
	fmt.Printf("%d registro(s) encontrado(s)\n\n", len(records))

	for i, rec := range records {
		p, err := alpr.DecryptTotal(rec, monthlySK)
		if err != nil {
			fmt.Printf("[%d] record_id=%s — ERRO DecryptTotal: %v\n\n", i+1, rec.RecordID, err)
			continue
		}
		printALPRPlaintext(i+1, rec.RecordID, p)
	}
}

// ----- helpers HTTP -----

func requestToken(govURL, invKey string, searchType token.SearchType, payload map[string]any) string {
	payload["search_type"] = string(searchType)
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, govURL+"/tokens", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Investigator-Key", invKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("requestToken: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		log.Fatalf("governança retornou %d: %s", resp.StatusCode, data)
	}

	var result struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Token
}

func fetchRecords(url, rawToken, query string) []alpr.ALPRRecord {
	req, _ := http.NewRequest(http.MethodGet, url+"?"+query, nil)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString([]byte(rawToken)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("fetchRecords: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		log.Fatalf("servidor retornou %d: %s", resp.StatusCode, data)
	}

	var records []alpr.ALPRRecord
	json.NewDecoder(resp.Body).Decode(&records)
	return records
}

// ----- apresentação -----

func printPlaintext(n int, recordID string, plainJSON []byte) {
	var p alpr.ALPRPlaintext
	if err := json.Unmarshal(plainJSON, &p); err != nil {
		fmt.Printf("[%d] record_id=%s — JSON inválido: %v\n\n", n, recordID, err)
		return
	}
	printALPRPlaintext(n, recordID, p)
}

func printALPRPlaintext(n int, recordID string, p alpr.ALPRPlaintext) {
	speed := "—"
	if p.Speed != nil {
		speed = fmt.Sprintf("%.1f km/h", *p.Speed)
	}
	fmt.Printf("[%d] record_id=%s\n", n, recordID)
	fmt.Printf("    Placa       : %s\n", p.Plate)
	fmt.Printf("    Capturado em: %s\n", p.CapturedAt.Format(time.RFC3339))
	fmt.Printf("    Localização : lat=%.6f lon=%.6f\n", p.PreciseLocation.Latitude, p.PreciseLocation.Longitude)
	fmt.Printf("    Confiança   : %.0f%%\n", p.Confidence*100)
	fmt.Printf("    Velocidade  : %s\n", speed)
	fmt.Println()
}

// ----- utilitários -----

func loadKgov(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("KGOV_PATH=%s não encontrado: %v", path, err)
	}
	if len(data) != 32 {
		log.Fatalf("kgov.bin deve ter 32 bytes, tem %d", len(data))
	}
	return data
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("variável obrigatória não definida: %s", key)
	}
	return v
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
