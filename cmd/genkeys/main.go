// genkeys gera todas as chaves criptográficas necessárias para o sistema ALPR
// e escreve um arquivo .env pronto para uso.
//
// Uso: go run ./cmd/genkeys [--secrets-dir ./secrets] [--passphrase <senha>]
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/governance"
)

func main() {
	secretsDir := flag.String("secrets-dir", "secrets", "diretório onde as chaves serão salvas")
	passphrase := flag.String("passphrase", "", "passphrase para cifrar a chave mensal (obrigatório)")
	flag.Parse()

	if *passphrase == "" {
		*passphrase = os.Getenv("KEY_PASSPHRASE")
	}
	if *passphrase == "" {
		log.Fatal("--passphrase ou KEY_PASSPHRASE é obrigatório")
	}

	if err := os.MkdirAll(*secretsDir, 0700); err != nil {
		log.Fatalf("criar diretório %s: %v", *secretsDir, err)
	}

	// Judge ECDSA P-256
	judgeSK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("gerar chave do juiz: %v", err)
	}
	if err := saveJudgeSK(filepath.Join(*secretsDir, "judge.pem"), judgeSK); err != nil {
		log.Fatalf("salvar judge.pem: %v", err)
	}
	if err := saveJudgePK(filepath.Join(*secretsDir, "judge.pub.pem"), &judgeSK.PublicKey); err != nil {
		log.Fatalf("salvar judge.pub.pem: %v", err)
	}
	fmt.Println("✓ Chave ECDSA do juiz gerada: secrets/judge.pem + secrets/judge.pub.pem")

	// Monthly X25519
	monthlySK, err := governance.GenerateMonthlyKeyPair()
	if err != nil {
		log.Fatalf("gerar chave mensal: %v", err)
	}
	monthlyPath := filepath.Join(*secretsDir, "monthly.key")
	if err := governance.SaveMonthlyKey(monthlyPath, monthlySK, []byte(*passphrase)); err != nil {
		log.Fatalf("salvar monthly.key: %v", err)
	}
	keyMonth := governance.KeyMonth()
	fmt.Printf("✓ Chave mensal X25519 gerada: secrets/monthly.key (key_month=%s)\n", keyMonth)

	// K_gov
	kgov, err := governance.GenerateKgov()
	if err != nil {
		log.Fatalf("gerar K_gov: %v", err)
	}
	kgovPath := filepath.Join(*secretsDir, "kgov.bin")
	if err := os.WriteFile(kgovPath, kgov, 0600); err != nil {
		log.Fatalf("salvar kgov.bin: %v", err)
	}
	fmt.Println("✓ K_gov gerado: secrets/kgov.bin")

	// Gera API keys aleatórias simples (hex 16 bytes)
	cameraKey := randomHex(16)
	investigatorKey := randomHex(16)

	// Escreve .env
	envContent := fmt.Sprintf(`# Gerado por cmd/genkeys em %s
# NÃO comite este arquivo. Adicione .env ao .gitignore.

# ── Banco de dados ─────────────────────────────────────────────────────────────
DB_USER=tcc
DB_PASSWORD=%s
DB_PRINCIPAL_NAME=tcc_principal
DB_BOLO_NAME=tcc_bolo

# ── Portas dos serviços ────────────────────────────────────────────────────────
SERVIDOR_PORT=8080
BOLO_PORT=8081
GOVERNANCA_PORT=8090

# ── Coletor (simulador ALPR) ───────────────────────────────────────────────────
CAMERA_ID=CAM-SIM-001
KEY_MONTH=%s

# ── Governança ─────────────────────────────────────────────────────────────────
JUDGE_SK_PATH=secrets/judge.pem
MONTHLY_KEY_PATH=secrets/monthly.key
KGOV_PATH=secrets/kgov.bin
KEY_PASSPHRASE=%s
CAMERA_API_KEY=%s
INVESTIGATOR_API_KEY=%s

# ── Servidor de custódia ────────────────────────────────────────────────────────
JUDGE_PK_PATH=secrets/judge.pub.pem
`, time.Now().Format(time.RFC3339), randomHex(8), keyMonth, *passphrase, cameraKey, investigatorKey)

	if err := os.WriteFile(".env", []byte(envContent), 0600); err != nil {
		log.Fatalf("escrever .env: %v", err)
	}
	fmt.Println("✓ .env escrito com todas as variáveis preenchidas")
	fmt.Println()
	fmt.Println("Próximos passos:")
	fmt.Println("  1. Edite .env e defina uma DB_PASSWORD segura")
	fmt.Println("  2. make up   (sobe todos os serviços com Docker Compose)")
	fmt.Println("  3. make test (executa testes unitários)")
}

func saveJudgeSK(path string, sk *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(sk)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func saveJudgePK(path string, pk *ecdsa.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
