// Package shamir implementa Shamir Secret Sharing em GF(2⁸).
// Cada share tem o formato [x || f(x)_0 || f(x)_1 || ... || f(x)_{len-1}],
// onde x é o índice (1..n) e f(x)_i é o i-ésimo byte do segredo avaliado
// no polinômio aleatório de grau threshold-1.
package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// Split divide secret em n shares, das quais threshold são necessárias para reconstruir.
func Split(secret []byte, n, threshold int) ([][]byte, error) {
	if threshold < 2 {
		return nil, fmt.Errorf("shamir: threshold mínimo é 2, got %d", threshold)
	}
	if n < threshold {
		return nil, fmt.Errorf("shamir: n (%d) deve ser >= threshold (%d)", n, threshold)
	}
	if n > 255 {
		return nil, errors.New("shamir: n máximo é 255")
	}
	if len(secret) == 0 {
		return nil, errors.New("shamir: segredo vazio")
	}

	// Para cada byte do segredo, gera um polinômio de grau threshold-1.
	// O coeficiente a_0 é o próprio byte; os demais são aleatórios.
	coeffs := make([][]byte, len(secret))
	for i, b := range secret {
		poly := make([]byte, threshold)
		poly[0] = b
		if _, err := rand.Read(poly[1:]); err != nil {
			return nil, fmt.Errorf("shamir: rand: %w", err)
		}
		// Garante que o coeficiente de maior grau não seja zero
		// (evita redução do grau efetivo do polinômio).
		for poly[threshold-1] == 0 {
			if _, err := rand.Read(poly[threshold-1:]); err != nil {
				return nil, err
			}
		}
		coeffs[i] = poly
	}

	// Avalia cada polinômio em x = 1..n
	shares := make([][]byte, n)
	for i := 0; i < n; i++ {
		x := byte(i + 1)
		share := make([]byte, 1+len(secret))
		share[0] = x
		for j, poly := range coeffs {
			share[j+1] = eval(poly, x)
		}
		shares[i] = share
	}
	return shares, nil
}

// Combine reconstrói o segredo a partir de threshold ou mais shares.
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("shamir: mínimo de 2 shares necessárias")
	}
	secretLen := len(shares[0]) - 1
	if secretLen <= 0 {
		return nil, errors.New("shamir: share vazia ou malformada")
	}
	for _, s := range shares {
		if len(s) != secretLen+1 {
			return nil, errors.New("shamir: shares com tamanhos incompatíveis")
		}
	}

	// Verifica índices únicos
	seen := make(map[byte]bool)
	for _, s := range shares {
		x := s[0]
		if x == 0 {
			return nil, errors.New("shamir: índice x=0 inválido")
		}
		if seen[x] {
			return nil, fmt.Errorf("shamir: índice duplicado x=%d", x)
		}
		seen[x] = true
	}

	secret := make([]byte, secretLen)
	xs := make([]byte, len(shares))
	ys := make([]byte, len(shares))
	for i, s := range shares {
		xs[i] = s[0]
	}

	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		for i, s := range shares {
			ys[i] = s[byteIdx+1]
		}
		secret[byteIdx] = lagrange(xs, ys)
	}
	return secret, nil
}

// lagrange interpola o valor f(0) via interpolação de Lagrange em GF(2⁸).
func lagrange(xs, ys []byte) byte {
	var result byte
	for i := range xs {
		num := byte(1)
		den := byte(1)
		for j := range xs {
			if i == j {
				continue
			}
			// num *= (0 - xs[j]) = xs[j]  (em GF(2⁸), -x == x)
			num = gfMul(num, xs[j])
			// den *= (xs[i] - xs[j])      (em GF(2⁸), subtração == XOR)
			den = gfMul(den, xs[i]^xs[j])
		}
		result ^= gfMul(ys[i], gfMul(num, gfInv(den)))
	}
	return result
}

// eval avalia o polinômio poly em x usando o esquema de Horner em GF(2⁸).
// poly[0] é o termo constante (a_0), poly[k] é o coeficiente de grau k.
func eval(poly []byte, x byte) byte {
	result := poly[len(poly)-1]
	for i := len(poly) - 2; i >= 0; i-- {
		result = poly[i] ^ gfMul(result, x)
	}
	return result
}

// ── Aritmética em GF(2⁸) com polinômio irredutível x⁸+x⁴+x³+x+1 (0x11b) ──

func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b // x⁸ mod (x⁸+x⁴+x³+x+1) = x⁴+x³+x+1 = 0x1b
		}
		b >>= 1
	}
	return p
}

// gfInv retorna o inverso multiplicativo de a em GF(2⁸) via exponenciação (a^254).
func gfInv(a byte) byte {
	if a == 0 {
		panic("shamir: inverso de 0 em GF(2⁸) indefinido")
	}
	// a^(2⁸-2) = a^254 via quadrados repetidos
	result := byte(1)
	base := a
	exp := 254
	for exp > 0 {
		if exp&1 != 0 {
			result = gfMul(result, base)
		}
		base = gfMul(base, base)
		exp >>= 1
	}
	return result
}
