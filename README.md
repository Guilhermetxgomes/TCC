# TCC — Implementação de sistema de monitoramento de tráfego resistente à vigilância em massa

Trabalho de Conclusão de Curso apresentado ao Departamento de Engenharia de Computação e Sistemas Digitais (PCS) da Escola Politécnica da Universidade de São Paulo.

- **Autores:** Gastón Enrique Christianini Buela, Guilherme Teixeira Gomes, João Pedro Lopes de Sousa Gomes
- **Orientador:** Prof. Dr. Thales Areco Bandiera Paiva
- **Relatório completo:** [`relatorio/main.pdf`](relatorio/main.pdf) (fonte LaTeX em [`relatorio/`](relatorio))

## Resumo

Este projeto apresenta um sistema de proteção para bases de dados de monitoramento de tráfego veicular que utiliza mecanismos criptográficos para equilibrar a segurança pública e a privacidade individual. A solução se fundamenta na tese de *Crypto Crumple Zones* (WRIGHT; VARIA, 2018), que propõe usar criptografia para impor um custo computacional a cada dado recuperado pelas autoridades.
Diferente de modelos de acesso total, a abordagem garante que o custo para acessar dados de um veículo específico seja baixo, mas que o custo acumulado para acessar grandes volumes de dados torne a vigilância em massa economicamente inviável.

## Arquitetura proposta

O relatório avalia três arquiteturas candidatas (Capítulo 3) e converge para uma síntese das três, referida como **Arquitetura 3.0**:

1. **BOLO com desbloqueio excepcional por quórum**: mantém a operacionalidade de consultas *Be On the Lookout* em tempo real (placas roubadas, mandados, *Amber Alert*) sem exigir decifragem.
2. **Vigilância criptografada com governança por quórum e desbloqueio de exceção**: organiza o ciclo de vida do dado em quatro camadas (borda, custódia, governança e exceção): captura com *crumpling* (AES-256-GCM + puzzle de prova de trabalho derivado de SHA-256).
3. **Threshold criptográfico**: introduz um Comitê de Emergência que reconstrói uma chave via *Shamir's Secret Sharing* / *Multi-Party Computation* para acesso excepcional.

A Arquitetura 3.0 resolve a vulnerabilidade de exposição da arquitetura (3) ao adotar **chaves mensais independentes** (pares assimétricos PK/SK em Curve25519, gerados a cada mês e fragmentados via *Shamir's Secret Sharing*), de modo que a reconstrução para acesso excepcional fique restrita ao mês de interesse, sem comprometer os demais períodos.

### Modalidades de busca

- **Busca Aberta**: o investigador não conhece a placa alvo; decifra todos os registros da janela sob investigação (custo escala com o volume da janela).
- **Busca Fechada**: o investigador já conhece a placa alvo; itera os registros até encontrar uma correspondência (custo médio menor, pois interrompe cedo).
- **Busca Total**: exclusiva para acesso excepcional mediado pelo Comitê de Emergência; reconstrói a chave secreta mensal (SK) via quórum para decifrar todos os registros do mês, com escopo e trilha de auditoria restritos a esse período.
- **BOLO**: a polícia notifica as câmeras de uma lista de placas de interesse (*blocklist*); cada câmera verifica a placa em texto claro no momento da captura e, em caso de correspondência, alerta a polícia diretamente, sem custo de puzzle envolvido.

## Estrutura do repositório

```
crypto/            esquema de crumpling (AES-256-GCM) e puzzle de prova de trabalho
database/          conexão e migrações do banco (Postgres)
entities/          Record, Blocklist, BlocklistEntry, Alert
services/          Camera, Police, Server
main.py                          simulação do custo de busca_fechada/busca_aberta sobre um único registro
main_busca_aberta.py             simulação de busca_aberta sobre um volume de capturas (Server real)
main_bolo_normal.py              simulação do fluxo BOLO normal (blocklist local + broadcast + TTL)
main_combined_usage.py           uso combinado de busca_aberta e BOLO normal na mesma janela de captura
main_bolo_normal_complexity.py   análise de complexidade temporal e espacial do BOLO normal na câmera
teste_multiplos_registros.py     benchmark de custo (USD) de busca_fechada/busca_aberta em escala
simulation/                      simulação em grafo (motor de tráfego, investigação, custo) usada pela interface web
scripts/download_city.py         gera simulation/data/city.json a partir do OpenStreetMap (só necessário uma vez)
web/                             API Flask + interface (Cytoscape.js) da simulação
relatorio/                       fonte LaTeX e PDF do relatório (Capítulos 1–4, referências)
```

## Simulação web em grafo

Simulação da **Cidade Universitária (USP, Butantã)**: cada cruzamento é um vértice com uma câmera (`Camera` + `Server` reais, gravando no Postgres), e cada aresta tem a probabilidade de um carro escolhê-la a partir do vértice. Vários carros circulam; em certo momento um deles comete um crime, e a interface mostra a investigação percorrendo o grafo:

- **Busca fechada** (placa conhecida): resolve os puzzles do crime e, câmera a câmera, os dos vizinhos mais prováveis até achar o carro.
- **Busca aberta** (placa desconhecida): decifra todos os registros da janela do crime, filtra pelas letras da placa lembradas e segue cada suspeito.
- **BOLO normal**: as câmeras alertam em claro, sem puzzle, mas só para avistamentos posteriores ao aviso.

Clicar num vértice mostra o que o banco guarda (`c_prime`, `n`, `nonce`, `ciphertext`; a placa não é armazenada) e permite decifrar um registro. A busca roda com `puzzle_level` pequeno (padrão 1000) para ser ao vivo, e o custo é extrapolado para um N realista (tentativas, tempo e US$ AWS).

```bash
docker compose up db                       # Postgres
pip install -r requirements.txt
flask --app web.app run --port 5001        # http://127.0.0.1:5001 (no macOS a 5000 é do AirPlay)
python -m simulation.selfcheck             # verificação sem interface
```

O grafo já vem em `simulation/data/city.json`. Para regerá-lo: `pip install -r requirements-osm.txt && python scripts/download_city.py`.
Bancos já inicializados recebem a coluna `run_id` automaticamente (`Server.ensure_schema()`); a migration `002_add_run_id.sql` cobre bancos novos.

O código implementa e valida experimentalmente os conceitos de *crumpling*, puzzle de prova de trabalho e busca aberta/fechada descritos no relatório, além do fluxo BOLO (Seção 3.1) integrado à câmera.

## Referência principal

WRIGHT, C.; VARIA, M. **Crypto crumple zones: Enabling limited access without mass surveillance.** In: 2018 IEEE European Symposium on Security and Privacy (EuroS&P). 2018. p. 288–306.
