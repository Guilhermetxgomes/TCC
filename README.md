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
- **Governança**: toda busca exige um *token* do Autorizador Legal (juiz) assinado com ECDSA P-256 (Aberta: câmera e janela; Fechada: HMAC da placa, prazo e orçamento de registros; Total: mês, dias e câmeras). O Servidor verifica o *token* antes de liberar qualquer registro e grava cada liberação ou recusa num log encadeado por hash, cujo último hash o Conselho copia para fora do banco. O investigador declara ao Auditor cada registro que abriu, com a solução *k*, e o Auditor reconcilia tokens × log × declarações. A Busca Total só acontece depois de publicada num boletim público.
- **BOLO**: a polícia notifica as câmeras de uma lista de placas de interesse (*blocklist*); cada câmera verifica a placa em texto claro no momento da captura e, em caso de correspondência, alerta a polícia diretamente, sem custo de puzzle envolvido.

## Estrutura do repositório

```
crypto/            esquema de crumpling (AES-256-GCM com AD = câmera e instante) e puzzle de prova de trabalho;
                   assinatura ECDSA dos registros pela câmera (signing); tokens de autorização (tokens) e
                   cadeia de hash do log e do boletim (hashchain);
                   amassamento por bloco (block_crumpling) e custódia da chave de sessão para a Busca Total
                   (escrow: HPKE X25519 do pacote cryptography). Nenhum algoritmo criptográfico é
                   implementado aqui: o código só compõe primitivas de cryptography e PyCryptodome
database/          conexão e migrações do banco (Postgres)
entities/          Record, Blocklist, BlocklistEntry, Alert, BlockHeader, SessionKeyWrap, AuthToken
services/          Camera, Police, Server, EmergencyCommittee; governança: LegalAuthorizer (judge), CustodyGateway
                   (custody), AuditLog (audit_log), PublicBulletin (bulletin), Auditor (auditor), Governance
experiments/cap4.py              experimentos do capítulo de resultados (sem banco); saída em experiments/resultados/
tests/test_crypto.py             testes do núcleo criptográfico (sem banco, sem pytest)
tests/test_bolo.py               testes da blocklist do BOLO (difusão, validade e capacidade)
tests/test_governance.py         testes de tokens, portão do Servidor, log encadeado, boletim, Auditor e ataques
docs/                            avaliação do texto/código e roteiro do capítulo de resultados
main.py                          simulação do custo de busca_fechada/busca_aberta sobre um único registro
main_busca_aberta.py             simulação de busca_aberta sobre um volume de capturas (Server real)
main_bolo_normal.py              simulação do fluxo BOLO normal (blocklist local + broadcast + TTL)
main_combined_usage.py           uso combinado de busca_aberta e BOLO normal na mesma janela de captura
main_bolo_normal_complexity.py   análise de complexidade temporal e espacial do BOLO normal na câmera
teste_multiplos_registros.py     benchmark de custo (USD) de busca_fechada/busca_aberta em escala
simulation/                      simulação em grafo (motor de tráfego, investigação, custo) usada pela interface web;
                                 attacks.py (sistema convencional x Nêmesis), tampering.py (adulterações),
                                 governance_attacks.py (ataques a tokens, log e boletim),
                                 tolls.py e real_search.py (volumes reais das praças de pedágio, ARTESP)
simulation/data/pedagio_2026_horario.csv.gz  veículos por hora de cada praça e sentido, jan.–set. 2026 (agregado)
scripts/download_city.py         gera simulation/data/city.json a partir do OpenStreetMap (só necessário uma vez)
web/                             API Flask + interface (Cytoscape.js) da simulação
relatorio/                       fonte LaTeX e PDF do relatório (Capítulos 1–4, referências)
```

## Simulação web

A interface tem quatro telas:

1. **Busca na Cidade Universitária** (descrita abaixo).
2. **Ataques: convencional × Nêmesis**: as mesmas capturas carregadas num sistema convencional (placa, câmera e instante em claro, indexados por placa) e no Nêmesis, e quatro ataques do operador do Servidor contra os dois: ler toda a base, seguir um veículo qualquer pela placa, mudar câmera e instante de um registro (álibi falso) e trocar a placa (sumir com o carro do crime). Nos ataques de leitura, os dois sistemas recebem o mesmo tempo; no Nêmesis os puzzles são resolvidos de verdade e o custo completo é extrapolado. As adulterações são detectadas pelo dado associado e pela assinatura da câmera.
3. **Dados reais de tráfego**: volumes horários das 365 praças e sentidos das rodovias estaduais concedidas de SP (ARTESP, 2026). Gráficos por hora, por dia e por praça, e uma busca dimensionada pelo volume real: um registro cifrado e assinado para cada veículo que passou na janela, com os puzzles resolvidos e o custo extrapolado.
4. **Auditoria**: tokens emitidos pelo juiz, log de decodificação do Servidor (com o hash de cada entrada e os checkpoints do Conselho), boletim público da Busca Total, reconciliação do Auditor (autorizado × liberado × declarado, com as discrepâncias) e volume por operador e mês. O painel de ataques à governança fica oculto: esses ataques estão fora do escopo da implementação.

### Tela 1: busca em grafo

Simulação da **Cidade Universitária (USP, Butantã)**: cada cruzamento é um vértice com uma câmera (`Camera` + `Server` reais, gravando no Postgres), e cada aresta tem a probabilidade de um carro escolhê-la a partir do vértice. Vários carros circulam; em certo momento um deles comete um crime, e a interface mostra a investigação percorrendo o grafo:

- **Busca fechada** (placa conhecida): resolve os puzzles do crime e, câmera a câmera, os dos vizinhos mais prováveis até achar o carro.
- **Busca aberta** (placa desconhecida): decifra todos os registros da janela do crime, filtra pelas letras da placa lembradas e segue cada suspeito.
- **BOLO normal**: as câmeras alertam em claro, sem puzzle, mas só para avistamentos posteriores ao aviso.
- **Busca total**: um quórum do Comitê de Emergência (4 de 8) reúne seus fragmentos de Shamir (PyCryptodome), recupera a chave X25519 do mês e abre as chaves de sessão que as câmeras custodiaram com HPKE; todos os registros do dia abrem sem puzzle. Abaixo do quórum a busca é recusada.

A opção "um puzzle por bloco de 10 min" troca o puzzle por registro por um único puzzle de tamanho N por câmera a cada 10 minutos simulados (amassamento por bloco): quem o resolve abre todos os registros do bloco.

Clicar num vértice mostra o que o banco guarda (`c_prime`, `n`, `nonce`, `ciphertext`; a placa não é armazenada) e permite decifrar um registro. A busca roda com `puzzle_level` pequeno (padrão 1000) para ser ao vivo, e o custo é extrapolado para um N realista (tentativas, tempo e US$ AWS).

```bash
docker compose up db                       # Postgres
pip install -r requirements.txt
flask --app web.app run --port 5001        # http://127.0.0.1:5001 (no macOS a 5000 é do AirPlay)
python -m simulation.selfcheck             # verificação sem interface
python -m simulation.selfcheck --memory    # idem, sem Postgres (servidor em memória)
python -m tests.test_crypto                # núcleo criptográfico
python -m tests.test_bolo                  # blocklist do BOLO
python -m tests.test_governance            # tokens, log, boletim, Auditor e ataques
python -m experiments.cap4 all             # experimentos do capítulo de resultados
python -m simulation.tolls build ~/Downloads/volume_horario_2026   # regera o agregado de pedágio (precisa de pandas)
```

O grafo já vem em `simulation/data/city.json`. Para regerá-lo: `pip install -r requirements-osm.txt && python scripts/download_city.py`.
Bancos já inicializados recebem a coluna `run_id` e as tabelas de blocos e de custódia automaticamente (`Server.ensure_schema()`); as migrations `002_add_run_id.sql`, `003_blocks_and_escrow.sql`, `004_record_signature.sql`, `005_audit_log.sql` e `006_hpke_session_wraps.sql` cobrem bancos novos.

O código implementa e valida experimentalmente os conceitos de *crumpling*, puzzle de prova de trabalho e busca aberta/fechada descritos no relatório, além do fluxo BOLO (Seção 3.1) integrado à câmera.

## Referência principal

WRIGHT, C.; VARIA, M. **Crypto crumple zones: Enabling limited access without mass surveillance.** In: 2018 IEEE European Symposium on Security and Privacy (EuroS&P). 2018. p. 288–306.
