

# 🛡️ XhosaCrypt Protocol (5-Layer StegoCrypt Engine)

> **Proof of Concept (PoC)** de um protocolo híbrido experimental que combina **Criptografia Modular Exponencial**, **Esteganografia Linguística (Xhosa)**, **Evasão por Homóglifos Cirílicos (Unicode)** e **Integridade via HMAC-SHA256**.

---

## 📌 Visão Geral

O **XhosaCrypt Protocol** foi projetado para responder a um desafio de segurança de dados em redes monitoradas: *como transmitir uma mensagem criptografada garantindo não apenas a confidencialidade do conteúdo, mas também a denegabilidade da própria existência da criptografia (ofuscamento)*.

A arquitetura do sistema divide o processo de proteção em **5 Camadas Ativas (CP1 a CP5)**, transformando texto plano em uma payload visualmente inofensiva e matematicamente resistente a ataques de frequência e análise estática.

---

## 🔬 Arquitetura das Camadas

1. **CP1 — Rotação Modular Exponencial de Primos (Confidencialidade):**  
   Em vez de rotações lineares simples, a Camada 1 introduz não-linearidade pura na fase de substituição de bytes. A chave de rotação deriva de um par de números primos combinados em uma potência encadeada com **Exponenciação Modular** e incorpora um **Salt aleatório de 64-bit** para garantir **Segurança Semântica (IND-CPA)**.

2. **CP2 — Esteganografia Linguística em Xhosa (Disfarce de Canal):**  
   Os bytes criptografados em Hexadecimal são convertidos para uma sequência de palavras reais do idioma **Xhosa**. O analisador de tráfego enxerga um texto gramaticalmente estruturado em vez de ruído binário.

3. **CP3 — Injeção de Homóglifos Cirílicos (Evasão Visual Unicode):**  
   Substituição sutil de caracteres do alfabeto latino no texto em Xhosa por seus **homóglifos idênticos no alfabeto cirílico** (ex: `'a'` latino por `'а'` cirílico). Dificulta a extração por robôs e análise estática, mantendo a leitura normal para humanos.

4. **CP4 — Carimbo de Autenticidade HMAC-SHA256 (Integridade):**  
   Gera uma assinatura de integridade combinando o texto e a chave via `HMAC-SHA256`. Qualquer alteração no meio do caminho invalida o pacote na hora.

5. **CP5 — Envelope de Transporte (Empacotamento):**  
   Empacota a payload, o Salt e o HMAC em JSON e codifica em **Base64 Safe** para envio sem corromper caracteres UTF-8.

---

## 🧪 Resultados dos Testes Práticos (Pydroid 3)

O protocolo foi submetido a baterias de testes em ambiente Android/Python 3 com os seguintes resultados:

* **[INPUT] Texto Original:** `'Testando Pipeline Completo CP1-CP5 no Pydroid 3!'`
* **[CP1] Primos:** `p1=48757`, `p2=37483` | **Salt:** `9230ea9858ad7cfc`
* **[CP2] Xhosa:** `abantu izikhali izikhali...`
* **[CP3] Homóglifo:** `'аbаntu izikhаli izikhаli...'`
* **[CP5] Pacote B64:** `eyJwYXlsb2FkIjogItCwYtCwbnR1...`
* **[OUTPUT] Reversão:** `'Testando Pipeline Completo CP1-CP5 no Pydroid 3!'`

**Validações do Pipeline:**
* ✓ **Reversibilidade:** Texto original == Texto revertido (Precisão 100%)
* ✓ **Integridade:** Validada via HMAC
* ✓ **Resistência a Adulteração:** Sucesso (Ataque detectado e bloqueado)
* ✓ **Autenticação:** Sucesso (Rejeição de senha incorreta)

---

## 🛠️ Como Executar

Não requer dependências externas (utiliza exclusivamente módulos nativos da biblioteca padrão do Python).

```bash
# Clone o repositório
git clone [https://github.com/SEU-USUARIO/XhosaCrypt-Protocol.git](https://github.com/SEU-USUARIO/XhosaCrypt-Protocol.git)

# Entre no diretório
cd XhosaCrypt-Protocol

# Execute o script principal
python main.py
’’’

# Feito com IA
# Ideia: Pinguim3364
# Prática do código/código: IA(Claude Sonnet 5/Haiku 4.5)
