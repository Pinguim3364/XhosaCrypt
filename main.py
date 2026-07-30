"""
Pipeline Completo: CP1-CP5 (Criptografia Modular Avançada)
===========================================================

CP1: Deslocamento Modular (Primos Dinâmicos + Salt)
CP2: Esteganografia Linguística (Xhosa)
CP3: Esteganografia Visual (Homóglifos Cirílicos)
CP4: Integridade (HMAC-SHA256)
CP5: Empacotamento Final (JSON + Base64)

Fluxo: Texto -> CP1 (bytes) -> Hex -> CP2-CP5 (transmissível)
Reverso: Pacote -> CP5-CP2 (hex) -> CP1 (bytes) -> Texto Original
"""

import random
import secrets
import hmac
import hashlib
import json
import base64

# ============================================================================
# CAMADA 1: DESLOCAMENTO MODULAR COM GERAÇÃO DINÂMICA DE PRIMOS
# ============================================================================

def eh_primo(n: int, rodadas: int = 20) -> bool:
    """Teste de primalidade de Miller-Rabin (probabilístico)."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n == p:
            return True
        if n % p == 0:
            return False

    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rodadas):
        base = random.randrange(2, n - 1)
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gerar_primo(bits: int) -> int:
    """Gera primo aleatório de 'bits' bits -- sem tabelas."""
    while True:
        candidato = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if eh_primo(candidato):
            return candidato


BITS_PRIMO = 16
TAM_SALT = 8


def gerar_chave_camada1():
    """Gera p1, p2 (dinâmicos) e Salt para uma execução."""
    p1 = gerar_primo(BITS_PRIMO)
    p2 = gerar_primo(BITS_PRIMO)
    salt = secrets.token_bytes(TAM_SALT)
    return p1, p2, salt


def _deslocamento_base(p1: int, p2: int) -> int:
    """Fórmula exata: (p1 * pow(p2, p1 * p2, 256)) % 256."""
    return (p1 * pow(p2, p1 * p2, 256)) % 256


def cp1_processar(texto: str, p1: int, p2: int, salt: bytes) -> bytes:
    """Texto (UTF-8) -> bytes deslocados."""
    base = _deslocamento_base(p1, p2)
    dados = texto.encode("utf-8")
    saida = bytearray(len(dados))
    for i, byte_original in enumerate(dados):
        salto = (base + salt[i % len(salt)] + i) % 256
        saida[i] = (byte_original + salto) % 256
    return bytes(saida)


def cp1_reverter(dados: bytes, p1: int, p2: int, salt: bytes) -> str:
    """Inverso exato: bytes -> Texto (UTF-8)."""
    base = _deslocamento_base(p1, p2)
    saida = bytearray(len(dados))
    for i, byte_deslocado in enumerate(dados):
        salto = (base + salt[i % len(salt)] + i) % 256
        saida[i] = (byte_deslocado - salto) % 256
    return bytes(saida).decode("utf-8")


# ============================================================================
# CAMADA 2: ESTEGANOGRAFIA LINGUÍSTICA (XHOSA)
# ============================================================================

HEX_XHOSA_MAP = {
    '0': 'umuntu', '1': 'ingxola', '2': 'isithako',
    '3': 'imvelo', '4': 'indlela', '5': 'izikhali',
    '6': 'umsebenzi', '7': 'iqabala', '8': 'idlozi',
    '9': 'inkomo', 'a': 'abantu', 'b': 'ibhokisi',
    'c': 'icwecwe', 'd': 'idatha', 'e': 'iengine',
    'f': 'ifayela'
}

XHOSA_HEX_MAP = {v: k for k, v in HEX_XHOSA_MAP.items()}


def cp2_encode(hex_string: str) -> str:
    """Hex -> Xhosa (aparenta frase contínua)."""
    palavras = [HEX_XHOSA_MAP[ch] for ch in hex_string.lower()]
    return ' '.join(palavras)


def cp2_decode(xhosa_string: str) -> str:
    """Xhosa -> Hex."""
    palavras = xhosa_string.split()
    return ''.join(XHOSA_HEX_MAP[p] for p in palavras)


# ============================================================================
# CAMADA 3: ESTEGANOGRAFIA VISUAL (HOMÓGLIFOS CIRÍLICOS)
# ============================================================================

LATIN_CYRILLIC = {
    'a': '\u0430',  # а
    'e': '\u0435',  # е
    'o': '\u043e',  # о
    'p': '\u0440',  # р
    'c': '\u0441',  # с
    'x': '\u0445',  # х
    'y': '\u0443',  # у
}

CYRILLIC_LATIN = {v: k for k, v in LATIN_CYRILLIC.items()}


def cp3_encode(xhosa_string: str) -> str:
    """Injetar homóglifos cirílicos (visualmente idêntica)."""
    resultado = []
    for ch in xhosa_string:
        if ch.lower() in LATIN_CYRILLIC:
            resultado.append(LATIN_CYRILLIC[ch.lower()])
        else:
            resultado.append(ch)
    return ''.join(resultado)


def cp3_decode(homoglifo_string: str) -> str:
    """Remover homóglifos cirílicos."""
    resultado = []
    for ch in homoglifo_string:
        if ch in CYRILLIC_LATIN:
            resultado.append(CYRILLIC_LATIN[ch])
        else:
            resultado.append(ch)
    return ''.join(resultado)


# ============================================================================
# CAMADA 4: INTEGRIDADE (HMAC-SHA256)
# ============================================================================

def cp4_compute_hmac(payload: str, chave: bytes) -> str:
    """Calcula HMAC-SHA256 do payload."""
    payload_bytes = payload.encode('utf-8')
    assinatura = hmac.new(chave, payload_bytes, hashlib.sha256).digest()
    return assinatura.hex()


def cp4_verify_hmac(payload: str, assinatura_hex: str, chave: bytes) -> bool:
    """Valida HMAC."""
    esperado = cp4_compute_hmac(payload, chave)
    return hmac.compare_digest(esperado, assinatura_hex)


# ============================================================================
# CAMADA 5: EMPACOTAMENTO FINAL (JSON + BASE64)
# ============================================================================

def cp5_pack(xhosa_homoglifo: str, hmac_hex: str, salt_hex: str) -> str:
    """Empacotar (JSON + Base64) para transmissão."""
    pacote = {
        'payload': xhosa_homoglifo,
        'hmac': hmac_hex,
        'salt': salt_hex
    }
    json_str = json.dumps(pacote, ensure_ascii=False)
    json_bytes = json_str.encode('utf-8')
    b64 = base64.b64encode(json_bytes).decode('ascii')
    return b64


def cp5_unpack(payload_b64: str) -> dict:
    """Desempacotar (Base64 + JSON)."""
    json_bytes = base64.b64decode(payload_b64.encode('ascii'))
    json_str = json_bytes.decode('utf-8')
    return json.loads(json_str)


# ============================================================================
# PIPELINE UNIFICADO (END-TO-END)
# ============================================================================

def criptografar_completo(texto_original: str, senha: str = None) -> dict:
    """
    Texto -> CP1-CP5 (transmissível).
    
    Retorna:
        {
            'pacote': payload_b64,
            'p1': int, 'p2': int,
            'salt': salt_hex,
            'chave': chave_derivada.hex()
        }
    """
    # Gerar chave CP1
    p1, p2, salt = gerar_chave_camada1()
    salt_hex = salt.hex()
    
    # Derivar chave para HMAC (usar Salt + senha opcional)
    chave_base = (salt + (senha.encode() if senha else b"")).ljust(32, b'\x00')[:32]
    
    # CP1: Texto -> Bytes
    cp1_bytes = cp1_processar(texto_original, p1, p2, salt)
    hex_string = cp1_bytes.hex()
    
    # CP2: Hex -> Xhosa
    xhosa = cp2_encode(hex_string)
    
    # CP3: Xhosa + Cirílicos
    homoglifo = cp3_encode(xhosa)
    
    # CP4: HMAC
    hmac_hex = cp4_compute_hmac(homoglifo, chave_base)
    
    # CP5: Empacotar
    pacote_b64 = cp5_pack(homoglifo, hmac_hex, salt_hex)
    
    return {
        'pacote': pacote_b64,
        'p1': p1,
        'p2': p2,
        'salt': salt_hex,
        'chave': chave_base.hex()
    }


def descriptografar_completo(resultado_criptografia: dict, senha: str = None) -> str:
    """
    CP5-CP1 -> Texto Original.
    
    Args:
        resultado_criptografia: dict retornado de criptografar_completo()
        senha: mesma senha usada na encriptação
    
    Retorna:
        texto_original (ou lança ValueError se integridade falhar)
    """
    pacote_b64 = resultado_criptografia['pacote']
    p1 = resultado_criptografia['p1']
    p2 = resultado_criptografia['p2']
    salt_hex = resultado_criptografia['salt']
    
    salt = bytes.fromhex(salt_hex)
    chave_base = (salt + (senha.encode() if senha else b"")).ljust(32, b'\x00')[:32]
    
    # CP5: Desempacotar
    pacote = cp5_unpack(pacote_b64)
    homoglifo = pacote['payload']
    hmac_recebido = pacote['hmac']
    
    # CP4: Validar integridade
    if not cp4_verify_hmac(homoglifo, hmac_recebido, chave_base):
        raise ValueError("Integridade comprometida: HMAC inválido")
    
    # CP3: Remover cirílicos
    xhosa = cp3_decode(homoglifo)
    
    # CP2: Xhosa -> Hex
    hex_string = cp2_decode(xhosa)
    
    # CP1: Hex -> Bytes -> Texto
    cp1_bytes = bytes.fromhex(hex_string)
    texto = cp1_reverter(cp1_bytes, p1, p2, salt)
    
    return texto


# ============================================================================
# TESTES END-TO-END
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("TESTE COMPLETO: CP1-CP5 (ENCRIPTAÇÃO E DESCRIPTAÇÃO)")
    print("=" * 80)
    
    texto_original = "Testando Pipeline Completo CP1-CP5 no Pydroid 3!"
    senha = "minha_senha_super_secreta"
    
    print(f"\n[INPUT] Texto Original: {texto_original!r}")
    print(f"[INPUT] Senha: {senha!r}")
    
    # --- ENCRIPTAÇÃO ---
    print("\n" + "-" * 80)
    print("ENCRIPTAÇÃO (CP1 -> CP2 -> CP3 -> CP4 -> CP5)")
    print("-" * 80)
    
    resultado = criptografar_completo(texto_original, senha)
    
    print(f"\n[CP1] Primos: p1={resultado['p1']}, p2={resultado['p2']}")
    print(f"[CP1] Salt: {resultado['salt']}")
    
    # Mostrar intermediários
    p1, p2, salt = resultado['p1'], resultado['p2'], bytes.fromhex(resultado['salt'])
    cp1_bytes = cp1_processar(texto_original, p1, p2, salt)
    hex_str = cp1_bytes.hex()
    print(f"[CP1] Hex (primeiros 40 chars): {hex_str[:40]}...")
    
    xhosa = cp2_encode(hex_str)
    print(f"[CP2] Xhosa (primeiros 80 chars): {xhosa[:80]}...")
    
    homoglifo = cp3_encode(xhosa)
    print(f"[CP3] Homóglilo (repr, primeiros 80): {repr(homoglifo[:80])}...")
    
    print(f"[CP4] HMAC: {resultado['chave'][:32]}...")
    print(f"[CP5] Pacote B64 (primeiros 80): {resultado['pacote'][:80]}...")
    
    # --- DESCRIPTAÇÃO ---
    print("\n" + "-" * 80)
    print("DESCRIPTAÇÃO (CP5 -> CP4 -> CP3 -> CP2 -> CP1)")
    print("-" * 80)
    
    try:
        texto_revertido = descriptografar_completo(resultado, senha)
        print(f"\n[OUTPUT] Texto Revertido: {texto_revertido!r}")
        
        if texto_revertido == texto_original:
            print("\n✓ SUCESSO: Texto original == Texto revertido")
            print("✓ Integridade validada (HMAC OK)")
        else:
            print(f"\n✗ FALHA: Textos diferem!")
    except ValueError as e:
        print(f"\n✗ ERRO: {e}")
    
    # --- TESTE DE ADULTERAÇÃO ---
    print("\n" + "-" * 80)
    print("TESTE DE ADULTERAÇÃO (HMAC PROTECTION)")
    print("-" * 80)
    
    pacote_adulterado = resultado['pacote'][:-10] + "XXXXXX"
    resultado_adulterado = resultado.copy()
    resultado_adulterado['pacote'] = pacote_adulterado
    
    print(f"\nPacote original (últimos 20): ...{resultado['pacote'][-20:]}")
    print(f"Pacote adulterado (últimos 20): ...{pacote_adulterado[-20:]}")
    
    try:
        texto_falso = descriptografar_completo(resultado_adulterado, senha)
        print(f"\n✗ FALHA: Adulteração não detectada!")
        print(f"  Texto (falso): {texto_falso!r}")
    except (ValueError, Exception) as e:
        print(f"\n✓ SUCESSO: Adulteração detectada!")
        print(f"  Erro: {type(e).__name__}")
    
    # --- TESTE COM SENHA ERRADA ---
    print("\n" + "-" * 80)
    print("TESTE COM SENHA ERRADA")
    print("-" * 80)
    
    try:
        texto_falso = descriptografar_completo(resultado, "senha_errada")
        print(f"\n✗ FALHA: Senha errada não detectada!")
    except ValueError as e:
        print(f"\n✓ SUCESSO: Senha errada detectada!")
        print(f"  Erro: {type(e).__name__}")
    
    print("\n" + "=" * 80)
    print("FIM DOS TESTES")
    print("=" * 80)
