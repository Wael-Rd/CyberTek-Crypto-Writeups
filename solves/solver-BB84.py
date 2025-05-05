import yaml
import base64
import math

with open("challenge.yml", "r") as f:
    data = yaml.safe_load(f)
qubits = data['qubits']
bob_bases = data['bob_bases']
ciphertext_b64 = data['ciphertext']
ciphertext_bytes = base64.b64decode(ciphertext_b64)
shared_key_bits = []
for i, base in enumerate(bob_bases):
    qubit = qubits[i]
    real = qubit['real']
    imag = qubit['imag']
    if base == '+':
        if imag == 1.0:
            alice_bit = 0
        elif real == 1.0:
            alice_bit = 1
        else:
            continue  
    elif base == 'x':
        if math.isclose(real, 1 / math.sqrt(2)) and math.isclose(imag, 1 / math.sqrt(2)):
            alice_bit = 0
        elif math.isclose(real, 1 / math.sqrt(2)) and math.isclose(imag, -1 / math.sqrt(2)):
            alice_bit = 1
        else:
            continue  
    shared_key_bits.append(alice_bit)
ciphertext_bits = []
for byte in ciphertext_bytes:
    for i in range(8):
        ciphertext_bits.append((byte >> (7 - i)) & 1)

if len(shared_key_bits) < len(ciphertext_bits):
    shared_key_bits = (shared_key_bits * (len(ciphertext_bits) // len(shared_key_bits) + 1))[:len(ciphertext_bits)]
flag_bits = [ciphertext_bits[i] ^ shared_key_bits[i] for i in range(len(ciphertext_bits))]
flag_bytes = []
for i in range(0, len(flag_bits), 8):
    byte = 0
    for b in flag_bits[i:i+8]:
        byte = (byte << 1) | b
    flag_bytes.append(byte)
flag = bytes(flag_bytes).decode()
print(f"Flag: {flag}")


#Flag: Securinets{QKD_zzzzzzzzzzzzzzzzzzMrx0rd}