#!/usr/bin/env python3
"""
Generate synthetic memory dumps mimicking MemLabs scenarios for bxmap demos.
Run: python3 generate_demo_dumps.py
Outputs: demo/dumps/lab1.dmp, lab2.dmp, lab4.dmp, lab6.dmp, minidump.dmp
"""

import os
import struct
import random

DEMO_DIR = "demo/dumps"
os.makedirs(DEMO_DIR, exist_ok=True)

def write_utf16le(data, s):
    """Write string as UTF-16LE with null terminator."""
    for c in s:
        data.extend(struct.pack('<H', ord(c)))
    data.extend(b'\x00\x00')

def write_utf16be(data, s):
    """Write string as UTF-16BE with null terminator."""
    for c in s:
        data.extend(struct.pack('>H', ord(c)))
    data.extend(b'\x00\x00')

def write_ascii(data, s):
    """Write ASCII string with null terminator."""
    data.extend(s.encode('ascii'))
    data.extend(b'\x00')

def pad_to(data, size):
    """Pad data to size with random bytes."""
    while len(data) < size:
        data.extend(os.urandom(min(1024, size - len(data))))

def make_lab1():
    """Lab 1: Simple ASCII + UTF-16LE strings, process info."""
    data = bytearray()
    
    # Header-like structure
    data.extend(b'MEMORY_DUMP_LAB1\x00')
    data.extend(os.urandom(512))
    
    # ASCII strings (process names, paths)
    ascii_strings = [
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Users\\victim\\Documents\\secret.txt",
        "explorer.exe",
        "svchost.exe",
        "cmd.exe /c whoami",
        "powershell.exe -enc SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHog...",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "192.168.1.100:4444",
        "password123",
        "admin@company.com",
    ]
    for s in ascii_strings:
        write_ascii(data, s)
        data.extend(os.urandom(random.randint(16, 256)))
    
    # UTF-16LE strings (registry, environment)
    utf16_strings = [
        "RAR password=SuperSecretRAR123!",
        "DB_PASSWORD=prod_db_pass_2024",
        "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
        "C:\\Users\\victim\\AppData\\Local\\Temp\\malware.exe",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]
    for s in utf16_strings:
        write_utf16le(data, s)
        data.extend(os.urandom(random.randint(16, 256)))
    
    # Some UTF-16BE mirrors (will be suppressed)
    for s in ["explorer.exe", "cmd.exe"]:
        write_utf16be(data, s)
        data.extend(os.urandom(random.randint(16, 64)))
    
    pad_to(data, 50 * 1024 * 1024)  # 50 MB
    return data

def make_lab2():
    """Lab 2: Network indicators, crypto wallets, URLs."""
    data = bytearray()
    
    data.extend(b'MEMORY_DUMP_LAB2\x00')
    data.extend(os.urandom(512))
    
    # Network IOCs
    network_iocs = [
        "http://malicious.c2.server/payload.exe",
        "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getUpdates",
        "ws://192.168.100.50:8080/ws",
        "ftp://backup:backup123@backup.server.com/dump.sql",
        "10.0.0.1:8080",
        "203.0.113.45:443",
    ]
    for s in network_iocs:
        write_ascii(data, s)
        data.extend(os.urandom(random.randint(32, 512)))
    
    # Crypto wallets
    wallets = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        "0x742d35Cc6634C0532925a3b8D4C0532925a3b8D4",
        "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
    ]
    for s in wallets:
        write_ascii(data, s)
        data.extend(os.urandom(random.randint(32, 512)))
    
    # Base64 blobs (some high entropy, some not)
    b64_blobs = [
        "SGVsbG8gV29ybGQh",  # low entropy "Hello World!"
        "U2VjcmV0UGFzc3dvcmQxMjM=",  # "SecretPassword123"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  # low entropy
        "J3GsK2vZ8XmPq9Rh5Yn1T3sH7vB8nM2kL5jH6gF1dS4a=",  # high entropy-ish
    ]
    for s in b64_blobs:
        write_ascii(data, s)
        data.extend(os.urandom(random.randint(32, 512)))
    
    # UTF-16LE env block
    env_vars = [
        "PATH=C:\\Windows\\System32;C:\\Windows",
        "TEMP=C:\\Users\\victim\\AppData\\Local\\Temp",
        "RAR_PASSWORD=ExtractMeIfYouCan2024!",
        "ENCRYPTION_KEY=32bytekeyforAES256encryption!!",
        "COOKIE=session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    ]
    for s in env_vars:
        write_utf16le(data, s)
        data.extend(os.urandom(random.randint(16, 128)))
    
    pad_to(data, 80 * 1024 * 1024)  # 80 MB
    return data

def make_lab4():
    """Lab 4: 1GB-like dump with user profile artifacts, tools, files."""
    data = bytearray()
    
    data.extend(b'MEMORY_DUMP_LAB4_1GB\x00')
    # Simulate larger dump with more repetitive structure
    # We'll make it smaller (100MB) for demo but structure it like 1GB
    
    # User profile paths (the key artifacts)
    user_files = [
        r"C:\Users\eminem\Desktop\secrets.txt",
        r"C:\Users\eminem\Desktop\FLAG NOT HERE.BMP",
        r"C:\Users\eminem\Desktop\Screenshot1.png",
        r"C:\Users\eminem\Desktop\DumpIt.zip",
        r"C:\Users\eminem\Documents\work.docx",
        r"C:\Users\eminem\Downloads\malware_sample.exe",
        r"C:\Users\eminem\Pictures\photo.jpg",
        r"C:\Users\eminem\Music\song.mp3",
        r"C:\Users\eminem\Videos\video.mp4",
        r"C:\Users\eminem\AppData\Roaming\Microsoft\Windows\Recent\secrets.lnk",
        r"C:\Users\eminem\AppData\Local\Temp\tmp123.tmp",
    ]
    
    # Write each path multiple times (simulating multiple string occurrences)
    for path in user_files:
        for _ in range(random.randint(3, 8)):
            write_ascii(data, path)
            data.extend(os.urandom(random.randint(8, 64)))
            write_utf16le(data, path)
            data.extend(os.urandom(random.randint(8, 64)))
    
    # Tool traces (DumpIt, WinPmem, etc.)
    tools = [
        "DumpIt.exe",
        "WinPmem.exe",
        "FTK Imager.exe",
        "DESKTOP-VICTIM-20240115-143022.raw",
        "physicalmemory.mem",
        "memory.dmp",
    ]
    for tool in tools:
        for _ in range(random.randint(2, 5)):
            write_ascii(data, tool)
            data.extend(os.urandom(random.randint(16, 128)))
            write_utf16le(data, tool)
            data.extend(os.urandom(random.randint(16, 128)))
    
    # Registry keys
    reg_keys = [
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\malware",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\malware",
        r"HKEY_CLASSES_ROOT\exefile\shell\open\command",
    ]
    for key in reg_keys:
        write_ascii(data, key)
        data.extend(os.urandom(random.randint(32, 256)))
        write_utf16le(data, key)
        data.extend(os.urandom(random.randint(32, 256)))
    
    # Email addresses
    emails = [
        "victim@company.com",
        "admin@company.com",
        "attacker@evil.com",
        "security@company.com",
    ]
    for email in emails:
        write_ascii(data, email)
        data.extend(os.urandom(random.randint(32, 256)))
    
    # URLs
    urls = [
        "http://c2.malware.com/beacon",
        "https://pastebin.com/raw/stolen_data",
        "http://192.168.1.100/exfil",
    ]
    for url in urls:
        write_ascii(data, url)
        data.extend(os.urandom(random.randint(32, 256)))
    
    pad_to(data, 100 * 1024 * 1024)  # 100 MB (demo size)
    return data

def make_lab6():
    """Lab 6: 1.6GB-like with RAR password in UTF-16 env block, 6 RAR signatures."""
    data = bytearray()
    
    data.extend(b'MEMORY_DUMP_LAB6_16GB\x00')
    
    # The key finding: RAR password in UTF-16 env block
    write_utf16le(data, "RAR password=MySecretRARPassword2024!")
    data.extend(os.urandom(256))
    
    # Also in ASCII (less likely but possible)
    write_ascii(data, "RAR password=MySecretRARPassword2024!")
    data.extend(os.urandom(256))
    
    # 6 RAR file signatures (RAR5: Rar!\x1a\x07\x01\x00)
    for i in range(6):
        offset = len(data)
        # RAR5 signature
        data.extend(b'Rar!\x1a\x07\x01\x00')
        # Fake RAR header data
        data.extend(struct.pack('<Q', 0x1234567890ABCDEF + i))  # CRC
        data.extend(struct.pack('<H', 0x7854))  # type
        data.extend(struct.pack('<H', 0x0100))  # flags
        data.extend(struct.pack('<I', 1024 + i * 512))  # size
        data.extend(os.urandom(random.randint(200, 1000)))  # file content
        data.extend(os.urandom(random.randint(1024, 4096)))  # padding between
    
    # Other env vars (UTF-16)
    env_vars = [
        "TEMP=C:\\Windows\\Temp",
        "USERPROFILE=C:\\Users\\admin",
        "ENCRYPTION_KEY=AES256KeyForFileEncryption123456789012",
        "BITCOIN_WALLET=bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    ]
    for var in env_vars:
        write_utf16le(data, var)
        data.extend(os.urandom(random.randint(64, 512)))
    
    # Tool traces
    tools = ["WinPmem", "DumpIt", "FTK Imager", "Belkasoft", "AVML"]
    for tool in tools:
        write_ascii(data, tool)
        data.extend(os.urandom(random.randint(32, 256)))
    
    pad_to(data, 120 * 1024 * 1024)  # 120 MB (demo size)
    return data

def make_minidump():
    """Minidump with VA mapping for --map-va, --rwx-only, --heap-only demo."""
    data = bytearray()
    
    # Minimal minidump header
    data.extend(b'MDMP')  # Signature
    data.extend(struct.pack('<I', 0xA793))  # Version
    data.extend(struct.pack('<I', 3))  # Stream count
    data.extend(b'\x00' * 100)  # Stream directory (simplified)
    
    # Module list stream (simplified)
    modules = [
        ("ntoskrnl.exe", 0xFFFFF80000000000, 0x1000000),
        ("hal.dll", 0xFFFFF80001000000, 0x200000),
        ("C:\\Windows\\System32\\kernel32.dll", 0x7FFD00000000, 0x180000),
        ("C:\\Windows\\System32\\ntdll.dll", 0x7FFD00180000, 0x1C0000),
        ("C:\\Program Files\\Malware\\evil.exe", 0x7FF600000000, 0x50000),
        ("C:\\Users\\victim\\AppData\\Local\\Temp\\payload.dll", 0x7FF700000000, 0x30000),
    ]
    
    for name, base, size in modules:
        write_utf16le(data, name)
        data.extend(struct.pack('<Q', base))
        data.extend(struct.pack('<Q', size))
        data.extend(struct.pack('<I', 0x1000000))  # timestamp
        data.extend(os.urandom(64))
    
    # Memory regions (some RWX, some heap)
    regions = [
        (0x7FF600000000, 0x50000, 0x60),  # evil.exe - RWX
        (0x7FF700000000, 0x30000, 0x60),  # payload.dll - RWX
        (0x0000020000000000, 0x100000, 0x40),  # heap - RW
        (0x0000010000000000, 0x80000, 0x40),  # heap - RW
        (0xFFFFF80000000000, 0x1000000, 0x20),  # kernel - R
    ]
    
    for base, size, protect in regions:
        data.extend(struct.pack('<Q', base))
        data.extend(struct.pack('<Q', size))
        data.extend(struct.pack('<I', protect))
        data.extend(os.urandom(32))
    
    # Strings in various regions
    strings = [
        (0x7FF600001000, "malware_command_and_control"),
        (0x7FF600002000, "http://c2.evil.com/beacon"),
        (0x7FF700001000, "injected_payload"),
        (0x00000200001000, "heap_allocation_123"),
        (0x00000100002000, "sensitive_data_on_heap"),
    ]
    
    for offset, s in strings:
        data.extend(struct.pack('<Q', offset))
        write_ascii(data, s)
        write_utf16le(data, s)
        data.extend(os.urandom(128))
    
    pad_to(data, 30 * 1024 * 1024)  # 30 MB
    return data

def main():
    print("Generating demo dumps...")
    
    dumps = [
        ("lab1.dmp", make_lab1, "Lab 1 - Basic strings"),
        ("lab2.dmp", make_lab2, "Lab 2 - Network/crypto IOCs"),
        ("lab4.dmp", make_lab4, "Lab 4 - User profile artifacts"),
        ("lab6.dmp", make_lab6, "Lab 6 - RAR password + signatures"),
        ("minidump.dmp", make_minidump, "Minidump - VA mapping demo"),
    ]
    
    for filename, generator, desc in dumps:
        path = os.path.join(DEMO_DIR, filename)
        print(f"  Generating {filename} ({desc})...")
        data = generator()
        with open(path, 'wb') as f:
            f.write(data)
        size_mb = len(data) / (1024 * 1024)
        print(f"    -> {size_mb:.1f} MB")
    
    print("\nDone! Demo dumps in demo/dumps/")
    print("\nQuick test commands:")
    print("  bxmap demo/dumps/lab1.dmp --auto-tune --extract all --report all")
    print("  bxmap demo/dumps/lab6.dmp --auto-tune --extract env --report user")
    print("  bxmap demo/dumps/minidump.dmp --map-va --rwx-only --auto-tune")

if __name__ == "__main__":
    main()