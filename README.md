# weaponized-pdf-teardown

Originally published at https://www.timsalvador.com/blog/weaponized-pdf-teardown/

A full static teardown of `evil.pdf`, a resume-themed **malicious PDF dropper**. The document auto-runs on open via `/OpenAction` and `/Launch`, drops a **PyInstaller-packed Windows binary** disguised as a PDF, and that binary is a **Meterpreter `reverse_tcp` stager** obfuscated with the *pyherion* crypter (AES-256-ECB, key in cleartext). The repo includes a standalone decryptor that reproduces the whole unwrap without executing anything.

> Analyzed on a Linux CLI box with plain shell tooling and [REA](https://github.com/morluto/rea) for the PyInstaller layer. Everything here is static: the PDF is never opened, the PE is never run, and the final stager is decrypted rather than executed. The method generalizes to any layered dropper; the exact object numbers and hashes are specific to this sample.

**📖 The full story, including the dead ends and lessons, is at [timsalvador.com/blog/weaponized-pdf-teardown](https://www.timsalvador.com/blog/weaponized-pdf-teardown/) and in [docs/writeup.md](docs/writeup.md).** It reads as a blog post and doubles as a build log.

---

## Results

Six layers, peeled statically:

| Layer | What it is | How it was opened |
|---|---|---|
| 1. PDF document | `/OpenAction` + `/AA` + `/Launch` | keyword scan, object dump |
| 2. `/Launch` action | `cmd.exe` + fake Adobe prompt | read the action string |
| 3. Embedded "PDF" | zlib stream, actually a Windows PE | decompress, check magic bytes |
| 4. PE | PyInstaller / Python 2.7 | REA `inspect_artifact` |
| 5. Entry script | pyherion crypter (AES-256-ECB) | key was in cleartext |
| 6. Payload | Meterpreter `reverse_tcp` stager | decrypt, read |

Indicators of compromise:

| Type | Indicator |
|---|---|
| C2 | `timsalvador.com` : `4444` (reverse TCP) |
| Dropper SHA-256 | `bce5092d06cb8b97f7a0fd5038a8ad46e668e295559d8c76c2ddb6e21c4733d0` |
| Payload SHA-256 | `f82a8cabf69ec8c68035358d1e058dfe611911d020e2772afc04adc7f089c445` |
| pyherion AES key | `gPxu{siK54F[NkXGs*9REuP|KDhfgD]e` (AES-256-ECB) |

---

## What's here

```
scripts/
  decrypt_pyherion.py   carve -> decompress -> AES-decrypt, prints source, never exec's
docs/                   the writeup (Markdown) and image folder
```

---

## Quick start

```bash
git clone https://github.com/tim-salvador/weaponized-pdf-teardown.git
cd weaponized-pdf-teardown

# Reproduce the unwrap against your own copy of the sample.
# The script only reads and decrypts; it never runs the payload or touches the network.
python3 scripts/decrypt_pyherion.py /path/to/evil.pdf
```

---

## Design principles

- **Read, do not run.** Every stage is defeated by reading what it must undo at runtime, so nothing is executed.
- **Identify by bytes, not by labels.** Declared MIME types and extensions are attacker-controlled; magic bytes are not.
- **One script, no side effects.** The decryptor writes nothing executable and opens no sockets.

---

## Requirements

- Python 3.9+ with the `cryptography` package
- A copy of the sample to point the script at (not distributed in this repo)
- Optional: [REA](https://github.com/morluto/rea) to inspect the PyInstaller archive yourself

---

## Caveats, in brief

- **Static analysis stops at the stager.** The second-stage Meterpreter payload lives on the listener, which was not captured.
- **This is a training sample.** The C2 and resume theme match my own domain; it is fully functional but not in-the-wild malware.
- **The sample is not included.** The repo ships the method and the decryptor, not the live binary.

Full detail on all of these in the writeup.

---

## License

MIT. See [LICENSE](LICENSE).

## Author

Tim Salvador · [timsalvador.com](https://timsalvador.com) · [github.com/tim-salvador](https://github.com/tim-salvador) · [linkedin.com/in/tim-salvador](https://linkedin.com/in/tim-salvador)
