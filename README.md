# Talking to TROPIC01 from an ESP32-P4

*A long, friendly walkthrough inspired by the early* Inside Macintosh *books—plain language, plenty of context, and real, practical detail.*

---

## Introduction

This article explains how your ESP32-P4 communicates with the TROPIC01 secure element. It does not assume you are a cryptographer or a protocol lawyer; it assumes you are a developer who wants to make a small device do a reliable, secure thing. We will focus on the **shape** of the bytes on the wire, the **order** of operations, and the **intent** behind each step. Along the way, we’ll decode the certificate just enough to extract the device’s static X25519 key, perform a secure channel handshake, and then exercise a full P-256 (secp256r1) ECDSA flow: generate a key in the device, read its public key, sign a digest, and verify the signature locally using mbedTLS.

If you’ve seen the short guide already, this is the same material, but expanded into a narrative with more “why” and “what to watch out for.”

---

## The Mental Model

Think of the system as three layers stacked on top of SPI:

1. **Layer 1 (L1): SPI**
   The raw transport. Mode 0 works well. Keep the clock conservative during bring-up (≈1 MHz is fine) and use a software-controlled CS (Chip Select) with tiny guard delays (a couple of microseconds) before and after toggling.

2. **Layer 2 (L2): Framed request/response**
   This is a tiny message format atop SPI. Every request includes a **request ID**, a **length byte**, the **payload** (if any), and a **CRC-16**. Every response you pull from the device has a **status**, a **length**, an optional **payload**, and a **CRC-16**—with one important exception: an ACK with length zero **omits** the CRC.

3. **Layer 3 (L3): Commands**
   These are the real features: random number generation, memory/config access, ECC key management, ECDSA/EdDSA signing, counters, and so on. Crucially, after a **secure channel** is established, all L3 commands travel encrypted and integrity-protected.

You always interact bottom-up: bring up SPI, talk L2, then perform an L3 handshake to create the encrypted tunnel, and only then use the “good stuff” (TRNG, ECC, etc.).

---

## Layer 2 in Detail

### Frames and CRC

An L2 request has this form:

```
[REQ_ID][LEN][PAYLOAD ...][CRC16]
```

* **REQ_ID** is one byte. Examples: `0x01` (GET_INFO), `0x02` (handshake), `0x04` (encrypted command), and so on.
* **LEN** is one byte; the payload can be 0–252 bytes.
* **CRC16** uses polynomial **0x8005**, initial value **0x0000**, MSB-first math, and is **LSB-first on the wire**. Put differently: compute CRC in the usual big-endian register sense, then serialize the low byte first, high byte second.

An L2 response is **not pushed** at you; you pull it by sending the one-byte **GET_RESPONSE** (`0xAA`). The device replies with a **chip status** byte. If the status says READY, you then read two bytes:

```
[STATUS][LEN]
```

If `LEN` is non-zero, you read the payload. Then you read two CRC bytes. If `LEN` is zero and `STATUS` is a pure ACK (`0x01`) there is **no CRC**.

The most common `STATUS` values are:

* `0x01` – Request OK (ACK)
* `0x02` – Response OK (data available)
* `0x03` – Request continues (you’re streaming a multi-part request)
* `0x04` – Response continues (you must pull again to get the rest)
* `0xFF` – Busy (you should wait and poll again)

### Polling rhythm

A normal rhythm looks like this:

1. Issue a request (for example, GET_INFO).
2. Poll `0xAA` until the device is READY and returns either an ACK or a data response.
3. If the response says “continues” (`0x04`), you keep polling and appending until complete.
4. Always check CRCs (except the special “ACK+LEN=0” case, which has no CRC).

This might feel chatty, but it’s very deterministic once you get used to it.

---

## Certificates and the Device’s Static X25519 Key

The TROPIC01 exposes an X.509 certificate. You read it in four chunks (0–127, 128–255, 256–383, 384–511). The first ten bytes of the concatenated blob are a small header; the certificate follows thereafter. Inside that certificate sits the device’s static X25519 public key (**STPUB**).

You don’t need to fully parse ASN.1 to find it. Search for the following pattern:

```
... 2B 65 6E 03 21 00 <32 bytes> ...
```

* `0x2B 0x65 0x6E` is part of the 1.3.101.* OID sequence used around modern curves.
* `0x03` is the BIT STRING tag.
* `0x21` is the length (33 bytes: one “unused bits” byte + 32 payload bytes).
* `0x00` is the unused-bits indicator for the BIT STRING.
* The **next 32 bytes** are the X25519 public key you need as **STPUB**.

We’ll use **STPUB** during the handshake to derive shared secrets.

---

## The Secure Channel: What It Is and Why It Matters

You can run some GET_INFO type operations without a secure channel, but all L3 commands that do real work—random numbers, ECC operations, counters—should go over an encrypted tunnel. The secure channel is based on **X25519** (for ECDH), **HKDF-SHA256** (for key derivation), and **AES-256-GCM** (for authenticated encryption).

### The Ingredients

* Your **pairing** keypair: `SH_PRIV` and `SH_PUB`, which the device knows about in a specific pairing slot (0, 1, 2, …).
* The device’s static X25519 `STPUB` (extracted from the certificate).
* A fresh ephemeral host keypair: `EHPRIV` and `EHPUB`, created per session.

### The Handshake Steps

1. **Host → Device:** Send `EHPUB` and the selected pairing slot index via the **handshake** request.

2. **Device → Host:** Returns `TSEHPUB` (its ephemeral handshake public key) and `TSAUTH`, a 16-byte tag.

3. **Both sides derive the same secrets** using three X25519 exchanges:

   * `ss_eh_tseh = X25519(EHPRIV, TSEHPUB)`
   * `ss_sh_tseh = X25519(SH_PRIV, TSEHPUB)`
   * `ss_eh_st   = X25519(EHPRIV, STPUB)`

   These feed a small HKDF chain to produce two operating keys:

   * `kcmd` — used to **encrypt commands** you send
   * `kres` — used to **decrypt responses** you receive
     (The device does the same internally.)

4. **Transcript hash:** Build a very specific SHA-256 transcript hash over the following sequence:

   * `PROTOCOL_NAME` (exact 32-byte string provided by the firmware)
   * then `SHPUB`
   * then `STPUB`
   * then `EHPUB`
   * then the **pairing slot index** as a single byte
   * then `TSEHPUB`

   Each step folds the previous digest into the next, exactly as the reference code shows.

5. **Verify `TSAUTH`:** Using an AES-GCM key named `kauth` (produced mid-way through the HKDF chain), run AES-GCM with a **zeroed 12-byte nonce**, **the transcript hash as AAD**, and **no plaintext**. If the produced 16-byte tag matches `TSAUTH`, the handshake is validated and the channel is established.

At this point, you set the channel’s **counter** to 0. For each L3 exchange, you build the 12-byte GCM nonce from the little-endian counter (first four bytes) with the rest zeros, then you increment the counter by one **after** you finish the request/response.

### The Two Big Pitfalls

* **Key direction:** Use **`kcmd`** to encrypt your outbound L3 command and **`kres`** to decrypt the inbound L3 response. Reversing them results in decryption failures that look like “GCM tag mismatch.”
* **Nonce/counter discipline:** The counter is part of the nonce. Do not reuse a counter value with the same key. Do not “peek and increment early.” Increment **after** a successful round trip.

---

## Layer 3: The Useful Commands

All successful L3 responses start with **`0xC3`** (“OK”). Some firmware builds include a few reserved bytes after `0xC3`; your code should tolerate both the “one-byte OK” and “OK plus padding” forms as shown in the reference.

### Random Numbers

* **Request:** `[0x50, nbytes]`
* **Response:** `0xC3 [00 00 00]? <nbytes>`
  You may see three zero bytes after `0xC3`; the code already handles this.

### ECC: P-256 (secp256r1)

* **Generate key:**
  Request: `[0x60, slot_le16, 0x01]`
  Response: `0xC3`
  Some devices insist that the slot be empty; if you get a failure, erase first or choose a fresh slot.

* **Read key:**
  Request: `[0x62, slot_le16]`
  Response:

  ```
  0xC3 | curve | origin | 13 reserved | pubkey...
  ```

  The public key format may be 64 bytes (X||Y) or 65 bytes (0x04||X||Y). Your verifier should accept either.

* **Sign (ECDSA):**
  Request: `[0x70, slot_le16, 13×0x00, SHA256(message)]`
  Response:

  ```
  0xC3 | 15 reserved | r(32) | s(32)
  ```

### Memory, Config, and Counters (Quick Tour)

* **Read config (R/I):** Request `[CMD, addr_le16]` → `0xC3 …data…`
* **Memory read/write/erase:** Usual pattern with slot addresses and short padding bytes. The working Python reference shows the exact payload layouts.
* **Monotonic counters:** Initialize, update (decrement), get. Indices are limited, so bounds-check against constants.

These are handy for device personalization, anti-rollback, and secure storage adjuncts—once you have the encrypted tunnel in place.

---

## A Complete Flow: From Power-Up to Verified Signature

Here’s the full script with commentary:

1. **SPI bring-up.** Mode 0, ~1 MHz, software CS. Tiny delays around CS toggles help with clean edges.

2. **Wait for READY.** Poll `0xAA` until the chip returns `0x01`. You’ll get to know this byte well.

3. **GET_INFO: CHIPID.** This is mostly a sanity check. If you can request and receive this cleanly, your L2 framing and CRCs are probably correct.

4. **GET_INFO: X.509 certificate (4 chunks).** Stitch the chunks together, skip the first 10 bytes of the header, and identify the certificate length. Extract the X25519 public key (STPUB) via the pattern `2B 65 6E 03 21 00` followed by 32 bytes.

5. **Secure Channel Handshake.**

   * Generate a fresh X25519 host keypair (EHPRIV/EHPUB).
   * L2 handshake request: send EHPUB + pairing slot index.
   * Receive TSEHPUB and TSAUTH.
   * Build the transcript hash in the exact sequence described above.
   * Derive `kcmd`/`kres` via HKDF stages.
   * Validate TSAUTH by AAD-only AES-GCM with zero nonce.
     If the tag matches, you now have an encrypted tunnel.

6. **Optional: TRNG test.** Request 32 bytes of randomness to exercise the channel and double-check your encrypt-then-decrypt dance and counter handling.

7. **ECC: Generate key in slot 0.** Send `[0x60, 0x0000, 0x01]`. If you get an error, erase and try again or switch to a different slot. The response `0xC3` indicates success.

8. **ECC: Read key.** Retrieve curve, origin, and the public key. Log what you got; it helps when you verify.

9. **Hash a message.** Compute SHA-256 of a test string (“hello-tropic01-ecdsa” is fine). Keep a hex dump for reference.

10. **ECC: Sign.** Send the sign request with the slot, 13 zero padding bytes, and your 32-byte hash. You receive an OK prefix and two 32-byte numbers: `r` and `s`.

11. **Verify locally with mbedTLS.**

    * Load group `MBEDTLS_ECP_DP_SECP256R1`.
    * Populate an `mbedtls_ecp_point` with X and Y (strip a leading 0x04 if present).
    * Convert `r` and `s` to MPIs.
    * Call `mbedtls_ecdsa_verify`.
      If it returns zero, your signature is correct and the entire pipeline is working.

12. **Tidy up.** You can abort the secure session, free buffers, and set GPIO pulls back to something polite. If this is automated testing, loop through more slots or repeat the flow to catch intermittent issues.

---

## Troubleshooting and “Why is it Always the CRC?”

**CRC mismatches**

* Confirm you computed CRC over exactly `[REQ_ID|LEN|PAYLOAD]` for requests, and `[STATUS|LEN|PAYLOAD]` for responses.
* Do not emit/read CRC on pure ACKs with `LEN=0`. That special case trips many first attempts.

**Handshake tag mismatch**

* The transcript hash order must match the reference byte-for-byte. Double-check that the **pairing slot index is a single byte** in that sequence.
* Confirm `PROTOCOL_NAME` is the exact 32-byte constant, including trailing zeros.
* Make sure your X25519 functions operate on little-endian byte arrays as expected by the library you’re using.

**GCM decrypt failures on L3**

* Check that the **nonce** is built from the current counter (little-endian), and that you increment the counter only after a full round trip.
* Ensure AAD is **empty** for ordinary L3 messages (only the handshake tag check uses AAD).
* Verify you used `kres` to decrypt responses (and not `kcmd` by accident).

**Key generation fails “sometimes”**

* Some firmware builds don’t allow generating into a non-empty slot. Erase first or pick another slot.
* If the device reboots or the session is aborted mid-operation, re-handshake to refresh keys and counters.

**Public key “wrong length”**

* Accept both 64-byte raw (X||Y) and 65-byte uncompressed SEC1 (0x04||X||Y). Your verifier should strip 0x04 if present.

---

## Design Notes & Rationale

* **Why L2 framing at all?** It lets the chip stay stateless at the SPI layer and still provide robust error detection and chunking. If you get a partial transfer, the CRC catches it. If you get a long transfer, the “continue” status makes it easy to stream.

* **Why X25519 for the tunnel but P-256 for ECDSA?** X25519 gives a clean, modern ECDH primitive that’s fast and standardized. P-256 remains widely used for ECDSA signatures, compatible with most TLS stacks and crypto libraries. Mixing them is common in real products.

* **Why counters in the nonce?** AES-GCM is catastrophically unsafe if you ever reuse a nonce with the same key. A monotonic counter is simple, deterministic, and audit-friendly, which is perfect for firmware.

---

## Practical Tips

* Keep SPI modest during bring-up; later you can increase it after you’re confident the electrical path is clean.
* Log short hex dumps of both ciphertext and plaintext (never private keys) during development; it makes it straightforward to compare against the Python reference.
* When in doubt, re-run the Python code on the same host message and compare the GCM inputs and outputs. If your nonces, keys, and counters match, the bytes will match too.

---

## Frequently Asked Questions

**Q: Can I skip the certificate and hardcode STPUB?**
A: For a quick test, yes. For a product, you want to read and verify the certificate chain, then extract STPUB. That’s how you prevent key substitution.

**Q: Does the device support Ed25519 signing too?**
A: Yes (command `0x71`). The request/response shapes mirror ECDSA’s, but the curve and message semantics differ. The included constants document both.

**Q: What happens if I lose power mid-session?**
A: The secure channel keys are ephemeral; just re-establish the session. You should also reset your L3 nonce counter to zero on each new session.

**Q: Why do some responses have extra zeros after `0xC3`?**
A: Firmware padding/reserved fields. Your parser should tolerate the reserved area sizes shown in the reference.

---

## Conclusion

Once you see the pattern, the TROPIC01 protocol feels pleasantly mechanical:

* Framed L2 messages with a crisp CRC.
* A disciplined, modern secure channel with a simple counter-nonce rule.
* Straightforward L3 commands that do exactly what they say.

The most common snags—CRC placement, handshake hash order, AES-GCM key direction, and nonce discipline—are easy to avoid if you follow the steps here. Combine this document with your working C demo and the Python reference, and you’ll have a reliable, testable foundation for secure key operations on ESP32-P4.

If you’d like this as a printable PDF or a developer-facing README tailored to your repository, I can format it accordingly.
