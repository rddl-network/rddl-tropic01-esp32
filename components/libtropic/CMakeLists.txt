# Automatisch alle .c-Dateien aus den relevanten vendor-Unterverzeichnissen einbinden
file(GLOB_RECURSE LIBTROPIC_SOURCES
    "src/*.c"
    "vendor/trezor_crypto/ed25519-donna/*.c"
    "vendor/trezor_crypto/aes/*.c"
    "vendor/trezor_crypto/chacha20poly1305/*.c"
    "vendor/trezor_crypto/*.c"
)

# 🔥 exclude test/fuzzer code
list(FILTER LIBTROPIC_SOURCES EXCLUDE REGEX "vendor/trezor_crypto/fuzzer/.*")
list(FILTER LIBTROPIC_SOURCES EXCLUDE REGEX "vendor/trezor_crypto/tests/.*")
list(FILTER LIBTROPIC_SOURCES EXCLUDE REGEX "vendor/trezor_crypto/tools/.*")
list(FILTER LIBTROPIC_SOURCES EXCLUDE REGEX "vendor/trezor_crypto/aes/aestst\\.c")
list(FILTER LIBTROPIC_SOURCES EXCLUDE REGEX "vendor/trezor_crypto/tools/.*")

idf_component_register(
    SRCS ${LIBTROPIC_SOURCES}
    INCLUDE_DIRS
        "include"
        "vendor"
        "vendor/secp256k1-zkp/include"
        "vendor/trezor_crypto"
        "vendor/trezor_crypto/ed25519-donna"
        "vendor/trezor_crypto/aes"
        "vendor/trezor_crypto/chacha20poly1305"
)




