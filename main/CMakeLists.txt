idf_component_register(SRCS "tropic_full.c"
                    INCLUDE_DIRS "."
                    REQUIRES driver mbedtls libtropic
                    PRIV_REQUIRES esp_timer esp_rom libtropic
                    
)



