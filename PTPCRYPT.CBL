       IDENTIFICATION DIVISION.
       PROGRAM-ID. PTPCRYPT.

       DATA DIVISION.
       WORKING-STORAGE SECTION.

       01  PLAINTEXT         PIC X(100).
       01  CIPHER-LENGTH     PIC 9(8) COMP-5.
       01  CIPHER-POINTER    POINTER.
       01  CIPHERTEXT        PIC X(500).
       01  DECRYPTED-POINTER POINTER.
       01  DECRYPTED-LENGTH  PIC 9(8) COMP-5.
       01  DECRYPTED-TEXT    PIC X(500).
       01  KEY-VAL           PIC X(32) VALUE "8579303019".

       01  BASE64-CIPHER     PIC X(500).
       01  BASE64-LENGTH     PIC 9(8) COMP-5.


       01  ENC-CTX           POINTER.
       01  DEC-CTX           POINTER.
       01  SALT.
           03  S1            PIC X(4) VALUE X"39300000".
           03  S2            PIC X(4) VALUE X"D4310000".

       01  RET-VALUE         PIC S9(9) COMP-5.
       01 pp             PROCEDURE-POINTER.

       LINKAGE SECTION.
       01 LN-PLAINTEXT-ARG.
          05 LN-PLAINTEXT-LENGTH  PIC 9(4) COMP-5.
          05 LN-PLAINTEXT         PIC X(100).

       PROCEDURE DIVISION USING LN-PLAINTEXT-ARG.

       MOVE LN-PLAINTEXT TO PLAINTEXT.

  **** SET pp TO ENTRY 'openssl_aes'

       CALL 'EVP_CIPHER_CTX_new' RETURNING ENC-CTX.
       CALL 'EVP_CIPHER_CTX_new' RETURNING DEC-CTX.

       CALL 'aes_init' USING
           BY REFERENCE KEY-VAL
           BY VALUE LENGTH OF KEY-VAL
           BY REFERENCE SALT
           BY VALUE ENC-CTX
           BY VALUE DEC-CTX
           RETURNING RET-VALUE
           ON EXCEPTION
               DISPLAY "AES INIT FAILED" UPON SYSOUT
               STOP RUN.

       IF RET-VALUE NOT = 0
           DISPLAY "AES INIT FAILED" UPON SYSOUT
           STOP RUN
       END-IF.

       MOVE LENGTH OF PLAINTEXT TO CIPHER-LENGTH.

       CALL 'aes_encrypt' USING
           BY VALUE ENC-CTX
           BY REFERENCE PLAINTEXT
           BY REFERENCE CIPHER-LENGTH
           RETURNING CIPHER-POINTER.

       CALL 'C$MEMCPY' USING BY REFERENCE CIPHERTEXT
                            BY VALUE CIPHER-POINTER
                            BY VALUE CIPHER-LENGTH.

       CALL 'base64_encode' USING
                            BY REFERENCE CIPHERTEXT
                            BY VALUE CIPHER-LENGTH
                            BY REFERENCE BASE64-CIPHER
                            RETURNING BASE64-LENGTH.

       DISPLAY "Base64 Ciphertext: " BASE64-CIPHER(1:BASE64-LENGTH).

       CALL 'base64_decode' USING
                            BY REFERENCE BASE64-CIPHER
                            BY VALUE BASE64-LENGTH
                            BY REFERENCE CIPHERTEXT
                            RETURNING CIPHER-LENGTH.

       MOVE CIPHER-LENGTH TO DECRYPTED-LENGTH.

       CALL 'aes_decrypt' USING
           BY VALUE DEC-CTX
           BY REFERENCE CIPHERTEXT
           BY REFERENCE DECRYPTED-LENGTH
           RETURNING DECRYPTED-POINTER.

       CALL 'C$MEMCPY' USING BY REFERENCE DECRYPTED-TEXT
                            BY VALUE DECRYPTED-POINTER
                            BY VALUE DECRYPTED-LENGTH.

       DISPLAY "Decrypted text: " DECRYPTED-TEXT(1:DECRYPTED-LENGTH).

       CALL 'aes_cleanup' USING
           BY VALUE ENC-CTX
           BY VALUE DEC-CTX.

       STOP RUN.
