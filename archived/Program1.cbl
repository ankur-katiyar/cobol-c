       IDENTIFICATION DIVISION.
       PROGRAM-ID. Program1.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 str            PIC X(20) VALUE "from COBOL".
       01 counter        PIC 9(8)  COMP-5 VALUE ZEROES.
       01 ret-value      PIC S9(9) COMP-5 VALUE ZEROES.
       01 pp             PROCEDURE-POINTER.

       PROCEDURE DIVISION.
           SET pp TO ENTRY 'myCDLL'
           CALL 'cfunc' USING BY REFERENCE str
                           BY REFERENCE counter
               RETURNING ret-value
           DISPLAY str
           DISPLAY counter
           DISPLAY "ret code = " ret-value
           GOBACK.
