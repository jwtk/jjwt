/*
 * Copyright (C) 2022 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.lang.CheckedFunction
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.*
import org.junit.Test

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.Provider
import java.security.SecureRandom
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.assertEquals

class RFC7520Section5Test {

    static final byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8)
    }

    static final String utf8(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8)
    }

    static final String b64Url(byte[] bytes) {
        return Encoders.BASE64URL.encode(bytes)
    }

    static final byte[] b64Url(String s) {
        return Decoders.BASE64URL.decode(s)
    }

    static final String FIGURE_72 =
            "You can trust us to stick with you through thick and " +
                    "thin\u2013to the bitter end. And you can trust us to " +
                    "keep any secret of yours\u2013closer than you keep it " +
                    "yourself. But you cannot trust us to let you face trouble " +
                    "alone, and go off without a word. We are your friends, Frodo."

    static final String FIGURE_73 = Strings.trimAllWhitespace('''
    {
      "kty": "RSA",
      "kid": "frodo.baggins@hobbiton.example",
      "use": "enc",
      "n": "maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT
          HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx
          6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U
          NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c
          R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy
          pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA
          VotGlvMQ",
      "e": "AQAB",
      "d": "Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy
          bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO
          5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6
          Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP
          1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN
          miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v
          pzj85bQQ",
      "p": "2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE
          oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH
          7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ
          2VFmU",
      "q": "te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V
          F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb
          9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8
          d6Et0",
      "dp": "UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH
          QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV
          RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf
          lo0rYU",
      "dq": "iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb
          pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A
          CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14
          TkXlHE",
      "qi": "kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ
          lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7
          Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx
          2bQ_mM"
    }
    ''')

    static final String FIGURE_74 = '3qyTVhIWt5juqZUCpfRqpvauwB956MEJL2Rt-8qXKSo'
    static final String FIGURE_75 = 'bbd5sTkYwhAIqfHsx8DayA'
    static final String FIGURE_76 = Strings.trimAllWhitespace('''
    laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePF
    vG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2G
    Xfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcG
    TSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8Vl
    zNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOh
    MBs9M8XL223Fg47xlGsMXdfuY-4jaqVw
    ''')

    static final String FIGURE_77 = Strings.trimAllWhitespace('''
    {
      "alg": "RSA1_5",
      "kid": "frodo.baggins@hobbiton.example",
      "enc": "A128CBC-HS256"
    }
    ''')
    static final String FIGURE_78 = Strings.trimAllWhitespace('''
    eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLm
    V4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0
    ''')

    static final String FIGURE_81 = Strings.trimAllWhitespace('''
    eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLm
    V4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0
    .
    laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePF
    vG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2G
    Xfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcG
    TSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8Vl
    zNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOh
    MBs9M8XL223Fg47xlGsMXdfuY-4jaqVw
    .
    bbd5sTkYwhAIqfHsx8DayA
    .
    0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_r
    aa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8O
    WzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZV
    yeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0
    zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2
    O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VW
    i7lzA6BP430m
    .
    kvKuFBXHe5mQr4lqgobAUg
    ''')

    static final String FIGURE_84 = Strings.trimAllWhitespace('''
    {
      "kty": "RSA",
      "kid": "samwise.gamgee@hobbiton.example",
      "use": "enc",
      "n": "wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRr
          I4pP1AhoqJRlZfYtWWd5mmHRG2pAHIlh0ySJ9wi0BioZBl1XP2e-C-Fy
          XJGcTy0HdKQWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnk
          Nrg71S2CuNZSQBIPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeSt
          sqo571utNfoUTU8E4qdzJ3U1DItoVkPGsMwlmmnJiwA7sXRItBCivR4M
          5qnZtdw-7v4WuR4779ubDuJ5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIU
          e7Tzizjg1nms0Xq_yPub_UOlWn0ec85FCft1hACpWG8schrOBeNqHBOD
          FskYpUc2LC5JA2TaPF2dA67dg1TTsC_FupfQ2kNGcE1LgprxKHcVWYQb
          86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJfNcFLlH3b8mb-H_ox35FjqB
          SAjLKyoeqfKTpVjvXhd09knwgJf6VKq6UC418_TOljMVfFTWXUxlnfhO
          OnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5qFDxDQKis99gcDa
          iCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfasvKn0aZRsnT
          yC0xhWBlsolZE",
      "e": "AQAB",
      "alg": "RSA-OAEP",
      "d": "n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bx
          cc0xQn5oZE5uSCIwg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq
          -B3qhfF3izlbkosrzjHajIcY33HBhsy4_WerrXg4MDNE4HYojy68TcxT
          2LYQRxUOCf5TtJXvM8olexlSGtVnQnDRutxEUCwiewfmmrfveEogLx9E
          A-KMgAjTiISXxqIXQhWUQX1G7v_mV_Hr2YuImYcNcHkRvp9E7ook0876
          DhkO8v4UOZLwA1OlUX98mkoqwc58A_Y2lBYbVx1_s5lpPsEqbbH-nqIj
          h1fL0gdNfihLxnclWtW7pCztLnImZAyeCWAG7ZIfv-Rn9fLIv9jZ6r7r
          -MSH9sqbuziHN2grGjD_jfRluMHa0l84fFKl6bcqN1JWxPVhzNZo01yD
          F-1LiQnqUYSepPf6X3a2SOdkqBRiquE6EvLuSYIDpJq3jDIsgoL8Mo1L
          oomgiJxUwL_GWEOGu28gplyzm-9Q0U0nyhEf1uhSR8aJAQWAiFImWH5W
          _IQT9I7-yrindr_2fWQ_i1UgMsGzA7aOGzZfPljRy6z-tY_KuBG00-28
          S_aWvjyUc-Alp8AUyKjBZ-7CWH32fGWK48j1t-zomrwjL_mnhsPbGs0c
          9WsWgRzI-K8gE",
      "p": "7_2v3OQZzlPFcHyYfLABQ3XP85Es4hCdwCkbDeltaUXgVy9l9etKgh
          vM4hRkOvbb01kYVuLFmxIkCDtpi-zLCYAdXKrAK3PtSbtzld_XZ9nlsY
          a_QZWpXB_IrtFjVfdKUdMz94pHUhFGFj7nr6NNxfpiHSHWFE1zD_AC3m
          Y46J961Y2LRnreVwAGNw53p07Db8yD_92pDa97vqcZOdgtybH9q6uma-
          RFNhO1AoiJhYZj69hjmMRXx-x56HO9cnXNbmzNSCFCKnQmn4GQLmRj9s
          fbZRqL94bbtE4_e0Zrpo8RNo8vxRLqQNwIy85fc6BRgBJomt8QdQvIgP
          gWCv5HoQ",
      "q": "zqOHk1P6WN_rHuM7ZF1cXH0x6RuOHq67WuHiSknqQeefGBA9PWs6Zy
          KQCO-O6mKXtcgE8_Q_hA2kMRcKOcvHil1hqMCNSXlflM7WPRPZu2qCDc
          qssd_uMbP-DqYthH_EzwL9KnYoH7JQFxxmcv5An8oXUtTwk4knKjkIYG
          RuUwfQTus0w1NfjFAyxOOiAQ37ussIcE6C6ZSsM3n41UlbJ7TCqewzVJ
          aPJN5cxjySPZPD3Vp01a9YgAD6a3IIaKJdIxJS1ImnfPevSJQBE79-EX
          e2kSwVgOzvt-gsmM29QQ8veHy4uAqca5dZzMs7hkkHtw1z0jHV90epQJ
          JlXXnH8Q",
      "dp": "19oDkBh1AXelMIxQFm2zZTqUhAzCIr4xNIGEPNoDt1jK83_FJA-xn
          x5kA7-1erdHdms_Ef67HsONNv5A60JaR7w8LHnDiBGnjdaUmmuO8XAxQ
          J_ia5mxjxNjS6E2yD44USo2JmHvzeeNczq25elqbTPLhUpGo1IZuG72F
          ZQ5gTjXoTXC2-xtCDEUZfaUNh4IeAipfLugbpe0JAFlFfrTDAMUFpC3i
          XjxqzbEanflwPvj6V9iDSgjj8SozSM0dLtxvu0LIeIQAeEgT_yXcrKGm
          pKdSO08kLBx8VUjkbv_3Pn20Gyu2YEuwpFlM_H1NikuxJNKFGmnAq9Lc
          nwwT0jvoQ",
      "dq": "S6p59KrlmzGzaQYQM3o0XfHCGvfqHLYjCO557HYQf72O9kLMCfd_1
          VBEqeD-1jjwELKDjck8kOBl5UvohK1oDfSP1DleAy-cnmL29DqWmhgwM
          1ip0CCNmkmsmDSlqkUXDi6sAaZuntyukyflI-qSQ3C_BafPyFaKrt1fg
          dyEwYa08pESKwwWisy7KnmoUvaJ3SaHmohFS78TJ25cfc10wZ9hQNOrI
          ChZlkiOdFCtxDqdmCqNacnhgE3bZQjGp3n83ODSz9zwJcSUvODlXBPc2
          AycH6Ci5yjbxt4Ppox_5pjm6xnQkiPgj01GpsUssMmBN7iHVsrE7N2iz
          nBNCeOUIQ",
      "qi": "FZhClBMywVVjnuUud-05qd5CYU0dK79akAgy9oX6RX6I3IIIPckCc
          iRrokxglZn-omAY5CnCe4KdrnjFOT5YUZE7G_Pg44XgCXaarLQf4hl80
          oPEf6-jJ5Iy6wPRx7G2e8qLxnh9cOdf-kRqgOS3F48Ucvw3ma5V6KGMw
          QqWFeV31XtZ8l5cVI-I3NzBS7qltpUVgz2Ju021eyc7IlqgzR98qKONl
          27DuEES0aK0WE97jnsyO27Yp88Wa2RiBrEocM89QZI1seJiGDizHRUP4
          UZxw9zsXww46wy0P6f9grnYp7t8LkyDDk8eoI4KX6SNMNVcyVS9IWjlq
          8EzqZEKIA"
    }
    ''')
    static final String FIGURE_85 = 'mYMfsggkTAm0TbvtlFh2hyoXnbEzJQjMxmgLN3d8xXA'
    static final String FIGURE_86 = '-nBoKLH0YkLZPSI9'
    static final String FIGURE_87 = Strings.trimAllWhitespace('''
    rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQi
    beYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyu
    cvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58
    -Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8Bpx
    KdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pK
    IIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7
    pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQ
    fOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe3
    8UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU
    06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5
    Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDR
    s
    ''')
    static final String FIGURE_88 = Strings.trimAllWhitespace('''
    {
      "alg": "RSA-OAEP",
      "kid": "samwise.gamgee@hobbiton.example",
      "enc": "A256GCM"
    }''')
    static final String FIGURE_89 = Strings.trimAllWhitespace('''
    eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG
    9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0
    ''')
    static final String FIGURE_92 = Strings.trimAllWhitespace('''
    eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG
    9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0
    .
    rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQi
    beYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyu
    cvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58
    -Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8Bpx
    KdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pK
    IIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7
    pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQ
    fOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe3
    8UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU
    06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5
    Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDR
    s
    .
    -nBoKLH0YkLZPSI9
    .
    o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgR
    L-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEw
    P7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8
    iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML
    7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSV
    maPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw
    .
    UCGiqJxhBI3IFVdPalHHvA
    ''')

    static final String FIGURE_95 = Strings.trimAllWhitespace('''
    {
      "keys": [
        {
          "kty": "oct",
          "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
          "use": "enc",
          "alg": "A128GCM",
          "k": "XctOhJAkA-pD9Lh7ZgW_2A"
        },
        {
          "kty": "oct",
          "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
          "use": "enc",
          "alg": "A128KW",
          "k": "GZy6sIZ6wl9NJOKB-jnmVQ"
        },
        {
          "kty": "oct",
          "kid": "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
          "use": "enc",
          "alg": "A256GCMKW",
          "k": "qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"
        }
      ]
    }
    ''')
    static final String FIGURE_96 = 'entrap_o\u2013peter_long\u2013credit_tun'
    static final String FIGURE_97 = 'uwsjJXaBK407Qaf0_zpcpmr1Cs0CC50hIUEyGNEt3m0'
    static final String FIGURE_98 = 'VBiCzVHNoLiR3F4V82uoTQ'
    static final String FIGURE_99 = '8Q1SzinasR3xchYz6ZZcHA'
    static final String FIGURE_101 = Strings.trimAllWhitespace('''
    {
      "alg": "PBES2-HS512+A256KW",
      "p2s": "8Q1SzinasR3xchYz6ZZcHA",
      "p2c": 8192,
      "cty": "jwk-set+json",
      "enc": "A128CBC-HS256"
    }
    ''')
    static final String FIGURE_102 = Strings.trimAllWhitespace('''
    eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3
    hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJl
    bmMiOiJBMTI4Q0JDLUhTMjU2In0
    ''')
    static final String FIGURE_105 = Strings.trimAllWhitespace('''
    eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3
    hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJl
    bmMiOiJBMTI4Q0JDLUhTMjU2In0
    .
    d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g
    .
    VBiCzVHNoLiR3F4V82uoTQ
    .
    23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IR
    sfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6l
    TF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb
    6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL
    _SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKd
    PQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrok
    AKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-
    zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V
    3kobXZ77ulMwDs4p
    .
    0HlwodAhOCILG5SQ2LQ9dg
    ''')

    static final String FIGURE_108 = Strings.trimAllWhitespace('''
    {
      "kty": "EC",
      "kid": "peregrin.took@tuckborough.example",
      "use": "enc",
      "crv": "P-384",
      "x": "YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQL
          pe2FpxBmu2",
      "y": "A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-
          SkgaFL1ETP",
      "d": "iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0Idn
          YK2xDlZh-j"
    }
    ''')
    static final String FIGURE_109 = 'Nou2ueKlP70ZXDbq9UrRwg'
    static final String FIGURE_110 = 'mH-G2zVqgztUtnW_'
    static final String FIGURE_111 = Strings.trimAllWhitespace('''
    {
      "kty": "EC",
      "crv": "P-384",
      "x": "uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuE
          DsQ6wNdNg3",
      "y": "sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-
          JdaY8tb7E0",
      "d": "D5H4Y_5PSKZvhfVFbcCYJOtcGZygRgfZkpsBr59Icmmhe9sW6nkZ8W
          fwhinUfWJg"
    }
    ''')
    public static final String FIGURE_113 = Strings.trimAllWhitespace('''
    {
      "alg": "ECDH-ES+A128KW",
      "kid": "peregrin.took@tuckborough.example",
      "epk": {
        "kty": "EC",
        "crv": "P-384",
        "x": "uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6i
            uEDsQ6wNdNg3",
        "y": "sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQT
            A-JdaY8tb7E0"
      },
      "enc": "A128GCM"
    }
    ''')
    static final String FIGURE_114 = Strings.trimAllWhitespace('''
    eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdH
    Vja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAt
    Mzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NH
    hBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMy
    ZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWT
    h0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0
    ''')
    static final String FIGURE_117 = Strings.trimAllWhitespace('''
    eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdH
    Vja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAt
    Mzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NH
    hBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMy
    ZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWT
    h0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0
    .
    0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2
    .
    mH-G2zVqgztUtnW_
    .
    tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cP
    WJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0
    IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkc
    Y9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w0
    3XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu
    07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ
    .
    WuGzxmcreYjpHGJoa17EBg
    ''')

    static {
        //ensure our representations match the RFC:
        assert FIGURE_77.equals(utf8(b64Url(FIGURE_78)))
        assert FIGURE_88.equals(utf8(b64Url(FIGURE_89)))
        assert FIGURE_101.equals(utf8(b64Url(FIGURE_102)))
        assert FIGURE_113.equals(utf8(b64Url(FIGURE_114)))
    }

    // https://www.rfc-editor.org/rfc/rfc7520.html#section-5.1
    @Test
    void testSection5_1() {

        RsaPrivateJwk jwk = Jwks.parser().build().parse(FIGURE_73) as RsaPrivateJwk
        RSAPublicKey key = jwk.toPublicJwk().toKey()

        def alg = new DefaultRsaKeyAlgorithm(StandardKeyAlgorithms.RSA1_5_ID, StandardKeyAlgorithms.RSA1_5_TRANSFORMATION) {
            @Override
            SecretKey generateCek(KeyRequest<?> request) {
                byte[] encoded = b64Url(FIGURE_74) // ensure RFC required value
                return new SecretKeySpec(encoded, "AES")
            }

            @Override
            protected JcaTemplate jca(Request<?> request) {
                return new JcaTemplate(getJcaName()) {
                    // overrides parent, Groovy doesn't pick it up due to generics signature:
                    @SuppressWarnings('unused')
                    byte[] withCipher(CheckedFunction<Cipher, byte[]> fn) throws SecurityException {
                        return b64Url(FIGURE_76)
                    }
                }
            }
        }

        def enc = new HmacAesAeadAlgorithm(128) {
            @Override
            protected byte[] ensureInitializationVector(Request request) {
                return b64Url(FIGURE_75) // ensure RFC required value
            }
        }

        // because Maps are not guaranteed to have the same order as defined in the RFC, we create an asserting
        // serializer here to check the constructed data, and then, after guaranteeing the same data, return
        // the order expected by the RFC
        def serializer = new Serializer<Map<String, ?>>() {
            @Override
            byte[] serialize(Map<String, ?> m) throws SerializationException {
                assertEquals 3, m.size()
                assertEquals alg.getId(), m.get('alg')
                assertEquals jwk.getId(), m.get('kid')
                assertEquals enc.getId(), m.get('enc')
                //everything has been asserted per the RFC - return the exact order as shown in the RFC:
                return utf8(FIGURE_77)
            }
        }

        String result = Jwts.builder()
                .serializer(serializer) // assert input, return RFC ordered string
                .header().keyId(jwk.getId()).and()
                .setPayload(FIGURE_72)
                .encryptWith(key, alg, enc)
                .compact()

        assertEquals FIGURE_81, result

        // Assert round trip works as expected:
        def parsed = Jwts.parser().decryptWith(jwk.toKey()).build().parseContentJwe(result)
        assertEquals alg.getId(), parsed.header.getAlgorithm()
        assertEquals jwk.getId(), parsed.header.getKeyId()
        assertEquals enc.getId(), parsed.header.getEncryptionAlgorithm()
        assertEquals FIGURE_72, utf8(parsed.payload)
    }

    @Test
    void testSection5_2() {

        RsaPrivateJwk jwk = Jwks.parser().build().parse(FIGURE_84) as RsaPrivateJwk
        RSAPublicKey key = jwk.toPublicJwk().toKey()

        def alg = new DefaultRsaKeyAlgorithm(StandardKeyAlgorithms.RSA_OAEP_ID, StandardKeyAlgorithms.RSA_OAEP_TRANSFORMATION) {
            @Override
            SecretKey generateCek(KeyRequest<?> request) {
                byte[] encoded = b64Url(FIGURE_85) // ensure RFC required value
                return new SecretKeySpec(encoded, "AES")
            }

            @Override
            protected JcaTemplate jca(Request<?> request) {
                return new JcaTemplate(getJcaName()) {
                    // overrides parent, Groovy doesn't pick it up due to generics signature:
                    @SuppressWarnings('unused')
                    byte[] withCipher(CheckedFunction<Cipher, byte[]> fn) throws SecurityException {
                        return b64Url(FIGURE_87)
                    }
                }
            }
        }

        def enc = new GcmAesAeadAlgorithm(256) {
            @Override
            protected byte[] ensureInitializationVector(Request request) {
                return b64Url(FIGURE_86) // ensure RFC required value
            }
        }

        // because Maps are not guaranteed to have the same order as defined in the RFC, we create an asserting
        // serializer here to check the constructed data, and then, after guaranteeing the same data, return
        // the order expected by the RFC
        def serializer = new Serializer<Map<String, ?>>() {
            @Override
            byte[] serialize(Map<String, ?> m) throws SerializationException {
                assertEquals 3, m.size()
                assertEquals alg.getId(), m.get('alg')
                assertEquals jwk.getId(), m.get('kid')
                assertEquals enc.getId(), m.get('enc')
                //everything has been asserted per the RFC - return the exact order as shown in the RFC:
                return utf8(FIGURE_88)
            }
        }

        String result = Jwts.builder()
                .serializer(serializer) // assert input, return RFC ordered string
                .header().keyId(jwk.getId()).and()
                .setPayload(FIGURE_72)
                .encryptWith(key, alg, enc)
                .compact()

        assertEquals FIGURE_92, result

        // Assert round trip works as expected:
        def parsed = Jwts.parser().decryptWith(jwk.toKey()).build().parseContentJwe(result)
        assertEquals alg.getId(), parsed.header.getAlgorithm()
        assertEquals jwk.getId(), parsed.header.getKeyId()
        assertEquals enc.getId(), parsed.header.getEncryptionAlgorithm()
        assertEquals FIGURE_72, utf8(parsed.payload)
    }

    @Test
    void testSection5_3() {

        def key = Keys.password(FIGURE_96.toCharArray())
        String cty = 'jwk-set+json'
        int p2c = 8192

        def wrapAlg = new AesWrapKeyAlgorithm(256) {
            @Override
            SecretKey generateCek(KeyRequest<?> request) {
                byte[] encoded = b64Url(FIGURE_97) // ensure RFC value
                return new SecretKeySpec(encoded, "AES")
            }
        }
        def alg = new Pbes2HsAkwAlgorithm(512, wrapAlg) {
            @Override
            protected byte[] generateInputSalt(KeyRequest<?> request) {
                return b64Url(FIGURE_99) // ensure RFC value
            }
        }
        def enc = new HmacAesAeadAlgorithm(128) {
            @Override
            protected byte[] ensureInitializationVector(Request request) {
                return b64Url(FIGURE_98) // ensure RFC value
            }
        }

        // because Maps are not guaranteed to have the same order as defined in the RFC, we create an asserting
        // serializer here to check the constructed data, and then, after guaranteeing the same data, return
        // the order expected by the RFC
        def serializer = new Serializer<Map<String, ?>>() {
            @Override
            byte[] serialize(Map<String, ?> m) throws SerializationException {
                assertEquals 5, m.size()
                assertEquals alg.getId(), m.get('alg')
                assertEquals FIGURE_99, m.get('p2s')
                assertEquals p2c, m.get('p2c')
                assertEquals cty, m.get('cty')
                assertEquals enc.getId(), m.get('enc')
                //everything has been asserted per the RFC - return the exact order as shown in the RFC:
                return utf8(FIGURE_101)
            }
        }

        String result = Jwts.builder()
                .serializer(serializer) // assert input, return RFC ordered string
                .header().contentType(cty).pbes2Count(p2c).and()
                .setPayload(FIGURE_95)
                .encryptWith(key, alg, enc)
                .compact()

        assertEquals FIGURE_105, result

        // Assert round trip works as expected:
        def parsed = Jwts.parser().decryptWith(key).build().parseContentJwe(result)
        assertEquals alg.getId(), parsed.header.getAlgorithm()
        assertEquals FIGURE_99, b64Url(parsed.header.getPbes2Salt())
        assertEquals p2c, parsed.header.getPbes2Count()

        assertEquals cty, parsed.header.get('cty') // compact form
        assertEquals "application/$cty" as String, parsed.header.getContentType() // normalized form

        assertEquals enc.getId(), parsed.header.getEncryptionAlgorithm()
        assertEquals FIGURE_95, utf8(parsed.payload)
    }

    @Test
    void testSection5_4() {

        def jwk = Jwks.parser().build().parse(FIGURE_108) as EcPrivateJwk
        def encKey = jwk.toPublicJwk().toKey()

        def wrapAlg = new AesWrapKeyAlgorithm(128) {
            @Override
            SecretKey generateCek(KeyRequest request) {
                byte[] encoded = b64Url(FIGURE_109) // ensure RFC value
                return new SecretKeySpec(encoded, "AES")
            }
        }
        def RFC_EPK = Jwks.parser().build().parse(FIGURE_111) as EcPrivateJwk
        def alg = new EcdhKeyAlgorithm(wrapAlg) {
            @Override
            protected KeyPair generateKeyPair(Curve curve, Provider provider, SecureRandom random) {
                return new KeyPair(RFC_EPK.toPublicJwk().toKey(), RFC_EPK.toKey()) // ensure RFC value
            }
        }
        def enc = new GcmAesAeadAlgorithm(128) {
            @Override
            protected byte[] ensureInitializationVector(Request request) {
                return b64Url(FIGURE_110)
            }
        }

        // because Maps are not guaranteed to have the same order as defined in the RFC, we create an asserting
        // serializer here to check the constructed data, and then, after guaranteeing the same data, return
        // the order expected by the RFC
        def serializer = new Serializer<Map<String, ?>>() {
            @Override
            byte[] serialize(Map<String, ?> m) throws SerializationException {
                assertEquals 4, m.size()
                assertEquals alg.getId(), m.get('alg')
                assertEquals jwk.getId(), m.get('kid')
                assertEquals enc.getId(), m.get('enc')
                assertEquals RFC_EPK.toPublicJwk(), m.get('epk')
                //everything has been asserted per the RFC - return the exact order as shown in the RFC:
                return utf8(FIGURE_113)
            }
        }

        String result = Jwts.builder()
                .serializer(serializer) // assert input, return RFC ordered string
                .header().keyId(jwk.getId()).and()
                .setPayload(FIGURE_72)
                .encryptWith(encKey, alg, enc)
                .compact()

        assertEquals FIGURE_117, result

        // Assert round trip works as expected:
        def parsed = Jwts.parser().decryptWith(jwk.toKey()).build().parseContentJwe(result)
        assertEquals alg.getId(), parsed.header.getAlgorithm()
        assertEquals enc.getId(), parsed.header.getEncryptionAlgorithm()
        assertEquals jwk.getId(), parsed.header.getKeyId()
        assertEquals RFC_EPK.toPublicJwk(), parsed.header.getEphemeralPublicKey()
        assertEquals FIGURE_72, utf8(parsed.payload)
    }
}
