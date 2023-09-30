## Base64 implementation

JJWT's `io.jsonwebtoken.io.Base64` implementation is based on [MigBase64](https://github.com/brsanthu/migbase64) with 
continued modifications for Base64 URL support and additional test cases. The MigBase64 copyright and license notice 
have been retained and are repeated here per that code's requirements:

```
Licence (BSD):
==============

Copyright (c) 2004, Mikael Grev, MiG InfoCom AB. (base64 @ miginfocom . com)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
Redistributions of source code must retain the above copyright notice, this list
of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this
list of conditions and the following disclaimer in the documentation and/or other
materials provided with the distribution.
Neither the name of the MiG InfoCom AB nor the names of its contributors may be
used to endorse or promote products derived from this software without specific
prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
OF SUCH DAMAGE.
```

Additionally, the following classes were copied from the Apache Commons-Codec project, with further JJWT-specific
modifications:
* io.jsonwebtoken.impl.io.Base64Codec
* io.jsonwebtoken.impl.io.Base64InputStream
* io.jsonwebtoken.impl.io.Base64OutputStream
* io.jsonwebtoken.impl.io.BaseNCodec
* io.jsonwebtoken.impl.io.BaseNCodecInputStream
* io.jsonwebtoken.impl.io.BaseNCodecOutputStream
* io.jsonwebtoken.impl.io.CodecPolicy

Its attribution:

```
Apache Commons Codec
Copyright 2002-2023 The Apache Software Foundation

This product includes software developed at
The Apache Software Foundation (https://www.apache.org/).
```

Also, the following classes were copied from the Apache Commons-IO project, with further JJWT-specific modifications:
* io.jsonwebtoken.impl.io.CharSequenceReader
* io.jsonwebtoken.impl.io.FilteredInputStream
* io.jsonwebtoken.impl.io.FilteredOutputStream
* io.jsonwebtoken.impl.io.ClosedInputStream
* io.jsonwebtoken.impl.io.UncloseableInputStream

It's attribution:

```
Apache Commons IO
Copyright 2002-2023 The Apache Software Foundation

This product includes software developed at
The Apache Software Foundation (https://www.apache.org/).
```