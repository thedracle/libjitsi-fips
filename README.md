libjitsi
========

libjitsi is an advanced Java media library for secure real-time audio/video communication. It allows applications to capture, playback, stream, encode/decode and encrypt audio and video flows. It also allows for advanced features such as audio mixing, handling multiple streams, participation in audio and video conferences.  Originally libjitsi was part of the Jitsi client source code but we decided to spin it off so that other projects can also use it.  libjitsi is distributed under the terms of the Apache license. 

========

Important!

Run videobridge with VB_EXTRA_JVM_PARAMS="-Djava.security.egd=file:/dev/./urandom", or the DTLS Handshake process with lock up on obtaining random bytes from /dev/random.
