/*
 * Copyright @ 2015 Atlassian Pty Ltd
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
package org.jitsi.impl.neomedia.transform.dtls;

import java.io.*;
import java.util.*;

import org.bouncycastle.tls.crypto.impl.jcajce.*;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoProvider;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;

import org.bouncycastle.tls.*;
import org.jitsi.util.*;

/**
 * Implements {@link TlsClient} for the purposes of supporting DTLS-SRTP.
 *
 * @author Lyubomir Marinov
 */
public class TlsClientImpl
    extends DefaultTlsClient
{
    /**
     * The <tt>Logger</tt> used by the <tt>TlsClientImpl</tt> class and its
     * instances to print debug information.
     */
    private static final Logger logger = Logger.getLogger(TlsClientImpl.class);

    private final TlsAuthentication authentication
        = new TlsAuthenticationImpl();

    /**
     * The <tt>SRTPProtectionProfile</tt> negotiated between this DTLS-SRTP
     * client and its server.
     */
    private int chosenProtectionProfile;

    /**
     * The SRTP Master Key Identifier (MKI) used by the
     * <tt>SRTPCryptoContext</tt> associated with this instance. Since the
     * <tt>SRTPCryptoContext</tt> class does not utilize it, the value is
     * {@link TlsUtils#EMPTY_BYTES}.
     */
    private final byte[] mki = TlsUtils.EMPTY_BYTES;

    /**
     * The <tt>PacketTransformer</tt> which has initialized this instance.
     */
    private final DtlsPacketTransformer packetTransformer;

    private static JcaTlsCrypto tlsCrypto = null;


    // Generate a TlsCrypto using BouncyCastle's Java Cryptography Architecture implementation that provides
    // FIPS compliant cryptography.
    static JcaTlsCrypto clientCrypto() {
        // Lazy initialize
        if(tlsCrypto == null) {
            JcaTlsCryptoProvider provider = new JcaTlsCryptoProvider().setProvider("BCFIPS");
            SecureRandom rnumGen = null;
            try {
                rnumGen = SecureRandom.getInstance("DEFAULT", "BCFIPS");
            }
            catch(Exception e) {
                e.printStackTrace();
                rnumGen = new SecureRandom();
            }

            tlsCrypto = (JcaTlsCrypto)provider.create(rnumGen);
        }
        return tlsCrypto;
    }

    /**
     * Initializes a new <tt>TlsClientImpl</tt> instance.
     *
     * @param packetTransformer the <tt>PacketTransformer</tt> which is
     * initializing the new instance
     */
    public TlsClientImpl(DtlsPacketTransformer packetTransformer)
    {
        // DefaultTlsClient now requires we provide a TlsCrypto object.
        super(TlsClientImpl.clientCrypto());

        this.packetTransformer = packetTransformer;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized TlsAuthentication getAuthentication()
        throws IOException
    {
        return authentication;
    }

    /**
     * Gets the <tt>SRTPProtectionProfile</tt> negotiated between this DTLS-SRTP
     * client and its server.
     *
     * @return the <tt>SRTPProtectionProfile</tt> negotiated between this
     * DTLS-SRTP client and its server
     */
    int getChosenProtectionProfile()
    {
        return chosenProtectionProfile;
    }

    /**
     * {@inheritDoc}
     *
     * Overrides the super implementation to explicitly specify cipher suites
     * which we know to be supported by Bouncy Castle and provide Perfect
     * Forward Secrecy.
     */
    @Override
    public int[] getCipherSuites()
    {
        return new int[]
        {
/* core/src/main/java/org/bouncycastle/crypto/tls/DefaultTlsClient.java */
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        };
    }

    /**
     * {@inheritDoc}
     *
     * Includes the <tt>use_srtp</tt> extension in the DTLS extended client
     * hello.
     */
    @Override
    @SuppressWarnings("rawtypes")
    public Hashtable getClientExtensions()
        throws IOException
    {
        Hashtable defaultClientExtensions = super.getClientExtensions();

        Hashtable clientExtensions = new Hashtable();
        /* 22 and 23 are extended_master_secret, and encrypt_then_mac
         * respectively. We filter these out because Jitsi can't handle
         * extended_master_secret.
         **/
        for(Object key : defaultClientExtensions.keySet()) {
            if(!key.toString().equals("22") && !key.toString().equals("23")) {
                clientExtensions.put(key, defaultClientExtensions.get(key));
            }
        }

        if (!isSrtpDisabled()
                && TlsSRTPUtils.getUseSRTPExtension(clientExtensions) == null)
        {
            if (clientExtensions == null)
                clientExtensions = new Hashtable();
            TlsSRTPUtils.addUseSRTPExtension(
                    clientExtensions,
                    new UseSRTPData(
                            DtlsControlImpl.SRTP_PROTECTION_PROFILES,
                            mki));
        }
        return clientExtensions;
    }

    /**
     * {@inheritDoc}
     *
     * The implementation of <tt>TlsClientImpl</tt> always returns
     * <tt>ProtocolVersion.DTLSv10</tt> because <tt>ProtocolVersion.DTLSv12</tt>
     * does not work with the Bouncy Castle Crypto APIs at the time of this
     * writing.
     */
    @Override
    public ProtocolVersion getClientVersion()
    {
        return ProtocolVersion.DTLSv10;
    }

    /**
     * Gets the <tt>TlsContext</tt> with which this <tt>TlsClient</tt> has been
     * initialized.
     *
     * @return the <tt>TlsContext</tt> with which this <tt>TlsClient</tt> has
     * been initialized
     */
    TlsContext getContext()
    {
        return context;
    }

    /**
     * Gets the <tt>DtlsControl</tt> implementation associated with this
     * instance.
     *
     * @return the <tt>DtlsControl</tt> implementation associated with this
     * instance
     */
    private DtlsControlImpl getDtlsControl()
    {
        return packetTransformer.getDtlsControl();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ProtocolVersion getMinimumVersion()
    {
        return ProtocolVersion.DTLSv10;
    }

    private Properties getProperties()
    {
        return packetTransformer.getProperties();
    }

    /**
     * {@inheritDoc}
     *
     * Overrides the super implementation as a simple means of detecting that
     * the security-related negotiations between the local and the remote
     * enpoints are starting. The detection carried out for the purposes of
     * <tt>SrtpListener</tt>.
     */
    @Override
    public void init(TlsClientContext context)
    {
        // TODO Auto-generated method stub
        super.init(context);
    }

    /**
     * Determines whether this {@code TlsClientImpl} is to operate in pure DTLS
     * mode without SRTP extensions or in DTLS/SRTP mode.
     *
     * @return {@code true} for pure DTLS without SRTP extensions or
     * {@code false} for DTLS/SRTP
     */
    private boolean isSrtpDisabled()
    {
        return getProperties().isSrtpDisabled();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #packetTransformer}.
     */
    @Override
    public void notifyAlertRaised(
            short alertLevel,
            short alertDescription,
            String message,
            Throwable cause)
    {
        packetTransformer.notifyAlertRaised(
                this,
                alertLevel, alertDescription, message, cause);
    }

    /**
     * {@inheritDoc}
     *
     * Makes sure that the DTLS extended server hello contains the
     * <tt>use_srtp</tt> extension.
     */
    @Override
    @SuppressWarnings("rawtypes")
    public void processServerExtensions(Hashtable serverExtensions)
        throws IOException
    {
        if (isSrtpDisabled())
        {
            super.processServerExtensions(serverExtensions);
            return;
        }

        UseSRTPData useSRTPData
            = TlsSRTPUtils.getUseSRTPExtension(serverExtensions);

        if (useSRTPData == null)
        {
            String msg
                = "DTLS extended server hello does not include the use_srtp"
                    + " extension!";
            IOException ioe = new IOException(msg);

            logger.error(msg, ioe);
            throw ioe;
        }
        else
        {
            int[] protectionProfiles = useSRTPData.getProtectionProfiles();
            int chosenProtectionProfile
                = (protectionProfiles.length == 1)
                    ? DtlsControlImpl.chooseSRTPProtectionProfile(
                            protectionProfiles[0])
                    : 0;

            if (chosenProtectionProfile == 0)
            {
                String msg = "No chosen SRTP protection profile!";
                TlsFatalAlert tfa
                    = new TlsFatalAlert(AlertDescription.illegal_parameter);

                logger.error(msg, tfa);
                throw tfa;
            }
            else
            {
                /*
                 * If the client detects a nonzero-length MKI in the server's
                 * response that is different than the one the client offered,
                 * then the client MUST abort the handshake and SHOULD send an
                 * invalid_parameter alert.
                 */
                byte[] mki = useSRTPData.getMki();

                if (Arrays.equals(mki, this.mki))
                {
                    super.processServerExtensions(serverExtensions);

                    this.chosenProtectionProfile = chosenProtectionProfile;
                }
                else
                {
                    String msg
                        = "Server's MKI does not match the one offered by this"
                            + " client!";
                    TlsFatalAlert tfa
                        = new TlsFatalAlert(AlertDescription.illegal_parameter);

                    logger.error(msg, tfa);
                    throw tfa;
                }
            }
        }
    }

    /**
     * Implements {@link TlsAuthentication} for the purposes of supporting
     * DTLS-SRTP.
     *
     * @author Lyubomir Marinov
     */
    private class TlsAuthenticationImpl
        implements TlsAuthentication
    {
        private TlsCredentials clientCredentials;

        /**
         * {@inheritDoc}
         */
        @Override
        public TlsCredentials getClientCredentials(
                CertificateRequest certificateRequest)
            throws IOException
        {
            if (clientCredentials == null)
            {
                CertificateInfo certificateInfo
                    = getDtlsControl().getCertificateInfo();

                org.bouncycastle.tls.Certificate cert = certificateInfo.getCertificate();

                // FIXME The signature and hash algorithms should be retrieved
                // from the certificate.
                short certificateType = cert.getCertificateAt(0).getClientCertificateType();
                short signatureAlgorithm = TlsUtils.getSignatureAlgorithmClient(certificateType);
                SignatureAndHashAlgorithm sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(context,
                        supportedSignatureAlgorithms, signatureAlgorithm);

                try {
                    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(certificateInfo.getKeyPair().getPrivateKey().getEncoded());
                    KeyFactory rsaFact = KeyFactory.getInstance("RSA");
                    RSAPrivateKey privateKey = (RSAPrivateKey)rsaFact.generatePrivate(spec);


                    // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
                    clientCredentials = new JcaDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), TlsClientImpl.clientCrypto(),
                            privateKey, cert, new SignatureAndHashAlgorithm(
                                HashAlgorithm.sha256,
                                SignatureAlgorithm.rsa));
                    }
                catch(NoSuchAlgorithmException algEx) {
                    logger.error("Unable to produce RSA Key using KeyFactory: " + algEx.getMessage());
                }
                catch(InvalidKeySpecException invalidKeySpecEx) {
                    logger.error("Unable to initialize PKCS8EncodedKeySpec, invalid key spec exception raised: " + invalidKeySpecEx.getMessage());
                }

            }
            return clientCredentials;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void notifyServerCertificate(TlsServerCertificate serverCertificate)
            throws IOException
        {
            try
            {
                getDtlsControl().verifyAndValidateCertificate(
                        serverCertificate.getCertificate());
            }
            catch (Exception e)
            {
                logger.error(
                        "Failed to verify and/or validate server certificate!",
                        e);
                if (e instanceof IOException)
                    throw (IOException) e;
                else
                    throw new IOException(e);
            }
        }
    }
}
