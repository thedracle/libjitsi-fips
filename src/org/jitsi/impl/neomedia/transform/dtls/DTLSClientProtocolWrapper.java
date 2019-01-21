package org.jitsi.impl.neomedia.transform.dtls;


import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSTransport;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import java.security.SecureRandom;

import java.util.logging.Logger;
import java.util.logging.Level;

// For constructing private inner class ClientHandshakeState.
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;


import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsPeer;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.TlsClientContext;
import org.bouncycastle.tls.ContentType;

public class DTLSClientProtocolWrapper extends DTLSClientProtocol {
    private static Logger LOG = Logger.getLogger(DTLSClientProtocolWrapper.class.getName());

    public DTLSClientProtocolWrapper() {
        super();
    }
    /**
     * The BCFIPS implementation of connect in DTLSClientProtocol destroys the masterSecret
     * required for jitsi to decode and ecrypt packets.
     *
     * This overrides this behavior and because of most of the structures being protected or private
     * inside DTLSClientProtocol has to make heavy use of reflection, see:
     * org/bouncycastle/tls/DTLSClientProtocol.java
     *
     * Original statements have been preserved using comments to clarify the statements using reflection.
     **/
    public DTLSTransport connect(TlsClient client, DatagramTransport transport) throws IOException {
        if (client == null)
        {
            throw new IllegalArgumentException("'client' cannot be null");
        }
        if (transport == null)
        {
            throw new IllegalArgumentException("'transport' cannot be null");
        }

        /**
         * Begin Reflection Wizardry.
         */
        try {
            SecurityParameters securityParameters = new SecurityParameters();
            Field securityParametersEntity = securityParameters.getClass().getDeclaredField("entity");
            securityParametersEntity.setAccessible(true);
            securityParametersEntity.set(securityParameters, ConnectionEnd.client);

            Constructor<ClientHandshakeState> clientHandshakeConstructor = ClientHandshakeState.class.getDeclaredConstructor();

            clientHandshakeConstructor.setAccessible(true);
            ClientHandshakeState state = clientHandshakeConstructor.newInstance();

            Field clientField = state.getClass().getDeclaredField("client");
            clientField.setAccessible(true);
            // state.client = client;
            clientField.set(state, client);

            Field clientContextField = state.getClass().getDeclaredField("clientContext");
            // state.clientContext = new TlsClientContextImpl(client.getCrypto(), securityParameters);
            clientContextField.setAccessible(true);

            Class tlsClientContextImplClass = Class.forName("org.bouncycastle.tls.TlsClientContextImpl");
            Constructor<?> tlsClientContextImplClassConstructor = tlsClientContextImplClass.getDeclaredConstructor(TlsCrypto.class, securityParameters.getClass());
            tlsClientContextImplClassConstructor.setAccessible(true);
            Object tlsClientContextImpl = tlsClientContextImplClassConstructor.newInstance(client.getCrypto(), securityParameters);

            clientContextField.set(state, tlsClientContextImpl);

            // state.clientContext = new TlsClientContextImpl(client.getCrypto(), securityParameters);

            Field securityParametersClientRandomField = securityParameters.getClass().getDeclaredField("clientRandom");
            securityParametersClientRandomField.setAccessible(true);

            // Method tlsProtocolCreateRandomBlock = TlsProtocol.class.getDeclaredMethod("createRandomBlock", Boolean.TYPE, TlsContext.class);
            // tlsProtocolCreateRandomBlock.setAccessible(true);
            // byte[] randomBlock = (byte[])tlsProtocolCreateRandomBlock.invoke(null, client.shouldUseGMTUnixTime(), tlsClientContextImpl);

            // createRandomBlock freezes... Use SecureRandom for now.
            SecureRandom rnumGen = null;
            try {
                rnumGen = SecureRandom.getInstance("DEFAULT", "BCFIPS");
            }
            catch(Exception e) {
                e.printStackTrace();
                rnumGen = new SecureRandom();
            }

            /**
             * The random block produced for DTLS negotiation
             *
             * See: https://tools.ietf.org/html/rfc5246#section-7.4.1
             */
            byte[] randomBlock = new byte[32];

            rnumGen.nextBytes(randomBlock);
            // Add in current time.
            int t = (int)(System.currentTimeMillis() / 1000L);
            randomBlock[0] = (byte)(t >>> 24);
            randomBlock[1] = (byte)(t >>> 16);
            randomBlock[2] = (byte)(t >>> 8);
            randomBlock[3] = (byte)t;

            securityParametersClientRandomField.set(securityParameters, randomBlock);
            // securityParameters.clientRandom = TlsProtocol.createRandomBlock(client.shouldUseGMTUnixTime(), state.clientContext);

            // We don't need extended master secret.
            Field securityParametersExtendedMasterSecret = securityParameters.getClass().getDeclaredField("extendedMasterSecret");
            securityParametersExtendedMasterSecret.setAccessible(true);
            securityParametersExtendedMasterSecret.set(securityParameters, false);

            Field securityParametersExtendedPadding = securityParameters.getClass().getDeclaredField("extendedPadding");
            securityParametersExtendedPadding.setAccessible(true);

            securityParametersExtendedPadding.set(securityParameters, client.shouldUseExtendedPadding());
            // securityParameters.extendedPadding = client.shouldUseExtendedPadding();

            client.init((TlsClientContext)tlsClientContextImpl);

            Class dtlsRecorderLayerClass = Class.forName("org.bouncycastle.tls.DTLSRecordLayer");

            // java.lang.NoSuchMethodException: org.bouncycastle.tls.DTLSRecordLayer.<init>(org.bouncycastle.tls.DatagramTransport, org.bouncycastle.tls.TlsPeer, short)
            // rdLayer(org.bouncycastle.tls.DatagramTransport,org.bouncycastle.tls.TlsContext,org.bouncycastle.tls.TlsPeer,short)

            // DTLSRecordLayer(DatagramTransport transport, TlsPeer peer, short contentType)
            Constructor<?> dtlsRecordLayerClassConstructor = dtlsRecorderLayerClass.getDeclaredConstructor(DatagramTransport.class, TlsContext.class, TlsPeer.class, Short.TYPE);

            dtlsRecordLayerClassConstructor.setAccessible(true);
            Object recordLayer = dtlsRecordLayerClassConstructor.newInstance(transport, tlsClientContextImpl, client, ContentType.handshake);

            // DTLSRecordLayer recordLayer = new DTLSRecordLayer(transport, client, ContentType.handshake);

            TlsSession sessionToResume = client.getSessionToResume();
            if (sessionToResume != null && sessionToResume.isResumable())
            {
                Object sessionParameters = sessionToResume.exportSessionParameters();
                if (sessionParameters != null)
                {
                    Field tlsSessionField = state.getClass().getDeclaredField("tlsSession");
                    tlsSessionField.setAccessible(true);
                    tlsSessionField.set(state, sessionToResume);

                    Field sessionParametersField = state.getClass().getDeclaredField("sessionParameters");
                    sessionParametersField.setAccessible(true);
                    sessionParametersField.set(state, sessionParameters);

                    // state.tlsSession = sessionToResume;
                    // state.sessionParameters = sessionParameters;
                }
            }

            try
            {
                Method clientHandshake = DTLSClientProtocol.class.getDeclaredMethod("clientHandshake", state.getClass(), dtlsRecorderLayerClass);
                return (DTLSTransport)clientHandshake.invoke(this, state, recordLayer);
                // return clientHandshake(state, recordLayer);
            }
            catch (Exception e)
            {
                if(e instanceof TlsFatalAlert) {
                    Method abortClientHandshake = super.getClass().getDeclaredMethod("abortClientHandshake", state.getClass(), dtlsRecorderLayerClass, Short.TYPE);
                    abortClientHandshake.invoke(this, state, recordLayer, ((TlsFatalAlert)e).getAlertDescription());
                    // super.abortClientHandshake(state, recordLayer, fatalAlert.getAlertDescription());
                }
                else if(e instanceof IOException || e instanceof RuntimeException) {
                    Method abortClientHandshake = super.getClass().getDeclaredMethod("abortClientHandshake", state.getClass(), dtlsRecorderLayerClass, Short.TYPE);
                    abortClientHandshake.invoke(this, state, recordLayer, AlertDescription.internal_error);

                }
                if(e instanceof RuntimeException) {
                    throw new TlsFatalAlert(AlertDescription.internal_error, e);
                }

                // All other errors are probably to do with reflection.
                throw e;
            }
        }
        catch (ReflectiveOperationException e) {
            e.printStackTrace();
        }
        catch(Exception e) {
            throw e;
        }
        return null;
    }
}
