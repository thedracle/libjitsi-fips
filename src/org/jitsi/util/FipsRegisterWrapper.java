package org.jitsi.util;
import org.bouncycastle.crypto.general.FipsRegister;
import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.internal.EngineProvider;

import java.util.logging.Logger;
import java.util.logging.Level;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * The FIPS package hides all of its bouncycastle internal goodies from us.
 * Jitsi makes use of them in its DtlsControlImpl and for several tests.
 *
 * Unfortunately wrapping in the same package will not work because the
 * certificate for a class added to a package in a signed jar have
 * to be the same.
 *
 * It's possible we could tell the JVM to make an exception, but it seems
 * easier instead to reach into the FipsRegister using reflection, and
 * use it to get access to the internal ciphers and components we need.
 */
public class FipsRegisterWrapper {
    private static Logger LOG = Logger.getLogger(FipsRegisterWrapper.class.getName());
    public static <T> EngineProvider<T> getProvider(FipsAlgorithm algorithm)
    {
        try {
            Method getProviderMethod = FipsRegister.class.getDeclaredMethod("getProvider", FipsAlgorithm.class);
            getProviderMethod.setAccessible(true);

            return (EngineProvider<T>) getProviderMethod.invoke(null, algorithm);
        }
        catch(IllegalAccessException e) {
            LOG.log(Level.SEVERE,"Illegal access exception throw trying to access FipsRegister: " + e.getMessage());
        }
        catch(NoSuchMethodException e) {
            LOG.log(Level.SEVERE,"No such method exception throw trying to access FipsRegister: " + e.getMessage());

        }
        catch(InvocationTargetException e) {
             LOG.log(Level.SEVERE,"Illegal target exception throw trying to access FipsRegister: " + e.getMessage());
        }
        return null;

    }
}
