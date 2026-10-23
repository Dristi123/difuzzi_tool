package difuzzi.rt;

import java.lang.reflect.Method;
import java.util.*;

/** Records which rewritten classes have been initialized, per class loader, and resets them (see {@link Rewriter}). */
public final class Statics {
    private static final Map<ClassLoader, List<Class<?>>> INITIALIZED = new IdentityHashMap<>();

    public static synchronized void register(Class<?> c) {
        INITIALIZED.computeIfAbsent(c.getClassLoader(), k -> new ArrayList<>()).add(c);
    }

    /** Restore the static state of every class of this loader initialized so far, in initialization order. */
    public static void resetAll(ClassLoader loader) throws Exception {
        List<Class<?>> classes;
        synchronized (Statics.class) {
            classes = new ArrayList<>(INITIALIZED.getOrDefault(loader, Collections.emptyList()));
        }
        for (Class<?> c : classes) {
            Method reset = c.getDeclaredMethod(Rewriter.RESET);
            reset.setAccessible(true);
            reset.invoke(null);
        }
    }
}
