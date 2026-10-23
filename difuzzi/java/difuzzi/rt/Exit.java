package difuzzi.rt;

/** Replacement for System.exit / Runtime.exit / Runtime.halt in rewritten programs (see {@link Rewriter}). */
public final class Exit {
    /** An Error rather than an Exception, so that a program's catch (Exception e) does not swallow it. */
    public static final class ExitException extends Error {
        public final int status;

        public ExitException(int status) {
            super("exit status " + status, null, false, false);
            this.status = status;
        }
    }

    public static void exit(int status) {
        throw new ExitException(status);
    }

    public static void runtimeExit(Runtime runtime, int status) {
        throw new ExitException(status);
    }
}
