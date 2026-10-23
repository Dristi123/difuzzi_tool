package difuzzi.rt;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;
import org.objectweb.asm.*;

/**
 * Offline bytecode rewriting of the compiled programs A and B (run once per program, before fuzzing).
 *
 * Always: calls to System.exit / Runtime.exit / Runtime.halt throw {@link Exit.ExitException} instead,
 * so a program cannot end the fuzzer.
 *
 * With reset (file level): every class gets a static method __difuzzi_reset() that restores its static
 * fields and re-runs its static initializer, so each run of main() starts from a fresh state even though
 * the classes are loaded (and instrumented for coverage) only once. The original static initializer is
 * renamed to __difuzzi_clinit; the new one registers the class with {@link Statics} and calls it.
 *
 * Usage: java difuzzi.rt.Rewriter IN_DIR OUT_DIR RESET(true|false)
 */
public final class Rewriter {
    static final String CLINIT = "__difuzzi_clinit", RESET = "__difuzzi_reset";

    public static void main(String[] args) throws IOException {
        Path in = Paths.get(args[0]), out = Paths.get(args[1]);
        boolean reset = Boolean.parseBoolean(args[2]);
        try (Stream<Path> files = Files.walk(in)) {
            for (Path p : (Iterable<Path>) files::iterator) {
                if (Files.isDirectory(p)) continue;
                Path target = out.resolve(in.relativize(p));
                Files.createDirectories(target.getParent());
                byte[] bytes = Files.readAllBytes(p);
                Files.write(target, p.toString().endsWith(".class") ? transform(bytes, reset) : bytes);
            }
        }
    }

    static final class StaticField {
        final String name, desc;
        StaticField(String name, String desc) { this.name = name; this.desc = desc; }
    }

    static byte[] transform(byte[] bytes, boolean reset) {
        ClassReader cr = new ClassReader(bytes);
        // Pass 1: which static fields to restore, and whether there is a static initializer.
        List<StaticField> fields = new ArrayList<>();
        boolean[] hasClinit = {false};
        int[] access = {0};
        cr.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override public void visit(int v, int acc, String n, String s, String sup, String[] itf) { access[0] = acc; }
            @Override public FieldVisitor visitField(int acc, String n, String d, String s, Object value) {
                if ((acc & Opcodes.ACC_STATIC) != 0 && value == null) fields.add(new StaticField(n, d));
                return null;
            }
            @Override public MethodVisitor visitMethod(int acc, String n, String d, String s, String[] e) {
                if (n.equals("<clinit>")) hasClinit[0] = true;
                return null;
            }
        }, ClassReader.SKIP_CODE);
        boolean eligible = reset && (access[0] & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ENUM | Opcodes.ACC_MODULE)) == 0;

        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        String[] owner = {null};
        cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
            @Override public void visit(int v, int acc, String n, String s, String sup, String[] itf) {
                owner[0] = n;
                super.visit(v, acc, n, s, sup, itf);
            }
            @Override public FieldVisitor visitField(int acc, String n, String d, String s, Object value) {
                if (eligible && (acc & Opcodes.ACC_STATIC) != 0 && value == null) acc &= ~Opcodes.ACC_FINAL;
                return super.visitField(acc, n, d, s, value);
            }
            @Override public MethodVisitor visitMethod(int acc, String n, String d, String s, String[] e) {
                if (eligible && n.equals("<clinit>")) {
                    n = CLINIT;
                    acc = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
                }
                return new ExitRedirect(super.visitMethod(acc, n, d, s, e));
            }
            @Override public void visitEnd() {
                if (eligible) {
                    MethodVisitor mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
                    mv.visitCode();
                    mv.visitLdcInsn(Type.getObjectType(owner[0]));
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "difuzzi/rt/Statics", "register", "(Ljava/lang/Class;)V", false);
                    if (hasClinit[0]) mv.visitMethodInsn(Opcodes.INVOKESTATIC, owner[0], CLINIT, "()V", false);
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(0, 0);
                    mv.visitEnd();

                    mv = super.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC, RESET, "()V", null, null);
                    mv.visitCode();
                    for (StaticField f : fields) {
                        pushDefault(mv, f.desc);
                        mv.visitFieldInsn(Opcodes.PUTSTATIC, owner[0], f.name, f.desc);
                    }
                    if (hasClinit[0]) mv.visitMethodInsn(Opcodes.INVOKESTATIC, owner[0], CLINIT, "()V", false);
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(0, 0);
                    mv.visitEnd();
                }
                super.visitEnd();
            }
        }, 0);
        return cw.toByteArray();
    }

    static void pushDefault(MethodVisitor mv, String desc) {
        switch (desc.charAt(0)) {
            case 'J': mv.visitInsn(Opcodes.LCONST_0); break;
            case 'F': mv.visitInsn(Opcodes.FCONST_0); break;
            case 'D': mv.visitInsn(Opcodes.DCONST_0); break;
            case 'L': case '[': mv.visitInsn(Opcodes.ACONST_NULL); break;
            default: mv.visitInsn(Opcodes.ICONST_0);   // int, short, byte, char, boolean
        }
    }

    /** Replaces calls that would end the JVM with calls that throw. */
    static final class ExitRedirect extends MethodVisitor {
        ExitRedirect(MethodVisitor mv) { super(Opcodes.ASM9, mv); }

        @Override public void visitMethodInsn(int op, String owner, String name, String desc, boolean itf) {
            if (op == Opcodes.INVOKESTATIC && owner.equals("java/lang/System") && name.equals("exit") && desc.equals("(I)V")) {
                super.visitMethodInsn(Opcodes.INVOKESTATIC, "difuzzi/rt/Exit", "exit", "(I)V", false);
            } else if (op == Opcodes.INVOKEVIRTUAL && owner.equals("java/lang/Runtime")
                    && (name.equals("exit") || name.equals("halt")) && desc.equals("(I)V")) {
                super.visitMethodInsn(Opcodes.INVOKESTATIC, "difuzzi/rt/Exit", "runtimeExit", "(Ljava/lang/Runtime;I)V", false);
            } else {
                super.visitMethodInsn(op, owner, name, desc, itf);
            }
        }
    }
}
