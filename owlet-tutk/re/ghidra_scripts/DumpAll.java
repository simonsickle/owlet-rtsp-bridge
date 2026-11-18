import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.*;
public class DumpAll extends GhidraScript {
    public void run() throws Exception {
        PrintWriter w = new PrintWriter(new FileWriter(getScriptArgs()[0]));
        DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isThunk() || f.isExternal()) continue;
            w.println("===== " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
            DecompileResults r = di.decompileFunction(f, 180, monitor);
            if (r.decompileCompleted() && r.getDecompiledFunction() != null) w.println(r.getDecompiledFunction().getC());
            else w.println("!! decompile failed");
            w.flush();
        }
        di.dispose(); w.close();
    }
}
