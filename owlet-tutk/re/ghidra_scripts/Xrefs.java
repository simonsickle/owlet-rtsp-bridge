import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import java.io.*;
// args: outfile addr...
public class Xrefs extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter w = new PrintWriter(new FileWriter(a[0]));
        for (int i = 1; i < a.length; i++) {
            Address t = toAddr(Long.parseLong(a[i].replace("0x",""), 16));
            w.println("## xrefs to " + t);
            for (Reference r : getReferencesTo(t)) {
                Function f = getFunctionContaining(r.getFromAddress());
                Instruction ins = getInstructionAt(r.getFromAddress());
                w.println("  " + r.getFromAddress() + " " + r.getReferenceType() + " in " + (f==null?"?":f.getName()+"@"+f.getEntryPoint()) + "  " + ins);
            }
        }
        w.close();
    }
}
