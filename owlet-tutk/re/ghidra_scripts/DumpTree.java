import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.util.*;
import java.io.*;

// args: outfile depth name_or_addr...
public class DumpTree extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter w = new PrintWriter(new FileWriter(a[0]));
        int depth = Integer.parseInt(a[1]);
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Deque<Object[]> q = new ArrayDeque<>();
        Set<Address> seen = new HashSet<>();
        for (int i = 2; i < a.length; i++) {
            Function f = null;
            if (a[i].startsWith("0x")) f = getFunctionContaining(toAddr(Long.parseLong(a[i].substring(2), 16)));
            else { List<Function> l = getGlobalFunctions(a[i]); if (!l.isEmpty()) f = l.get(0); }
            if (f == null) { w.println("!! not found " + a[i]); continue; }
            q.add(new Object[]{f, 0});
        }
        while (!q.isEmpty()) {
            Object[] o = q.poll(); Function f = (Function) o[0]; int d = (Integer) o[1];
            if (!seen.add(f.getEntryPoint())) continue;
            if (f.isThunk() || f.isExternal()) continue;
            w.println("===== " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses() + " depth=" + d);
            DecompileResults r = di.decompileFunction(f, 120, monitor);
            if (r.decompileCompleted() && r.getDecompiledFunction() != null) w.println(r.getDecompiledFunction().getC());
            else w.println("!! decompile failed");
            if (d < depth) for (Function c : f.getCalledFunctions(monitor)) q.add(new Object[]{c, d + 1});
        }
        di.dispose(); w.close();
    }
}
