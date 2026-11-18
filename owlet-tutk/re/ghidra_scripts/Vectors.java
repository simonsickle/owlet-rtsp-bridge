import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import java.io.*;
import java.util.*;
// Runs vendor encode (0x116eac) and decode (0x117168) under p-code emulation. args: outfile
public class Vectors extends GhidraScript {
    static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02x",x));return s.toString();}
    EmulatorHelper emu;
    byte[] call(long fn, byte[] in, int total, int enc) throws Exception {
        long IN=0x20000000L, OUT=0x20010000L, SP=0x30080000L, TLS=0x40000000L, RET=0x50000000L;
        emu.writeMemory(toAddr(IN), Arrays.copyOf(in, 4096));
        emu.writeMemory(toAddr(OUT), new byte[4096]);
        emu.writeMemory(toAddr(TLS), new byte[256]);
        emu.writeRegister("sp", SP); emu.writeRegister("tpidr_el0", TLS);
        emu.writeRegister("x0", IN); emu.writeRegister("x1", OUT);
        emu.writeRegister("x2", total); emu.writeRegister("x3", enc);
        emu.writeRegister("x30", RET); emu.writeRegister("pc", fn);
        emu.setBreakpoint(toAddr(RET));
        Address cur = toAddr(fn);
        for (int guard=0; guard<64; guard++) {
            boolean ok = emu.run(cur, null, monitor);
            long pc = emu.getExecutionAddress().getOffset();
            if (pc == RET) break;
            ghidra.program.model.symbol.Symbol sym = getSymbolAt(toAddr(pc));
            String nm = sym==null?"":sym.getName();
            if (nm.contains("memcpy")) {
                long d=emu.readRegister("x0").longValue(), s2=emu.readRegister("x1").longValue(); int nn=emu.readRegister("x2").intValue();
                if (nn>0) emu.writeMemory(toAddr(d), emu.readMemory(toAddr(s2), nn));
                cur = toAddr(emu.readRegister("x30").longValue());
                emu.writeRegister("pc", cur.getOffset());
                continue;
            }
            throw new Exception("emu stop at "+emu.getExecutionAddress()+" sym="+nm+" "+emu.getLastError());
        }
        return emu.readMemory(toAddr(OUT), total);
    }
    public void run() throws Exception {
        emu = new EmulatorHelper(currentProgram);
        emu.writeMemory(toAddr(0x1502e0L), "Charlie is the d".getBytes("ASCII"));
        emu.writeMemory(toAddr(0x152230L), new byte[]{1});
        PrintWriter w = new PrintWriter(new FileWriter(getScriptArgs()[0]));
        Random r = new Random(1234);
        int[][] cases = new int[80][];
        int n=0;
        for (int l=1;l<=40;l++) cases[n++]=new int[]{l,l};
        for (int l: new int[]{48,63,64,65,88,100,127,128,200,255,256,1000,1400}) cases[n++]=new int[]{l,l};
        for (int[] c: new int[][]{{88,16},{200,16},{200,64},{200,48},{100,64},{1400,64},{20,16},{30,16},{64,48}}) cases[n++]=c;
        w.println("[");
        for (int i=0;i<n;i++){
            int total=cases[i][0], enc=cases[i][1];
            byte[] in=new byte[total]; r.nextBytes(in);
            byte[] e=call(0x116eacL,in,total,enc);
            byte[] d=call(0x117168L,e,total,enc);
            w.println(String.format(" {\"total\":%d,\"enc\":%d,\"plain\":\"%s\",\"encoded\":\"%s\",\"decoded\":\"%s\"}%s",total,enc,hex(in),hex(e),hex(d),i==n-1?"":","));
        }
        w.println("]"); w.close(); emu.dispose();
    }
}
