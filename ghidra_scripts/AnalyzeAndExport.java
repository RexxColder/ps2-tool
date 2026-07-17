// AnalyzeAndExport.java - Export functions with SDK detection + strings
// @category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.io.*;

public class AnalyzeAndExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outDir = getScriptArgs().length > 0 ? getScriptArgs()[0] : ".";
        new File(outDir).mkdirs();

        // Export functions
        PrintWriter fw = new PrintWriter(new FileOutputStream(new File(outDir, "functions.csv")));
        fw.println("address,name,size,is_named,is_sdk,subsystem");

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int funcCount = 0, sdkCount = 0;

        while (funcs.hasNext()) {
            Function func = funcs.next();
            if (func.isThunk() || func.isExternal()) continue;

            long addr = func.getEntryPoint().getOffset();
            String name = func.getName();
            long size = func.getBody().getNumAddresses();
            boolean isNamed = !name.startsWith("sub_") && !name.startsWith("FUN_") && !name.startsWith("thunk_");
            boolean isSdk = isSdkFunc(name);

            String subsystem = isSdk ? "SDK" : (isNamed ? "NAMED" : "UNKNOWN");
            fw.printf("0x%08X,%s,%d,%b,%b,%s\n", addr, name, size, isNamed, isSdk, subsystem);
            funcCount++;
            if (isSdk) sdkCount++;
        }
        fw.close();

        // Export strings
        PrintWriter sw = new PrintWriter(new FileOutputStream(new File(outDir, "strings.csv")));
        sw.println("address,text,category");
        int strCount = 0;
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext()) {
            Data d = data.next();
            if (d.hasStringValue()) {
                String val = d.getDefaultValueRepresentation();
                if (val != null && val.length() > 2) {
                    val = val.replace("\"", "").replace("\n", " ").replace("\r", "");
                    sw.printf("0x%08X,\"%s\",\"OTHER\"\n", d.getAddress().getOffset(), val);
                    strCount++;
                }
            }
        }
        sw.close();

        println("Functions: " + funcCount + " (SDK: " + sdkCount + ")");
        println("Strings: " + strCount);
    }

    private boolean isSdkFunc(String name) {
        if (name == null) return false;
        String l = name.toLowerCase();
        return l.startsWith("sce") || l.startsWith("pad") || l.startsWith("mc") ||
               l.startsWith("cd") || l.startsWith("dma") || l.startsWith("vif") ||
               l.startsWith("gif") || l.startsWith("mpeg") || l.startsWith("spu") ||
               l.startsWith("iop") || l.startsWith("vu") || l.startsWith("sif") ||
               l.startsWith("gs") || l.contains("thread") || l.contains("sema") ||
               l.contains("event");
    }
}
