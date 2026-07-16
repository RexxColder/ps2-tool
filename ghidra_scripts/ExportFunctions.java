// ExportFunctions.java - Export functions and strings from Ghidra to CSV
// @category Analysis
// Usage: analyzeHeadless ... -postScript ExportFunctions.java <output_dir>
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.io.*;

public class ExportFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Get output directory from script arguments or default to project dir
        String outDir = ".";
        if (getScriptArgs().length > 0) {
            outDir = getScriptArgs()[0];
        } else {
            // Try to get from Ghidra project location
            File projectDir = currentProgram.getExecutablePath() != null 
                ? new File(currentProgram.getExecutablePath()).getParentFile() 
                : new File(".");
            if (projectDir.exists()) outDir = projectDir.getAbsolutePath();
        }
        
        File outDirFile = new File(outDir);
        if (!outDirFile.exists()) outDirFile.mkdirs();
        
        println("Exporting to: " + outDir);
        
        // Export functions
        File funcFile = new File(outDir, "functions.csv");
        PrintWriter fw = new PrintWriter(new FileOutputStream(funcFile));
        fw.println("address,name,size,is_named,subsystem");
        
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (funcs.hasNext()) {
            Function func = funcs.next();
            long addr = func.getEntryPoint().getOffset();
            String name = func.getName();
            long size = func.getBody().getNumAddresses();
            boolean isNamed = !name.startsWith("sub_") && !name.startsWith("FUN_");
            String subsystem = "";
            String lowerName = name.toLowerCase();
            if (lowerName.contains("sce") || lowerName.contains("pad") || lowerName.contains("mc") ||
                lowerName.contains("cd") || lowerName.contains("dma") || lowerName.contains("vif") ||
                lowerName.contains("gif") || lowerName.contains("mpeg") || lowerName.contains("spu") ||
                lowerName.contains("iop") || lowerName.contains("vpu") || lowerName.contains("vu")) {
                subsystem = "SDK";
            } else if (lowerName.contains("d3d") || lowerName.contains("render") || lowerName.contains("graph")) {
                subsystem = "GRAPHICS";
            } else if (lowerName.contains("audio") || lowerName.contains("sound") || lowerName.contains("music")) {
                subsystem = "AUDIO";
            } else if (lowerName.contains("net") || lowerName.contains("socket") || lowerName.contains("http")) {
                subsystem = "NETWORK";
            } else if (lowerName.contains("thread") || lowerName.contains("sema") || lowerName.contains("mutex")) {
                subsystem = "THREADING";
            } else if (isNamed) {
                subsystem = "NAMED";
            } else {
                subsystem = "UNKNOWN";
            }
            fw.printf("0x%08X,%s,%d,%b,%s\n", addr, name, size, isNamed, subsystem);
            count++;
        }
        fw.close();
        println("Exported " + count + " functions to " + funcFile.getAbsolutePath());
        
        // Export strings
        File strFile = new File(outDir, "strings.csv");
        PrintWriter sw = new PrintWriter(new FileOutputStream(strFile));
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
        println("Exported " + strCount + " strings to " + strFile.getAbsolutePath());
    }
}
