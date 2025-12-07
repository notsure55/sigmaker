//find signatures
//@author notsure55
//@category Listing
//@keybinding
//@menupath
//@toolbar
//@runtime Java

// ghidra api imports
import ghidra.app.script.GhidraScript;
import ghidra.program.model.sourcemap.*;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.ISF.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import java.util.List;
import java.util.ArrayList;

/* https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/OperandType.html
   Used for getting operand types and build are bitmask for which ones are dynamic / addresses
   i.e var ytype = instruction.getOperandType(index);
*/
/* https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/InstructionPrototype.html
   var mask = getInstructionMask()
   byte[] mask_bytes = mask.getBytes();
*/
/*https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html#getBytes()
   used for grabbing bytes for evrery inteface that inherits from codeunit
*/
/* https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html
   used for grabbing the listing section of the program, so we can interact with the bytes
   and addresses associated with the selection that we are hovering
*/
/* https://ghidra.re/ghidra_docs/api/ghidra/program/util/ProgramSelection.html
   Used for grabbing current highlighted selection in listing.
   i.e currentSelection.getFirstRange()
*/

public class sigfinder extends GhidraScript {

    public List<Integer> parse_pattern(String pattern) {
        String[] tokens = pattern.split(" ");
        List<Integer> sig = new ArrayList<>();

        for (String t : tokens) {
            if (t.equals("??")) {
                sig.add(-1);
            } else {
                sig.add(Integer.parseInt(t, 16));
            }
        }

        return sig;
    }

    public void run() throws Exception {
        var listing = currentProgram.getListing();
        var ins = listing.getInstructions(true);

        String pattern = askString("Signature", "Enter your pattern:");
        List<Integer> sig = parse_pattern(pattern);

        int index = 0;
        Instruction first_ins = null;

        for (var i : ins) {
            byte[] bytes = i.getBytes();

            for (int b = 0; b < bytes.length; b++) {
                int want = sig.get(index);

                if (want != -1 && (bytes[b] & 0xFF) != want) {
                    index = 0;
                    continue;
                } else {
                    if (index == 0) {
                        first_ins = i;
                    }
                }

                index++;

                if (index == sig.size()) {
                    if (first_ins != null) {
                        println("Found sig at: " + first_ins.getAddress().toString());
                    }
                    index = 0;
                }
            }
        }
    }
}
