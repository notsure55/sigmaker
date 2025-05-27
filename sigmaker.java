//Create signatures for pattern scannning
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

public class sigmaker extends GhidraScript {

    public void run() throws Exception {
        // first time coding in java so if my code sucks or could be done better thats on me
        var range = currentSelection.getFirstRange();
        var address_view = new AddressSet(range);

        var listing = currentProgram.getListing();
        var ins = listing.getInstructions(address_view, true);

        String sig = new String("Signature: ");

        for (var i : ins) {
            byte[] i_bytes = i.getBytes();
            boolean[] is_wildcard = new boolean[i_bytes.length];

            var proto = i.getPrototype();

            for (int j = 0; j < proto.getNumOperands(); ++j) {
                int optype = i.getOperandType(j);

                // check if operand is dynamic or address
                if ((optype & OperandType.DYNAMIC) != 0 || (optype & OperandType.ADDRESS) != 0) {
                    var mask = proto.getOperandValueMask(j);
                    byte[] mask_bytes = mask.getBytes();
                    // we get byte mask and check all bytes to see which ones are not 0
                    for (int k = 0; k < mask_bytes.length; ++k) {
                        if (mask_bytes[k] != 0) {
                            is_wildcard[k] = true;
                        }
                    }
                }
            }

            for (int k = 0; k < i_bytes.length; ++k) {
                if (is_wildcard[k]) {
                    sig += "?? ";
                } else {
                    sig += String.format("%02x ", i_bytes[k]);
                }
            }
        }

        println(sig);
    }
}
