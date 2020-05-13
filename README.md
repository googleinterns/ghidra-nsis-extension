# Loading Extension into Eclipse for Development

* Install eclipse from [eclipse.org](https://www.eclipse.org/downloads/)
* Install Ghidra Eclipse extension, follow instructions [here](https://ghidra-sre.org/InstallationGuide.html#Extensions)
* In eclipse's `File` menu, select `Import...` 
* Select `Projects from Git` then select the git checkout location.
* If there are build errors, you might need to fix your build path by right clicking on the project, then `Build Path` and `Configure Build Path` 
* In the `GhidraDev`menu of Eclipse, use the `Link Ghidra...` and enter the path to the Ghidra binary install location.
* You can test that everything is working in your project by selecting the `Run`menu, then `Run As` and `Ghidra`.
* A new instance if Ghidra should be loaded, if you import an NSIS executable file, should see the 'Nsis' Format suggestion in the first entry of the import dialog.

# Updating The Disassembler Specification

* If a change is made to Nsis.slaspec, it needs to be reprocessed by the sleight utility. Example commande: `<ghidra installer folder>/support/sleigh data/languages/Nsis.slaspec`
* The newly generated files then need to be moved to the `<ghidra install folder>/Ghidra/Processors/Nsis/`folder.


# Resources

* https://ghidra.re/courses/languages/html/sleigh.html
* https://www.reddit.com/r/ReverseEngineering/comments/bupmxu/implementing_a_new_cpu_architecture_for_ghidra/
* https://github.com/VGKintsugi/Ghidra-SegaSaturn-Processor
* https://www.reddit.com/r/ghidra/comments/bhhrt0/quick_guide_to_creating_a_processor_in_ghidra/
* https://wrongbaud.github.io/writing-a-ghidra-loader/
