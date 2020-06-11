**This is not an officially supported Google product.**

# Loading Extension into Eclipse for Development
* Install Java
  * Tested verison: `jdk-11.0.2`
* Install eclipse from [eclipse.org](https://www.eclipse.org/downloads/)
  * Tested version: `2020-03`
* Install Ghidra
  * Tested version: `ghidra_9.1.2_PUBLIC`
  * Ghidra must be started atleast once.
* Install Ghidra Eclipse extension, follow instructions [here](https://ghidra-sre.org/InstallationGuide.html#Extensions)
* Checkout git project `ghidra-nsis-extension` to local directory
* In eclipse's `File` menu, select `New->Java Project`
* Un-select `Use default location` and navigate to the `nsis` folder in the git
  checkout location
  * `ghidra-nsis-extension/nsis`
* Press `Next`
* Un-select `Create module-info.java file`
* Press `Finish`
  * There will be build errors
* In the `GhidraDev` menu of Eclipse, use the `Link Ghidra...` and enter the path to the Ghidra binary install location
  * Select the Java project `nsis` just created
  * If there is Java conflict probably best to keep the current Java by pressing
    `Cancel`
  * Build errors should be resolved
* You can test that everything is working in your project by selecting the `Run`menu, then `Run As` and `Ghidra`.
* A new instance of Ghidra should be loaded, if you import an NSIS executable file, should see the 'Nsis' Format suggestion in the first entry of the import dialog.

# Updating The Disassembler Specification

* If a change is made to Nsis.slaspec, it needs to be reprocessed by the sleight utility. Example commande: `<ghidra installer folder>/support/sleigh data/languages/Nsis.slaspec`
* The newly generated files then need to be moved to the `<ghidra install folder>/Ghidra/Processors/Nsis/`folder.

# Build extension from the command line

* Install [gradle](https://gradle.org/)
  * Tested version: `5.0`
* Execute the command from nsis folder
```
$ gradle -PGHIDRA_INSTALL_DIR=<path_to_ghidra>
```
* Zip file will be created in the `dist` folder

# Installing extension

* Open Ghidra and select `File->Install Extensions...`
* Press the `plus` icon in the top right and find the extension zip file
* Press `OK` you will be prompted to restart Ghidra

# Resources

## Ghidra
* https://ghidra.re/courses/languages/html/sleigh.html
* https://www.reddit.com/r/ReverseEngineering/comments/bupmxu/implementing_a_new_cpu_architecture_for_ghidra/
* https://github.com/VGKintsugi/Ghidra-SegaSaturn-Processor
* https://www.reddit.com/r/ghidra/comments/bhhrt0/quick_guide_to_creating_a_processor_in_ghidra/
* https://wrongbaud.github.io/writing-a-ghidra-loader/

## NSIS
* NSIS home: https://nsis.sourceforge.io/
* Data structures for NSIS file format: https://sourceforge.net/p/nsis/code/HEAD/tree/NSIS/trunk/Source/exehead/fileform.h
* IDA plugin for NSIS files: https://github.com/isra17/nrs
