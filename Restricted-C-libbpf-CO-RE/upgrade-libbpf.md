Steps to install most recent version of libbpf

At time of writing, the most recent version of libbpf is 1.6.2, so we'll use that.

    Uninstall the existing version of libbpf. The quick-and-easy way to do so is to run locate pkgconfig | grep libbpf (you may have to run sudo apt install plocate), find all current instances of libbpf.pc, and remove them manually.

    Download the most recent source of libbpf. You can find the releases here: https://github.com/libbpf/libbpf/releases. Download the source code for the most recent version and extract it into a directory of your choice.

    Build the library. Navigate into the src folder of the extracted archive and run make and then make install (these may or may not need to be run as sudo commands).

    Update the necessary PATHs. Open your ~/.bashrc file (i.e. nano ~/.bashrc), and at the end of the file, add the following lines: export PKG_CONFIG_PATH=/usr/lib64/pkgconfig/:$PKG_CONFIG_PATH and export LD_LIBRARY_PATH=/usr/lib64:$LD_LIBRARY_PATH . This ensures that both the linker and pkg-config can find the newly-created library files.

    Update the libbpf and LD config files. Run the following two commands: echo "/usr/lib64" | sudo tee /etc/ld.so.conf.d/libbpf.conf and sudo ldconf .

