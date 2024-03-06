# GDB Python script that defines setup_session and restore_regs GDB custom commands

import gdb
import subprocess
import socket
import os
import json
from contextlib import closing
from pty import STDERR_FILENO, STDOUT_FILENO

# Define the specific registers we're interested in
registers_of_interest = [
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 
    'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 
    'r12', 'r13', 'r14', 'r15', 'rip', 'eflags', 
    'cs', 'ss', 'ds', 'es', 'fs', 'gs'
]

# Global dictionaries to store register values from corefile and live process
core_registers = {}
live_registers = {}

# Current working directory
cwd = os.getcwd()

# Global variable to store Crash server path
lldb_crash_server_path = None

# Check if LLDB_CRASH_SERVER_PATH environment variable is set
if "LLDB_CRASH_SERVER_PATH" in os.environ:
    lldb_crash_server_path = os.environ["LLDB_CRASH_SERVER_PATH"]
else:
    print("The $lldb_crash_server_path variable is not set.\n"
          "To set it, use one of the following methods:\n"
          "1. In GDB: set $lldb_crash_server_path=\"/path/to/lldb-crash-server\"\n"
          "2. In your shell: export LLDB_CRASH_SERVER_PATH=/path/to/lldb-crash-server")


class GDBSessionSetup(gdb.Command):
    """Set up GDB session: load binary and corefile, save and restore registers, start crash server and establish connection."""

    def __init__(self):
        super(GDBSessionSetup, self).__init__(
            "setup_session", gdb.COMMAND_USER, gdb.COMPLETE_FILENAME
        )

    def invoke(self, arg, from_tty):
        global lldb_crash_server_path, cwd

        args = arg.split()
        if len(args) != 2:
            print("Usage: setup_session <binary> <corefile>")
            return
        
        gdb_settings = self.get_gdb_setting()

        binary, corefile = args
        gdb.execute(f"file {binary}")
        gdb.execute(f"core {corefile}")
        gdb.execute("set exec-file-mismatch off")

        # Read and save corefile registers
        self.save_registers("core")

        # Check if $lldb_crash_server_path convenience variable is set
        crash_server_gdb_var = gdb.parse_and_eval("$lldb_crash_server_path")
        if crash_server_gdb_var.type.code != gdb.TYPE_CODE_VOID:
            lldb_crash_server_path = str(crash_server_gdb_var).strip('"')

        if lldb_crash_server_path is None:
            print("Crash server path is not set.")
            return
        
        # Create uncore json file
        self.create_json_file(corefile, binary, gdb_settings)

        # Create a named pipe
        pipe_path = os.path.join(cwd, "gdb_lldb_signal_pipe")
        self.create_pipe(pipe_path)

        # Start Crash server as a subprocess
        port = self.find_free_port()
        subprocess.Popen([lldb_crash_server_path, "g", f"localhost:{port}", binary,
                         "--uncore-json", "./uncore.json"], stdout=STDOUT_FILENO, stderr=STDERR_FILENO)

        # Read from a named pipe (waiting for a signal from Crash server)
        self.read_from_pipe(pipe_path)

        # Connect to remote target
        gdb.execute(f"target remote localhost:{port}")

        # Read and save live process registers
        self.save_registers("live")

        # Automatically restore corefile registers
        gdb.execute(f"restore_regs core")

        print("Session setup complete.")

    # Depending on the source parameter, save corefile or live process register values
    def save_registers(self, source):
        global core_registers, live_registers
        reg_values = core_registers if source == "core" else live_registers

        for reg in registers_of_interest:
            reg_values[reg] = gdb.parse_and_eval(f"${reg}")

        print(
            f"{source.capitalize()} registers saved: {', '.join([f'{reg}={reg_values[reg]}' for reg in registers_of_interest])}"
        )

    def find_free_port(self):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(('localhost', 0))
            return s.getsockname()[1]

    def create_json_file(self, core_path, binary_path, gdb_settings):
        global cwd

        # Set the uncore output and json file path
        output_path = os.path.join(cwd, "outdir")
        json_path = os.path.join(cwd, "uncore.json")

        data = {
            "core": core_path,
            "binos_root": "",
            "entry_point": "main",
            "prog": binary_path,
            "pid": "",
            "additional_resources": "",
            "custom_o_file": [],
            "output_directory": output_path,
            "hot_patch": {
            },
            "gdbparse": {
                "gdb": "gdb",
                "args": [
                    binary_path,
                    core_path
                ],
                "kwargs": {
                }
            }
        }

        if len(gdb_settings) > 1:
            # Create a gdb script with all commands from gdb_settings
            script_path = os.path.join(cwd, "gdb_uncore.script")
            with open(script_path, "w") as script_file:
                for cmd in gdb_settings:
                    script_file.write(cmd + "\n")
            data["gdbparse"]["kwargs"]["-x"] = script_path
        elif len(gdb_settings) == 1:
            data["gdbparse"]["kwargs"]["-ex"] = gdb_settings[0]

        # Convert the JSON data to a string
        json_str = json.dumps(data, indent=4)

        # Write the JSON string to a file in the current working directory
        try:
            with open(json_path, "w") as json_file:
                json_file.write(json_str)
            print(f"JSON file successfully created at: {json_path}")
        except Exception as e:
            print(f"Error: {e}")

    # Get gdb session settings
    def get_gdb_setting(self):
        gdb_settings = []

        # Retrieve the process sysroot setting
        sysroot_setting = gdb.execute("show sysroot", to_string=True)
        if sysroot_setting.startswith("The current system root is"):
            sysroot_path = sysroot_setting.split('"')[1].strip()
            if sysroot_path != "target:" and sysroot_path != "":
                gdb_settings.append(f"set sysroot {sysroot_path}")

        # Retrieve and process solib-search-path setting
        solib_search_path_setting = gdb.execute("show solib-search-path", to_string=True)
        if solib_search_path_setting.startswith("The search path for loading non-absolute shared library symbol files is"):
            solib_search_path = solib_search_path_setting.split(' is ')[1].strip()
            if solib_search_path != "." and solib_search_path != "":
                gdb_settings.append(f"set solib-search-path {solib_search_path}")

        return gdb_settings

    # Create a named FIFO pipe
    def create_pipe(self, pipe_path):
        try:
            os.mkfifo(pipe_path)
        except OSError as e:
            print(f"Error creating the pipe: {e}")

    # Read from the named pipe
    def read_from_pipe(self, pipe_path):
        try:
            with open(pipe_path, "r") as pipe:
                message = pipe.read()
                print(message)
        except Exception as e:
            print(f"Error reading from the pipe: {e}")


class RestoreRegisters(gdb.Command):
    """Restore registers to saved values from either corefile or live process."""

    def __init__(self):
        super(RestoreRegisters, self).__init__(
            "restore_regs", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if arg not in ["core", "live"]:
            print("Usage: restore_regs <core|live>")
            return

        registers = core_registers if arg == "core" else live_registers

        if not registers:
            print(f"No registers saved for {arg}.")
            return

        # Restore the registers
        for reg in registers_of_interest:
            gdb.execute(f"set ${reg} = {int(registers[reg])}")

        print(f"Registers restored from {arg}.")


# Register the commands with GDB
GDBSessionSetup()
RestoreRegisters()
