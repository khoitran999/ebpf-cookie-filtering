from bcc import BPF
from config import config
import utils.helper_functions as helpers
import os

class PacketAnalyzer:
    def __init__(self):
        self.function_name = config['function_name']
        self.interface = config['network_interface']
        self.packet_count_map = None

        kernel_headers = f"/lib/modules/{os.uname().release}/build"

        # Define compiler flags
        cflags = [
            f"-I{kernel_headers}/include",
            f"-I{kernel_headers}/include/uapi",
            f"-I{kernel_headers}/arch/{os.uname().machine}/include",
            "-I/usr/include",            # Include standard include directories
            "-I/usr/include/bcc",        # Include the directory with BCC's helpers.h
            "-D__KERNEL__",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
        ]

        self.bpf = BPF(
            src_file=config['ebpf_program'],
            cflags=cflags
        )



    def attach(self):
        function_name = str(self.function_name)
        fn = self.bpf.load_func(function_name, BPF.XDP)
        self.bpf.attach_xdp(self.interface, fn, 0)
        self.packet_count_map = self.bpf.get_table("packet_count")

    def get_packet_count(self):
        count = 0
        for key, value in self.packet_count_map.items():
            count += value.value
        self.packet_count_map.clear()
        return count

    def cleanup(self):
        self.bpf.remove_xdp(self.interface, 0)
        self.bpf.cleanup()

