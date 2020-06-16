#!/usr/bin/env python
"""
ESP8266 firmware parser

Very hacky at the moment. This logic is based on a quick reading of the
following sources:
    * https://github.com/espressif/esptool/wiki/Firmware-Image-Format
    * https://richard.burtons.org/2015/05/17/decompiling-the-esp8266-boot-loader-v1-3b3/
    * https://boredpentester.com/reversing-esp8266-firmware-part-3/ (that whole
      series really)

These firmware dumps seem to contain multiple binaries. So we have a rudimentary
heuristic to find a couple binaries, which we pass back in a list to the
binaryview to present to the user as options.
"""

import binascii
import struct

from binaryninja import BinaryViewType
from binaryninja.enums import SegmentFlag

class InvalidFormat(Exception):
    pass

class ESPSegment:
    header_fmt = "<II"

    def __init__(self, load_address, size, outer_size, data_bv_offset):
        self.outer_size = outer_size
        self.load_address = load_address
        self.size = size
        self.data_bv_offset = data_bv_offset

    def __repr__(self):
        return f"""ESPSegment(outer_size={hex(self.outer_size)},
load_address={hex(self.load_address)},
size={hex(self.size)},
data_bv_offset={hex(self.data_bv_offset)})
"""
    def load(self, bv, parent_bv, outer_entry_point=None):
        if outer_entry_point is None or not (
                self.load_address <=
                outer_entry_point <=
                self.load_address + self.size):
            permissions = (SegmentFlag.SegmentContainsCode |
                           SegmentFlag.SegmentContainsData |
                           SegmentFlag.SegmentReadable     |
                           SegmentFlag.SegmentWritable     |
                           SegmentFlag.SegmentExecutable)
        else:
            permissions = (SegmentFlag.SegmentContainsCode |
                           SegmentFlag.SegmentContainsData |
                           SegmentFlag.SegmentReadable     |
                           SegmentFlag.SegmentExecutable)

        bv.add_auto_segment(self.load_address, self.size,
                            self.data_bv_offset, self.size,
                            permissions)

    @classmethod
    def parse(cls, bv, bv_offset):
        header_size = struct.calcsize(cls.header_fmt)
        header = bv.read(bv_offset + 0, header_size)
        if len(header) < header_size:
            raise InvalidFormat("Could not read Segment Header")
        load_address, seg_size = struct.unpack(cls.header_fmt, header)

        return cls(
            outer_size=header_size + seg_size,
            load_address=load_address,
            size=seg_size,
            data_bv_offset=bv_offset + header_size)

class E9File:
    name = "Raw(E9)"
    header_fmt = "<BBBBI"
    def __init__(self, bv_offset, magic, segment_count, flash_interface,
                 flash_cfg, entry_point, data_bv_offset, outer_size):
        self.bv_offset = bv_offset
        self.magic = magic
        self.segment_count = segment_count
        self.flash_interface = flash_interface
        self.flash_cfg = flash_cfg
        self.entry_point = entry_point
        print("entry point:", hex(entry_point))
        self.data_bv_offset = data_bv_offset
        self.outer_size = outer_size
        self.segments = []

    def __repr__(self):
        return f"""E9File(bv_offset={hex(self.bv_offset)},
magic={hex(self.magic)},
segment_count={self.segment_count},
flash_interface={hex(self.flash_interface)},
flash_cfg={hex(self.flash_cfg)},
entry_point={hex(self.entry_point)},
data_bv_offset={hex(self.data_bv_offset)},
outer_size={hex(self.outer_size)},
segments={repr(self.segments)})
"""

    def _segments_size(self):
        return sum(i.outer_size for i in self.segments)

    def load(self, bv, parent_bv, outer_entry_point=None):
        for seg in self.segments:
            seg.load(bv, parent_bv, outer_entry_point)
        bv.entry_addr = self.entry_point

    @classmethod
    def parse(cls, bv, bv_offset):
        header_size = struct.calcsize(cls.header_fmt)
        header = bv.read(bv_offset + 0, header_size)
        if len(header) < header_size:
            raise InvalidFormat("Could not read E9 Header")

        (magic, seg_count, flash_interface, flash_cfg,
         entry_point) = struct.unpack(cls.header_fmt, header)

        if magic != 0xe9:
            raise InvalidFormat("Invalid magic")

        f = cls(bv_offset=bv_offset,
                magic=magic,
                segment_count=seg_count,
                flash_interface=flash_interface,
                flash_cfg=flash_cfg,
                entry_point=entry_point,
                data_bv_offset=bv_offset + header_size,
                outer_size=None # will fill in below
                )

        for _ in range(seg_count):
            f.segments.append(ESPSegment.parse(bv, bv_offset + header_size + f._segments_size()))

        f.outer_size = header_size + f._segments_size()

        return f

class EAFile:
    name = "Bootloaded(EA)"
    header_fmt = "<BBBBIII"
    def __init__(self, bv_offset, magic1, magic2, config, entry_point,
                 text_length, data_bv_offset, outer_size):
        self.bv_offset = bv_offset
        self.magic1 = magic1
        self.magic2 = magic2
        self.config = config
        self.entry_point = entry_point
        print("ENTRY_POINT:", entry_point)
        self.text_length = text_length
        self.data_bv_offset = data_bv_offset
        self.outer_size = outer_size
        self.e9file = None

    def __repr__(self):
        return f"""EAFile(bv_offset={hex(self.bv_offset)},
magic1={hex(self.magic1)},
magic2={self.magic2},
config={hex(self.config[0])} {hex(self.config[1])},
entry_point={hex(self.entry_point)},
text_length={hex(self.text_length)},
data_bv_offset={hex(self.data_bv_offset)},
outer_size={hex(self.outer_size)},
e9file={repr(self.e9file)})
"""

    def load(self, bv, parent_bv):
        bv.add_auto_segment(0x1000 + self.data_bv_offset, self.text_length,
                            self.data_bv_offset, self.text_length,
                            (SegmentFlag.SegmentContainsCode |
                             SegmentFlag.SegmentContainsData |
                             SegmentFlag.SegmentDenyWrite    |
                             SegmentFlag.SegmentReadable     |
                             SegmentFlag.SegmentExecutable))
        self.e9file.load(bv, parent_bv, self.entry_point)
        bv.entry_addr = self.entry_point

    @classmethod
    def parse(cls, bv, bv_offset):
        header_size = struct.calcsize(cls.header_fmt)
        header = bv.read(bv_offset + 0, header_size)
        if len(header) < header_size:
            raise InvalidFormat("Could not read EA Header")

        config = [None, None]
        (magic1, magic2, config[0], config[1], entry_point, unused, text_length
         ) = struct.unpack(cls.header_fmt, header)

        if magic1 != 0xea:
            raise InvalidFormat("Invalid magic")

        f = cls(bv_offset=bv_offset,
                magic1=magic1,
                magic2=magic2,
                config=config,
                entry_point=entry_point,
                text_length=text_length,
                data_bv_offset=bv_offset+header_size,
                outer_size=None # will fill in below
                )

        f.e9file = E9File.parse(bv, f.data_bv_offset + text_length)

        f.outer_size = header_size + text_length + f.e9file.outer_size

        return f

class AppendedData:
    name = "AppendedData"
    def __init__(self, length, data_bv_offset):
        self.length = length
        self.data_bv_offset = self.bv_offset = data_bv_offset
        self.outer_size = length

    def __repr__(self):
        return f"""AppendedData(length={hex(self.length)},
data_bv_offset={hex(self.data_bv_offset)})
"""

    def load(self, bv, parent_bv):
        bv.add_auto_segment(0, self.length,
                            self.data_bv_offset, self.length,
                            (SegmentFlag.SegmentContainsCode |
                             SegmentFlag.SegmentContainsData |
                             SegmentFlag.SegmentReadable     |
                             SegmentFlag.SegmentWritable     |
                             SegmentFlag.SegmentExecutable))

    @classmethod
    def parse(cls, bv, bv_offset):
        return AppendedData(bv.end-bv_offset, bv_offset)


def parse_firmware(bv):
    firmware_options = []
    try:
        f = E9File.parse(bv, 0)
        firmware_options.append(f)
    except InvalidFormat:
        print("Could not find starting E9File")
        return

    if f.outer_size > 0x1000:
        return
    try:
        f2 = EAFile.parse(bv, 0x1000)
        firmware_options.append(f2)
    except InvalidFormat:
        print("Could not find following EAFile")

    try:
        f3 = E9File.parse(bv, 0x1000)
        firmware_options.append(f3)
    except InvalidFormat:
        print("Could not find following E9File")

    next_addr = firmware_options[-1].bv_offset + firmware_options[-1].outer_size 
    if (next_addr < bv.end):
        firmware_options.append(AppendedData.parse(bv, next_addr))

    return firmware_options

def main():
    TEST_FIRMWARE = ""
    bv = BinaryViewType['Raw'].open(TEST_FIRMWARE)
    if not bv:
        print("Could not open bv")
        return
    print()
    print()
    data = parse_firmware(bv)
    print(data)

if __name__ == '__main__':
    main()
