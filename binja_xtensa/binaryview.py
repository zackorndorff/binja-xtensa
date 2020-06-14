import json
import struct

from binaryninja import Architecture, BinaryView, Settings, Symbol
from binaryninja.enums import SectionSemantics, SymbolType

from .firmware_parser import parse_firmware

class ESPFirmware(BinaryView):
    name = "ESPFirmware"
    long_name = "ESP Firmware"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data):
        if data.read(0, 1) in [b'\xe9', b'\xea']:
            return True
        return False

    @classmethod
    def get_load_settings_for_data(cls, data):
        firmware_options = parse_firmware(data)

        ourEnum = ["option" + str(i) for i in range(len(firmware_options))]
        ourEnumDescriptions = [
            f"{i.name} at {hex(i.bv_offset)}"
            for i in firmware_options]

        setting =  f"""{{
            "title": "Which Firmware",
            "type": "string",
            "description": "Which of the binaries in this file do you want?",
            "enum": {json.dumps(ourEnum)},
            "enumDescriptions": {json.dumps(ourEnumDescriptions)},
            "default": {json.dumps(ourEnum[0])}
            }}
            """

        print(setting)

        load_settings = Settings("esp_bv_settings")
        assert load_settings.register_group("loader", "Loader")
        assert load_settings.register_setting("loader.esp.whichFirmware",
                                              setting)
        return load_settings

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_addr

    def init(self):

        try:
            load_settings = self.get_load_settings(self.name)
            which_firmware = load_settings.get_string("loader.esp.whichFirmware", self)
        except:
            print("Did not get our whichFirmware setting")
            return False

        firmware_options = parse_firmware(self.parent_view)

        try:
            prefix = "option"
            print("Using option", which_firmware)
            if not which_firmware.startswith(prefix):
                raise Exception("You didn't choose one of the firmware options")
            which_firmware = int(which_firmware[len(prefix):])
        except:
            print("You didn't choose one of the firmware options")
            return False

        try:
            print("Using option", which_firmware)
            the_firmware = firmware_options[which_firmware]
        except:
            print("You didn't choose one of the firmware options")
            return False

        self.platform = Architecture['xtensa'].standalone_platform
        self.arch = Architecture['xtensa']
        self.entry_addr = 0

        the_firmware.load(self, self.parent_view)

        if self.entry_addr != 0:
            for seg in self.segments:
                if (seg.start <= self.entry_addr <= seg.end) and seg.executable:
                    self.add_auto_section('entry_section', seg.start,
                                          seg.end - seg.start,
                                          SectionSemantics.ReadOnlyCodeSectionSemantics
                                          )
            self.create_user_function(self.entry_addr)
            self.define_auto_symbol(Symbol(
                SymbolType.FunctionSymbol,
                self.entry_addr,
                "entry"))
        return True
