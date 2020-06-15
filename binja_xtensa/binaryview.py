"""
ESP8266 Firmware .bin BinaryView

Using `firmware_parser.py`, we attempt to find binaries in the dump. By default
we'll pick an interesting one (currently the last one with a detected header),
but we present a load option to the user to allow picking a different one.
"""
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
        # These happen to be the two magic bytes used by firmware_parser.py
        if data.read(0, 1) in [b'\xe9', b'\xea']:
            return True
        return False

    @classmethod
    def _pick_default_firmware(cls, firmware_options):
        """Rudimentary heuristic for "interesting" binaries"""
        for idx, firm in reversed(list(enumerate(firmware_options))):
            if firm.name != "AppendedData":
                return idx, firm

        return 0, firmware_options[0]

    @classmethod
    def get_load_settings_for_data(cls, data):
        # This example was crucial in figuring out how to present load options
        # https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/mappedview.py
        # It's also helpful to call Settings().serialize_schema() from the
        # Python console and examine the results.

        firmware_options = parse_firmware(data)
        default_firmware_idx, _ = cls._pick_default_firmware(firmware_options)

        ourEnum = ["option" + str(i) for i in range(len(firmware_options))]
        ourEnumDescriptions = [
            f"{i.name} at {hex(i.bv_offset)}"
            for i in firmware_options]

        # TODO: actually JSON serialize this
        setting =  f"""{{
            "title": "Which Firmware",
            "type": "string",
            "description": "Which of the binaries in this file do you want?",
            "enum": {json.dumps(ourEnum)},
            "enumDescriptions": {json.dumps(ourEnumDescriptions)},
            "default": {json.dumps(ourEnum[default_firmware_idx])}
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
        # This should be set by the the_firmware.load() if there is an entry
        # point.
        # Otherwise, for lack of a better choice, we end up with 0
        return self.entry_addr

    def init(self):

        try:
            load_settings = self.get_load_settings(self.name)
            which_firmware = load_settings.get_string("loader.esp.whichFirmware", self)
        except:
            which_firmware = None

        firmware_options = parse_firmware(self.parent_view)

        try:
            prefix = "option"

            if which_firmware is None:
                try:
                    which_firmware_idx, _ = self._pick_default_firmware(firmware_options)
                except:
                    import traceback
                    traceback.print_exc()
                    raise
                which_firmware = prefix + str(which_firmware_idx)

            if not which_firmware.startswith(prefix):
                raise Exception("You didn't choose one of the firmware options")
            which_firmware = int(which_firmware[len(prefix):])
        except:
            print("You didn't choose one of the firmware options")
            return False

        try:
            print("Using firmware index", which_firmware)
            the_firmware = firmware_options[which_firmware]
        except:
            print("You didn't choose one of the firmware options")
            return False

        self.platform = Architecture['xtensa'].standalone_platform
        self.arch = Architecture['xtensa']
        self.entry_addr = 0

        # Will create segments and set entry_addr as needed.
        the_firmware.load(self, self.parent_view)

        if self.entry_addr != 0:
            for seg in self.segments:
                if (seg.start <= self.entry_addr <= seg.end) and seg.executable:
                    # It seems the ReadOnlyCodeSectionSemantics kicks off the
                    # autoanalysis
                    self.add_auto_section('entry_section', seg.start,
                                          seg.end - seg.start,
                                          SectionSemantics.ReadOnlyCodeSectionSemantics
                                          )
            # I want to be able to find the entry point in the UI
            # I couldn't find a create_auto_function... maybe I didn't look hard
            # enough
            self.create_user_function(self.entry_addr)
            self.define_auto_symbol(Symbol(
                SymbolType.FunctionSymbol,
                self.entry_addr,
                "entry"))
        return True
