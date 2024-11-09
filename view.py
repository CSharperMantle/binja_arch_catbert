from binaryninja import Architecture, SegmentFlag
from binaryninja.binaryview import BinaryView

VM_CODE_BASE = 0x0
VM_DATA_BASE = 0x1000000


class CatbertView(BinaryView):
    name = "Catbert"
    long_name = "Catbert encrypted file"

    def __init__(self, data: BinaryView):
        super().__init__(parent_view=data, file_metadata=data.file)
        self.arch = Architecture["Catbert"]
        self.platform = Architecture["Catbert"].standalone_platform
        self.data = data
        self._bytecode_entry = int.from_bytes(data.read(0x8, 4), "little")
        self._bytecode_len = int.from_bytes(data.read(0xC, 4), "little")

    def init(self) -> bool:
        self.add_user_segment(VM_CODE_BASE, 0x10000, self._bytecode_entry, self._bytecode_len, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)  # type: ignore
        self.add_user_segment(VM_DATA_BASE, 0x10000, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)  # type: ignore
        self.add_entry_point(self._bytecode_entry)
        return True

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        return data.read(0, 4) == b"C4TB"

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_entry_point(self) -> int:
        return self._bytecode_entry

    def perform_get_address_size(self) -> int:
        return Architecture["Catbert"].address_size


CatbertView.register()
