import asyncio
import enum
import struct
import sys
from typing import Tuple, List

from ble_serial.bluetooth.ble_interface import BLE_interface
from ble_serial.log.console_log import setup_logger
from bleak import BleakScanner
from PIL import Image


address = '8D:BA:D7:22:D8:7B'
uuid_tpl = '0000%s-0000-1000-8000-00805f9b34fb'
service = uuid_tpl % 'ae30'
char_w = uuid_tpl % 'ae01'
char_r = uuid_tpl % 'ae02'


class PacketTooSmallError(Exception):
    pass

class Packet:
    def __init__(self, code: int, data: bytes):
        self.code = code
        self.data = data

    CHECKSUM_MAP = bytes.fromhex("""
        00 07 0e 09 1c 1b 12 15 38 3f 36 31 24 23 2a 2d
        70 77 7e 79 6c 6b 62 65 48 4f 46 41 54 53 5a 5d
        e0 e7 ee e9 fc fb f2 f5 d8 df d6 d1 c4 c3 ca cd
        90 97 9e 99 8c 8b 82 85 a8 af a6 a1 b4 b3 ba bd
        c7 c0 c9 ce db dc d5 d2 ff f8 f1 f6 e3 e4 ed ea
        b7 b0 b9 be ab ac a5 a2 8f 88 81 86 93 94 9d 9a
        27 20 29 2e 3b 3c 35 32 1f 18 11 16 03 04 0d 0a
        57 50 59 5e 4b 4c 45 42 6f 68 61 66 73 74 7d 7a
        89 8e 87 80 95 92 9b 9c b1 b6 bf b8 ad aa a3 a4
        f9 fe f7 f0 e5 e2 eb ec c1 c6 cf c8 dd da d3 d4
        69 6e 67 60 75 72 7b 7c 51 56 5f 58 4d 4a 43 44
        19 1e 17 10 05 02 0b 0c 21 26 2f 28 3d 3a 33 34
        4e 49 40 47 52 55 5c 5b 76 71 78 7f 6a 6d 64 63
        3e 39 30 37 22 25 2c 2b 06 01 08 0f 1a 1d 14 13
        ae a9 a0 a7 b2 b5 bc bb 96 91 98 9f 8a 8d 84 83
        de d9 d0 d7 c2 c5 cc cb e6 e1 e8 ef fa fd f4 f3
    """)

    @classmethod
    def calc_checksum(cls, data: bytes) -> int:
        acc = 0
        for b in data:
            acc = cls.CHECKSUM_MAP[(acc ^ b) & 0xff]
        return acc

    def encode(self):
        return struct.pack(
            '<2sHH',
            b'Qx',  # header
            self.code,
            len(self.data),
        ) + self.data + struct.pack(
            'BB',
            self.calc_checksum(self.data),
            0xff,  # footer
        )

    @classmethod
    def decode(cls, packet: bytes) -> Tuple['Packet', bytes]:
        if len(packet) < 9:
            raise PacketTooSmallError('No metadata', packet)
        if packet[:2] != b'Qx':
            raise ValueError('Not a valid packet', packet)
        code, length = struct.unpack('<HH', packet[2:6])
        # now we know length and can cut off the excess data
        if len(packet) < length+8:
            raise PacketTooSmallError('Not enough data', packet)
        packet, rest = packet[:length+8], packet[length+8:]
        if packet[-1] != 0xff:
            raise ValueError('Invalid packet ending byte', packet)
        data = packet[6:-2]
        checksum = packet[-2]
        if cls.calc_checksum(data) != checksum:
            raise ValueError('Checksum invalid', checksum, packet)
        return cls(code, data), rest

    def __str__(self):
        return f'<Packet {self.code:x}: {self.data.hex(" ")}>'


class DeviceState(enum.Flag):
    NO_PAPER = 0x1
    PAPER_LID_OPEN = 0x2
    OVERHEAT = 0x4
    BATTERY_LOW = 0x8


class Protocol:
    def __init__(self, addr):
        self.addr = addr
        self.read_queue = asyncio.Queue()
        self.bt = BLE_interface()
        self.bt.set_receiver(self.handle_input)
        self.task = None
        self.buf = b''
        self.new_compression = False

    async def connect(self):
        print('Connecting bt')
        await self.bt.connect(self.addr, 'public', 'hci0', 5.0)
        print('Setup chars')
        await self.bt.setup_chars(char_w, char_r, 'rw')
        self.task = asyncio.create_task(self.bt.send_loop())
        print('Connected')

    async def disconnect(self):
        self.bt.stop_loop()
        # wait for all packets to be sent
        while not self.bt._send_queue.empty():
            # .join won't work since we don't use task_done()
            await asyncio.sleep(.3)
        await self.bt.disconnect()
        # do something with self.task? or will it close itself?
        if e := self.task.exception():
            print('Loop failed', e)

    def handle_input(self, data):
        print('Got data', data)
        self.buf += data
        try:
            # decode all packets from current parcel
            while True:
                try:
                    pkt, self.buf = Packet.decode(self.buf)
                except ValueError as e:
                    # invalid packet; try to cut byte by byte
                    print(f'XXX wrong packet: {e}; cropping')
                    self.buf = self.buf[1:]
                else:
                    print('<<', pkt)
                    if not self.known_response(pkt):
                        self.read_queue.put_nowait(pkt)
        except PacketTooSmallError:
            # not enough data - wait for more to arrive
            pass

    def known_response(self, pkt):
        # some packets are handled without putting them to queue
        if pkt.code == 0x1bb:
            assert len(pkt.data) == 1
            val =  pkt.data[0]
            print('Can Add?', val+1)
            return True
        elif pkt.code == 0x1ae:
            assert len(pkt.data) == 1
            val = pkt.data[0]
            if val == 0x10:
                print('Stop Write')
            elif val == 0:
                print('Start Write')
            else:
                print('Unknown write?')
            return True

    async def cmd(self, code, data=b'\x00', with_resp=False):
        packet = Packet(code, data)
        print('>>', packet)
        self.bt.queue_send(packet.encode())
        if with_resp:
            # response packet has the same code as request plus 0x100
            return await self.recv(code | 0x100)

    async def recv(self, code):
        while True:
            p = await self.read_queue.get()
            if p.code == code:
                return p
            print('Dropping unexpected packet', p, hex(code))

    async def get_dev_info(self):
        res = await self.cmd(0xa8, with_resp=True)
        version = res.data[3:].strip(b'\x00').decode()
        devt = res.data[0]
        devtype = f'XW00{devt}'
        parts = [int(p) for p in version.split('.')]  # TODO also split by '_'
        pt = tuple(parts)
        self.new_compression = devt != 1 and pt >= (1, 1)
        if devt == 17:
            ...  # set eneragy and device address depending on v==1.1.1.1
        devtype2 = res.data[1]
        wifi = {
            0: 'Not connected, not set',
            1: 'Not connected, set',
            2: 'Not set up',
            3: 'Network has been set up wifi',
        }.get(res.data[2], '')

        return dict(
            version=version,
            devtype=devtype,
            devtype2=devtype2,
            wifi=wifi,
        )

    async def get_dev_state(self):
        res = await self.cmd(0xa3, with_resp=True)
        val = res.data[0]
        return DeviceState(val)

    async def set_quality(self, quality: int):
        if not (1 <= quality <= 5):
            raise ValueError('Invalid quality', quality)
        await self.cmd(0xa4, bytes([0x30 + quality]))

    async def set_speed(self, speed: int):
        # expected values: 2, 3, 5
        await self.cmd(0xa4, bytes([0x20 + speed]))

    async def set_energy(self, value: int):
        assert 0 <= value <= 0xffff
        await self.cmd(0xaf, struct.pack('<H', value))

    async def set_wifi_date(self, a, b):
        data = b'\x00\xa0' + a.encode() + b.encode()
        resp = await self.cmd(0xa5, data, with_resp=True)
        result = resp.data[:2]
        if result == '\xa1\x01':
            print('Success')
            return True
        elif result == '\xa1\x02':
            print('Failure')
            return False
        raise ValueError('Unknown response', result)

    async def lattice_start(self):
        await self.cmd(0xa6, b'\x38\x44\x5f\x5f\x5f\x44\x38\x2c')

    async def lattice_end(self):
        await self.cmd(0xa6, bytes(11))  # same as start, but all zeros

    async def update_dev(self):
        await self.cmd(0xa9)

    async def set_wifi_data(self, ssid, password):
        await self.cmd(0xaa, ssid.encode())
        await self.cmd(0xab, password.encode())

    async def print_img(self):
        await self.cmd(0xbe, b'\x00')

    async def print_text(self):
        await self.cmd(0xbe, b'\x01')

    async def feed_paper(self, amount):
        # IDK what it does, but it does not feed paper
        await self.cmd(0xbd, bytes([amount]))

    async def do_feed_paper(self, amount):
        """
        Do feed paper. Amount is from 0 to 0xffff,
        actual values are 0x30 and 0x48.
        """
        await self.cmd(0xa1, struct.pack('<H', amount))

    async def send_raw(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.bt.queue_send(data)

    @classmethod
    def compress_line(cls, pixels: List[int]) -> bytes:
        result = b''
        lastp = None
        count = 0
        had_black = False
        for p in pixels:
            if lastp is None or lastp == p:
                count += 1
            else:
                result += cls._encode_compressed(count, lastp)
                count = 1  # current pixel
            if p:
                had_black = True
            lastp = p
        if count:
            result += cls._encode_compressed(count, lastp)
        return result

    @staticmethod
    def _encode_compressed(count: int, color: int) -> bytes:
        color = int(bool(color))  # convert to (0,1)
        result = b''
        while count > 127:
            result += bytes([(color<<7) | 127])
            count -= 127
        if count:
            result += bytes([(color<<7) | count])
        return result

    @staticmethod
    def pack_pixels(pixels: List[int]) -> bytes:
        result = b''
        pixels = pixels.copy()
        while pixels:
            ps, pixels = pixels[:8], pixels[8:]
            res = 0
            for p in reversed(ps):
                res <<= 1
                res |= int(bool(p))
            result += bytes([res])
        return result

    async def _print_line(self, data):
        await self.cmd(0xbf, data)

    async def print_line(self, pixels: List[int]):
        data = b''
        if self.new_compression:
            data = self.compress_line(pixels)
            code = 0xbf  # compressed
        if not data or len(data) > (len(pixels)+7)//8:
            data = self.pack_pixels(pixels)
            code = 0xa2  # packed, i.e. non-compressed
        await self.cmd(code, data)


async def find_printers():
    print('Scanning')
    devs = await BleakScanner.discover()
    printers = []
    for d in devs:
        if 1494 in d.metadata.get('manufacturer_data', {}):
            printers.append(d)
    return printers


def convert(img, width=384):
    img1 = img.resize((width, width*img.height//img.width))
    if img1.mode in ('RGBA', 'LA') or (
        img1.mode == 'P' and 'transparency' in img1.info
    ):
        alpha = img1.convert('RGBA').split()[-1]
        bg = Image.new('RGBA', img1.size, (255, 255, 255, 255))
        bg.paste(img1, mask=alpha)
        img1 = bg
    img2 = img1.convert(mode='1')
    if len(sys.argv) > 2 and sys.argv[2] == '-p':
        img2.show()
        print('Press C-c to abort, Enter to continue')
        input()

    # we use inverted logic: 0 is white, 1 is black
    pixels = [0 if px else 1 for px in img2.getdata()]
    lines = []
    while pixels:
        l, pixels = pixels[:width], pixels[width:]
        lines.append(l)
    return lines


async def main():
    args = lambda: None
    args.verbose = True
    setup_logger(args)

    printers = await find_printers()
    if not printers:
        print('No printers found')
        return 1
    if len(printers) > 1:
        print('Choose printer... (not implemented)', printers)
        return 1
    print('Using printer', printers[0])
    addr = printers[0].address

    proto = Protocol(addr)
    await proto.connect()
    await asyncio.sleep(1)

    print('info', await proto.get_dev_info())
    print('state', await proto.get_dev_state())

    img = Image.open(sys.argv[1])
    lines = convert(img, 384)

    await asyncio.sleep(1)

    await proto.set_quality(3)  # IDK what does it mean in reality
    await proto.lattice_start()
    await proto.set_energy(0)  # 0 to 0xffff; bigger value means darger print
    await proto.print_text()
    await proto.feed_paper(26)
    for line in lines:
        await proto.print_line(line)  #[:384])
    await proto.feed_paper(25)
    await proto.do_feed_paper(0x30)
    await proto.do_feed_paper(0x30)
    await proto.get_dev_state()
    #await proto.feed_paper(25)
    #await proto.do_feed_paper(0x30)
    await proto.lattice_end()


    # just wait indefinitely
    while False:
        try:
            s = input()
        except EOFError:
            break
        if not s.strip():
            await asyncio.sleep(1)
            continue
        cmd, *args = s.split()
        if not hasattr(proto, cmd):
            print('Unknown')
            continue
        if cmd == 'cmd':
            args[0] = int(args[0], 0)
            args[1] = bytes.fromhex(' '.join(args[1:]))
            args = args[:2]
        print(await getattr(proto, cmd)(*args))

    await proto.disconnect()

if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
