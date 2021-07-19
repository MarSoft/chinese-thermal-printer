#!/usr/bin/env python

import asyncio
import sys

from PIL import Image, ImageDraw, ImageFont

from blueprint import get_printer, Protocol, convert


def render(text: str) -> Image.Image:
    width = 384
    height = 265 # 384/58*40 = 264 (approx 256)
    white = 255
    black = 0

    img = Image.new('1', (width, height), white)
    draw = ImageDraw.Draw(img)
    draw.fill = black

    lines = text.strip().splitlines()
    if not lines:
        # nothing to render, return empty image
        return img

    # start by full height then fit by width
    lineheight = height // len(lines)
    while True:
        draw.font = ImageFont.truetype('font.ttf', lineheight)
        maxwidth = 0
        for line in lines:
            x, y, w, h =draw.font.getbbox(line)
            if w > maxwidth:
                maxwidth = w
        if maxwidth <= width:
            break
        lineheight -= 1

    for i, line in enumerate(lines):
        draw.text((0, i*lineheight), line)

    return img


async def main():
    text = sys.stdin.read()
    img = render(text)
    if '-p' in sys.argv:
        img.show()
        await asyncio.sleep(5)
        return

    lines = convert(img)

    prn = Protocol(await get_printer())
    await prn.connect()
    await prn.get_dev_info()
    print(await prn.get_dev_state())

    await prn.set_energy(0)  # 0 to 0xffff
    await prn.print_text()
    await prn.print_lines(lines)
    await prn.do_feed_paper(40)



if __name__ == '__main__':
    asyncio.run(main())
