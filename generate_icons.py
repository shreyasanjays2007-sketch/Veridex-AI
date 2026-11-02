import zlib
import struct
import math

def create_png(width, height, draw_func):
    raw_data = bytearray()
    for y in range(height):
        raw_data.append(0)  # Filter type 0 (None)
        for x in range(width):
            r, g, b, a = draw_func(x, y, width, height)
            raw_data.extend([r, g, b, a])
            
    # PNG signature
    png = b'\x89PNG\r\n\x1a\n'
    
    # IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data)
    png += struct.pack('>I', len(ihdr_data)) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)
    
    # IDAT chunk
    compressed = zlib.compress(raw_data)
    idat_crc = zlib.crc32(b'IDAT' + compressed)
    png += struct.pack('>I', len(compressed)) + b'IDAT' + compressed + struct.pack('>I', idat_crc)
    
    # IEND chunk
    iend_crc = zlib.crc32(b'IEND')
    png += struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
    
    return png

def shield_pixel(x, y, w, h):
    # Normalize coordinates to -1.0 to 1.0
    nx = (x - w / 2) / (w / 2)
    ny = (y - h / 2) / (h / 2)
    dist = math.sqrt(nx * nx + ny * ny)
    
    # Dark circular background
    if dist > 0.95:
        return (0, 0, 0, 0) # Transparent outside
    
    # Shield shape: |x| <= 0.7 * (1 - (ny+0.6)**2 * 0.3) for ny > -0.6
    # Let's do a stylish shield in the center
    in_shield = False
    if ny >= -0.65 and ny <= 0.75:
        width_at_y = 0.65 * (1.0 - (ny + 0.3) * 0.45) if ny > 0 else 0.65
        if abs(nx) <= width_at_y:
            in_shield = True
            
    if in_shield:
        # Cyan-to-blue gradient
        t = (ny + 0.65) / 1.4
        r = int(0 * (1 - t) + 14 * t)
        g = int(242 * (1 - t) + 120 * t)
        b = int(254 * (1 - t) + 240 * t)
        
        # Inner V checkmark in white
        if abs(ny - (abs(nx) * 0.9 - 0.1)) < 0.12 and abs(nx) < 0.4:
            return (255, 255, 255, 255)
            
        return (r, g, b, 255)
    else:
        # Dark tech background circle
        return (11, 15, 25, 255)

for size in [16, 32, 48, 128]:
    png_bytes = create_png(size, size, shield_pixel)
    with open(f"D:\\veridex-ai\\icons\\icon{size}.png", "wb") as f:
        f.write(png_bytes)
    print(f"Generated icon{size}.png")
