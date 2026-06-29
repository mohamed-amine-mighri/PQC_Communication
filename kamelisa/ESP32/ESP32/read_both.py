import serial, time, threading

def reader(port, label, lines):
    try:
        s = serial.Serial(port, 115200, timeout=0.2)
    except Exception as e:
        lines.append(f"[{label}] OPEN ERROR: {e}")
        return
    # Hardware-reset the ESP32 into run mode (RTS->EN, DTR->GPIO0)
    s.setDTR(False)   # GPIO0 high -> normal boot
    s.setRTS(True)    # EN low -> hold in reset
    time.sleep(0.1)
    s.setRTS(False)   # release reset -> boot
    s.reset_input_buffer()
    end = time.time() + 60
    buf = b""
    while time.time() < end:
        data = s.read(256)
        if data:
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                txt = line.decode("utf-8", "replace").rstrip("\r")
                lines.append(f"[{label}] {txt}")
    s.close()

la, lb = [], []
ta = threading.Thread(target=reader, args=("COM4", "ALICE", la))
tb = threading.Thread(target=reader, args=("COM3", "BOB", lb))
ta.start(); tb.start()
ta.join(); tb.join()
out = "===== ALICE (COM4) =====\n" + "\n".join(la) + "\n\n===== BOB (COM3) =====\n" + "\n".join(lb)
out = out.encode("ascii", "replace").decode("ascii")
with open(r"C:\Users\selam\Downloads\ESP32\ESP32\serial_out.txt", "w") as f:
    f.write(out)
print("WROTE", len(la), "alice lines,", len(lb), "bob lines")
