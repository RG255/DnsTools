class DnsPtrRecord {
    [string]$Pointer

    DnsPtrRecord([string]$pointer) {
        $this.Pointer = $pointer
    }

    static [DnsPtrRecord] Parse([DnsBinaryReader]$r, [int]$len) {
        $name = $r.ReadName()
        return [DnsPtrRecord]::new($name)
    }

    [byte[]]ToWire() {
        $w = [DnsBinaryWriter]::new()
        $w.WriteName($this.Pointer)
        return $w.ToArray()
    }
}
