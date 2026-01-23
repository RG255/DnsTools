function ConvertTo-HexString 
{
	param([byte[]]$bytes)
	-join ($bytes | ForEach-Object -Process {$_.ToString('x2')})
}