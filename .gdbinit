define hook-stop
python
try:
    gdb.parse_and_eval('g_under_debug').assign(1)
except:
    pass
end

define hook-detach
python
try:
    gdb.parse_and_eval('g_under_debug').assign(0)
except:
    pass
end
