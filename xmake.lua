set_xmakever("2.6.1") -- Minimum version to compile BPF source correctly

-- repositories
includes("xmake/repos.lua")

-- rules
add_rules("mode.release", "mode.debug")

-- traffico
target("traffico")
    set_kind("binary")
    set_default(true)
    includes("bpf")
    add_deps("bpf")
    add_packages("libbpf")
    add_files({"traffico.c"}, { languages = { "c11" }})
