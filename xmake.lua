set_xmakever("2.6.1") -- Minimum version to compile BPF source correctly

-- repositories
includes("xmake/repos.lua")

-- rules
add_rules("mode.release", "mode.debug")

-- traffico
target("traffico")
    set_kind("binary")
    set_default(true)
    includes("api")
    add_deps("api")
    add_packages("libbpf")
    add_files({"traffico.c"}, { languages = { "c11" }})

-- traffico-cni
target("traffico-cni")
    set_kind("binary")
    includes("api")
    add_deps("api")
    add_files({"main.c"}, { langguages = { "c11" }})