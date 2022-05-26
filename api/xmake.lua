
set_xmakever("2.6.1") -- Minimum version to compile BPF source correctly

-- repositories
includes("xmake/repos.lua")

-- rules
add_rules("mode.release", "mode.debug")

-- target to generate API components for every BPF program
target("every.api")
    set_kind("headeronly")
    includes("../bpf")
    add_deps("bpf")
    on_config(function(target)
        import("xmake.modules.api", { rootdir = os.projectdir() })
        api.gen(target, "bpf")

        import("actions.config.configfiles", { alias = "gen_configfiles", rootdir = os.programdir() })
        gen_configfiles()
    end)

-- target to generate the API
target("api")
    set_kind("headeronly")
    add_deps("every.api")
    on_config(function(target)
        import("xmake.modules.api", { rootdir = os.projectdir() })
        api(target, "every.api", true)

        import("actions.config.configfiles", { alias = "gen_configfiles", rootdir = os.programdir() })
        gen_configfiles()
    end)