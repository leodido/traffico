set_xmakever("2.6.1") -- Minimum version to compile BPF source correctly

-- includes
includes("xmake/repos.lua")

add_requires("cjson")

-- rules
add_rules("mode.release", "mode.debug")

-- traffico
target("traffico")
    set_kind("binary")
    set_default(true)
    includes("api")
    add_deps("api")
    add_packages("libbpf")
    add_files({ "traffico.c" }, { languages = { "c11" }})
target_end()

-- traffico-cni
target("traffico-cni")
    set_kind("binary")
    add_packages("cjson")
    includes("api")
    add_deps("api")
    add_packages("libbpf")
    add_files({ "traffico-cni.c" }, { languages = { "c11" }})
target_end()

-- test
add_requires("bats v1.7.0", { system = false })
target("test")
    set_kind("phony")
    add_deps("traffico", "traffico-cni")
    add_packages("bats")
    on_run(function (target)
        for _, name in ipairs(target:get("deps")) do
            os.addenv("PATH", path.absolute(target:dep(name):targetdir()))
        end
        import("privilege.sudo")
        sudo.execv("bats", { "-t", "test/" })
    end)
target_end()
