set_xmakever("2.9.2") -- Minimum version for build.fence policy and BPF source compilation

-- includes
includes("xmake/repos.lua")

-- rules
add_rules("mode.release", "mode.debug")

-- traffico
target("traffico")
    set_kind("binary")
    set_default(true)
    includes("api")
    add_deps("api")
    add_deps("chain")
    add_deps("bpf")
    add_packages("libbpf")
    add_files({ "traffico.c" }, { languages = { "c11" }})
target_end()

-- traffico-cni
add_requires("cjson")
target("traffico-cni")
    set_kind("binary")
    add_packages("cjson")
    includes("api")
    add_deps("api")
    add_deps("bpf")
    add_packages("libbpf")
    add_files({ "traffico-cni.c" }, { languages = { "c11" }})
target_end()

-- test
add_requires("bats v1.11.1", { system = false })
add_requires("mini_httpd", { system = false })
target("intent-ir-unit")
    set_kind("binary")
    set_default(false)
    add_includedirs(".")
    add_files({ "test/intent_unit.c" }, { languages = { "c11" }})
target_end()

target("dag-unit")
    set_kind("binary")
    set_default(false)
    add_includedirs(".")
    add_files({ "test/dag_unit.c" }, { languages = { "c11" }})
target_end()

target("test")
    set_kind("phony")
    add_packages("bats", "mini_httpd")
    on_run(function (target)
        import("core.base.option")
        local bats_args = {"-t"}
        local selected = table.wrap(option.get("arguments"))
        local build_targets = {}
        local selected_test_paths = 0
        if #selected == 0 then
            table.insert(bats_args, "test/")
            build_targets = {"traffico", "traffico-cni", "intent-ir-unit", "dag-unit"}
        else
            local needs_full_suite_targets = false
            local needs_intent_ir_unit = false
            local needs_dag_unit = false
            for _, arg in ipairs(selected) do
                table.insert(bats_args, arg)
                if arg == "test" or arg == "test/" or arg:find("%.bats$") then
                    selected_test_paths = selected_test_paths + 1
                    if arg:find("intent_unit", 1, true) then
                        needs_intent_ir_unit = true
                    elseif arg:find("dag_unit", 1, true) then
                        needs_dag_unit = true
                    else
                        needs_full_suite_targets = true
                    end
                end
            end
            if selected_test_paths == 0 then
                table.insert(bats_args, "test/")
                build_targets = {"traffico", "traffico-cni", "intent-ir-unit", "dag-unit"}
            elseif needs_full_suite_targets then
                build_targets = {"traffico", "traffico-cni", "intent-ir-unit", "dag-unit"}
            else
                if needs_intent_ir_unit then
                    table.insert(build_targets, "intent-ir-unit")
                end
                if needs_dag_unit then
                    table.insert(build_targets, "dag-unit")
                end
            end
        end
        for _, name in ipairs(build_targets) do
            os.execv("xmake", {"build", "-y", name})
        end
        import("core.project.project")
        for _, name in ipairs(build_targets) do
            local built = project.target(name)
            if built then
                os.addenv("PATH", path.absolute(built:targetdir()))
            end
        end
        os.addenv("PATH", path.absolute("tools"))
        import("privilege.sudo")
        sudo.execv("bats", bats_args)
    end)
target_end()
