set_xmakever("2.6.1") -- Minimum version to compile BPF source correctly

-- options
option("require-bpftool", {showmenu = true, default = false, description = "require bpftool package"})

--- run `xmake f --require-bpftool=y` to pull bpftool from xmake-repo repo rather than using the system one
if has_config("require-bpftool") then
    add_requires("linux-tools", {configs = {bpftool = true}})
    add_packages("linux-tools")
end

-- bpftool
local bpftool = path.join("tools", "bpftool")
target("bpftool")
    set_kind("phony")
    on_config(function (target)
        if os.tryrm(bpftool) then
            local sys_bpftool
            if has_config("require-bpftool") then
                sys_bpftool = path.join(target:pkg("linux-tools"):installdir(), "sbin", "bpftool")
                os.ln(sys_bpftool, bpftool)
            else
                import("lib.detect.find_program")
                sys_bpftool = find_program("bpftool")
                if sys_bpftool == nil then
                    os.raise("cannot find bpftool in system")
                end
                os.ln(sys_bpftool, bpftool)
            end
            import("core.base.option")
            if option.get("verbose") then
                print(sys_bpftool)
                import("core.base.json")
                local vers = os.iorunv(bpftool, {"version", "-j"})
                print(json.decode(vers))
            end
        end
    end)
    before_build(function(target)
        import("utils.progress")
        progress.show(10, "${color.build.object}providing.bpftool %s", bpftool)
    end)
    on_clean(function (target)
        os.tryrm(bpftool)
    end)
