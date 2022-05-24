set_xmakever("2.6.1") -- Minimum version to compile BPF source correctly

-- options
--- run `xmake f --generate-vmlinux=y` to always generate vmlinux.h rather than assuming one exists in vmlinux/
option("generate-vmlinux", {showmenu = true, default = false, description = "always generate vmlinux.h"})

-- vmlinux
local vmlinuxh = path.join("vmlinux", "vmlinux.h")
target("vmlinux")
    set_kind("headeronly")
    add_includedirs(path.join("$(projectdir)", "vmlinux"), { public = true })

    local missing = false
    if has_config("generate-vmlinux") then
        -- We're gonna need bpftool to generate the vmlinux.h
        includes("../tools")
        add_deps("bpftool")
    else
        if not os.exists(path.absolute(vmlinuxh, os.projectdir())) then
            -- We're assuming you provide a vmlinux.h
            missing = true
        end
    end

    before_build(function(target)
        -- Ensure vmlinux.h exists
        if missing then
            os.raise("missing " .. vmlinuxh .. ": provide it or configure xmake to generate one for you with xmake f --generate-vmlinux=y")
        end

        import("utils.progress")
        if has_config("generate-vmlinux") then
            -- Generate vmlinux.h
            progress.show(20, "${color.build.object}generating.vmlinux %s", vmlinuxh)
            local bpftool = path.join("tools", "bpftool")
            os.execv(bpftool, { "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c" }, { stdout = vmlinuxh })
        end
    end)
    on_clean(function(target)
        -- Delete vmlinux.h if we always generate it
        if has_config("generate-vmlinux") then
            os.tryrm(vmlinuxh)
        end
        -- Otherwise do nothing to keep the vmlinux.h the user provided
    end)