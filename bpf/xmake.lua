set_xmakever("2.6.1") -- Minimum version to compile BPF source correctly

-- repositories
includes("../xmake/repos.lua")

-- rules
rule("bpf")
    set_extensions(".bpf.c")
    on_config(function (target)
        assert(is_host("linux"), 'rule("bpf"): only supported on linux!')
        local headerdir = path.join(target:autogendir(), "rules", "bpf")
        if not os.isdir(headerdir) then
            os.mkdir(headerdir)
        end
        target:add("includedirs", headerdir, { interface = true })
    end)
    before_buildcmd_file(function (target, batchcmds, sourcefile, opt)
        local filecfg = target:fileconfig(sourcefile)
        local bpftool = "bpftool"
        if filecfg and filecfg.bpftool then
            bpftool = filecfg.bpftool
        end

        local headerfile = path.join(target:autogendir(), "rules", "bpf", (path.filename(sourcefile):gsub("%.bpf%.c", ".skel.h")))
        local objectfile = path.join(target:autogendir(), "rules", "bpf", (path.filename(sourcefile):gsub("%.bpf%.c", ".bpf.o")))
        local targetarch
        if target:is_arch("x86_64", "i386") then
            targetarch = "__TARGET_ARCH_x86"
        elseif target:is_arch("arm64", "arm64-v8a") then
            targetarch = "__TARGET_ARCH_arm64"
        elseif target:is_arch("arm.*") then
            targetarch = "__TARGET_ARCH_arm"
        elseif target:is_arch("mips64", "mips") then
            targetarch = "__TARGET_ARCH_mips"
        elseif target:is_arch("ppc64", "ppc") then
            targetarch = "__TARGET_ARCH_powerpc"
        end
        target:add("includedirs", path.directory(headerfile), { interface = true })
        target:set("optimize", "faster")
        batchcmds:show_progress(opt.progress, "${color.build.object}compiling.bpf %s", sourcefile)
        batchcmds:mkdir(path.directory(objectfile))
        batchcmds:compile(sourcefile, objectfile, {configs = {force = {cxflags = {"-target bpf", "-g"}}, defines = targetarch}})
        batchcmds:mkdir(path.directory(headerfile))
        batchcmds:show_progress(opt.progress, "${color.build.object}compiling.bpf.o %s", objectfile)
        batchcmds:execv(bpftool, {"gen", "skeleton", objectfile}, {stdout = headerfile})
        batchcmds:show_progress(opt.progress, "${color.build.object}generating.skel.h %s", headerfile)
        batchcmds:add_depfiles(sourcefile)
        batchcmds:set_depmtime(os.mtime(headerfile))
        batchcmds:set_depcache(target:dependfile(objectfile))
    end)
rule_end()

-- rules
add_rules("mode.release", "mode.debug")

-- toolchain
add_requires("llvm")
set_toolchains("@llvm")

-- requirements
add_requires("linux-headers")
add_requires("libbpf v0.7.0", { system = false })

-- probe
target("bpf")
    set_kind("object")
    set_policy("build.across_targets_in_parallel", false)
    includes("../tools")
    add_deps("bpftool")
    includes("../vmlinux")
    add_deps("vmlinux")
    add_packages("libbpf")
    add_files("*.bpf.c", { rules = { "bpf", override = true}, bpftool = path.join("tools", "bpftool") })
